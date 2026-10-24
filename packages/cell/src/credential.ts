import { GitHubAppMetadata } from "@lockjaw/domain";
import type {
  Caller,
  CredentialName,
  Operation,
  Policy as CredentialPolicy,
} from "@lockjaw/domain";
import {
  CallerNotAllowed,
  CredentialExpired,
  CredentialNeedsAuth,
  CredentialNotFound,
  CredentialRevoked,
  KeyUnavailable,
} from "@lockjaw/domain/errors";
import { Policy } from "@lockjaw/gateway-rules";
import type { EffectActor } from "@xstate/effect";
import { waitFor } from "@xstate/effect";
import type { Redacted } from "effect";
import {
  Cache,
  Exit,
  Clock,
  Context,
  Deferred,
  Effect,
  Layer,
  Option,
  Schema,
  Semaphore,
} from "effect";

import { CredentialStore } from "./credential-store.js";
import type {
  Audit,
  Metadata,
  State,
  StoredValue,
} from "./credential-store.js";
import { GitHubApp, CredentialReferenceInvalid } from "./github-app.js";
import { Keyring } from "./keyring.js";
import { LifecycleWork, startLifecycle } from "./lifecycle.js";
import type { LifecycleEvent, lifecycleMachine } from "./lifecycle.js";
import { Refresher } from "./refresher.js";
import type { RefreshTokens } from "./refresher.js";

export interface SetMetadata extends Metadata {
  readonly policy: CredentialPolicy;
  readonly refreshToken?: Redacted.Redacted;
}

const githubMetadataIdentity = (metadata: GitHubAppMetadata | undefined) =>
  metadata === undefined
    ? ""
    : JSON.stringify([
        metadata.appId,
        Object.entries(metadata.installations).toSorted(([left], [right]) =>
          left.localeCompare(right)
        ),
      ]);

const make = Effect.fn("Credential.make")(function* makeOperation(
  credential: CredentialName
) {
  const store = yield* CredentialStore;
  const keyring = yield* Keyring;
  const policy = yield* Policy;
  const refresher = yield* Refresher;
  const github = yield* GitHubApp;
  let signingKey: CryptoKey | undefined;

  const installationTokens = yield* Cache.makeWith(
    (owner: string) =>
      Effect.gen(function* mintInstallation() {
        const meta = yield* store.meta();
        const configuration = meta?.githubApp;

        const installationId =
          configuration && Object.hasOwn(configuration.installations, owner)
            ? configuration.installations[owner]
            : undefined;

        if (!configuration || installationId === undefined) {
          return yield* new CredentialReferenceInvalid({
            credential,
            next: "Ask approver to POST /v1/approve with githubApp.installations for this owner, then retry.",
            rule: "subkey",
            what: "No GitHub installation is approved for this owner",
            why: "The owner sub-key must have an installation id",
          });
        }

        if (!signingKey) {
          const current = yield* store.value();

          if (!current) {
            return yield* new CredentialNotFound({
              credential,
              rule: "missing",
            });
          }

          const dek = yield* keyring.unwrap(
            current.wrapped,
            credential,
            current.wrapped.kekId
          );

          signingKey = yield* keyring.importSigningKey(
            current.sealed,
            dek,
            credential,
            current.version,
            "RSASSA-PKCS1-v1_5/SHA-256"
          );
        }

        const minted = yield* github.mint({
          appId: configuration.appId,
          credential,
          installationId,
          key: signingKey,
        });

        return {
          ...minted,
          cacheFor: Math.max(
            0,
            minted.expiresAt - (yield* Clock.currentTimeMillis) - 300_000
          ),
        };
      }),
    {
      capacity: 1000,
      timeToLive: (exit) => (Exit.isSuccess(exit) ? exit.value.cacheFor : 0),
    }
  );

  const clearSigning = () =>
    Effect.gen(function* clearSigningMaterial() {
      signingKey = undefined;
      yield* Cache.invalidateAll(installationTokens);
    });

  yield* Effect.addFinalizer(() => clearSigning());
  const mutex = yield* Semaphore.make(1);
  const restored = yield* store.snapshot();

  let version = Math.max(
    (yield* store.value())?.version ?? 0,
    (yield* store.value("refresh"))?.version ?? 0
  );

  const encrypt = Effect.fn("Credential.encrypt")(function* encryptOperation(
    value: Redacted.Redacted,
    githubApp?: boolean
  ) {
    const dek = yield* keyring.newDek();
    const wrapped = yield* keyring.wrap(dek, credential);
    version += 1;
    const currentMetadata = yield* store.meta();

    const signing =
      githubApp === true || currentMetadata?.kind === "github-app";

    const sealed = yield* keyring.encrypt(
      value,
      dek,
      credential,
      version,
      signing ? "RSASSA-PKCS1-v1_5/SHA-256" : undefined
    );

    return { sealed, version, wrapped };
  });

  const decrypt = (value: StoredValue) =>
    keyring
      .unwrap(value.wrapped, credential, value.wrapped.kekId)
      .pipe(
        Effect.flatMap((dek) =>
          keyring.decrypt(value.sealed, dek, credential, value.version)
        )
      );

  const persistedState = () =>
    store.snapshot().pipe(Effect.map((snapshot) => snapshot?.state ?? "empty"));

  const check = Effect.fn("Credential.check")(function* checkOperation(
    state: State
  ) {
    if (state === "revoked") {
      return yield* new CredentialRevoked({ credential, rule: "revoked" });
    }

    if (state === "expired") {
      return yield* new CredentialExpired({ credential, rule: "expired" });
    }

    if (state === "needsAuth") {
      return yield* new CredentialNeedsAuth({ credential, rule: "needs-auth" });
    }

    if (state === "empty") {
      return yield* new CredentialNotFound({ credential, rule: "missing" });
    }

    return yield* Effect.void;
  });

  const refresh = Effect.fn("Credential.refresh")(function* refreshOperation() {
    const current = yield* store.value();

    if (!current) {
      return "invalid_grant" as const;
    }

    const token = yield* store.value("refresh");

    const tokens: RefreshTokens = token
      ? { refreshToken: yield* decrypt(token), value: yield* decrypt(current) }
      : { value: yield* decrypt(current) };

    return yield* refresher.refresh(credential, tokens).pipe(
      Effect.flatMap((result) =>
        mutex.withPermit(
          Effect.gen(function* refreshAdmitted() {
            if ((yield* persistedState()) !== "refreshing") {
              return "invalid_grant" as const;
            }

            const value = yield* encrypt(result.value);

            const refreshValue = result.refreshToken
              ? yield* encrypt(result.refreshToken)
              : undefined;

            yield* store.replace(value, refreshValue, result.expiresAt);

            return "ok" as const;
          })
        )
      ),
      Effect.catchTag("RefreshFailure", (error) =>
        Effect.succeed(error.reason)
      ),
      Effect.tap((result) =>
        Effect.gen(function* scheduleRefresh() {
          if (result === "retryable") {
            const failures =
              ((yield* store.refreshSchedule())?.failures ?? 0) + 1;

            yield* store.scheduleRefresh(
              (yield* Clock.currentTimeMillis) +
                Math.min(300_000, 1000 * 2 ** Math.min(failures - 1, 9)),
              failures
            );
          } else {
            yield* store.clearRefresh();
          }
        })
      )
    );
  });

  const installed =
    yield* Deferred.make<EffectActor<typeof lifecycleMachine>>();

  const work = LifecycleWork.of({
    persist: (state, revision) =>
      Effect.gen(function* persistSnapshot() {
        const actor = yield* Deferred.await(installed);

        const xstate = yield* Schema.decodeEffect(
          Schema.fromJsonString(Schema.Json)
        )(JSON.stringify(actor.getPersistedSnapshot()));

        yield* store.transition(
          {
            recoveryAttempt: actor.getSnapshot().context.recoveryAttempt,
            revision,
            state,
            xstate,
          },
          yield* Clock.currentTimeMillis
        );
      }).pipe(Effect.orDie),
    refresh: () => refresh().pipe(Effect.orDie),
  });

  const lifecycle = yield* startLifecycle(
    restored ?? { revision: 0, state: "empty" },
    (actor) => Deferred.succeed(installed, actor).pipe(Effect.asVoid)
  ).pipe(Effect.provideService(LifecycleWork, work));

  const transition = Effect.fn("Credential.transition")(
    function* transitionOperation(event: LifecycleEvent, refreshing: boolean) {
      const before = lifecycle.actor.getSnapshot().context.revision;
      yield* lifecycle.send(event);
      yield* waitFor<typeof lifecycle.actor>(
        lifecycle.actor,
        (snapshot: {
          readonly context: {
            readonly revision: number;
            readonly ready: boolean;
          };
          readonly value: string;
        }) =>
          snapshot.context.revision > before &&
          (snapshot.context.ready ||
            (refreshing && snapshot.value === "refreshing"))
      ).pipe(Effect.orDie);
    }
  );

  const ready = () => lifecycle.settled();

  const stable = <A, E, R>(operation: Effect.Effect<A, E, R>) =>
    Effect.gen(function* stableOperation() {
      while (true) {
        yield* ready();

        const result = yield* mutex.withPermit(
          Effect.gen(function* admittedOperation() {
            if (!lifecycle.actor.getSnapshot().context.ready) {
              return Option.none<A>();
            }

            return Option.some(yield* operation);
          })
        );

        if (Option.isSome(result)) {
          return result.value;
        }
      }
    });

  const set = Effect.fn("Credential.set")(function* setOperation(
    value: Redacted.Redacted,
    metadata: SetMetadata
  ) {
    yield* ready();

    return yield* stable(
      Effect.gen(function* setAdmitted() {
        const state = yield* persistedState();

        if (state === "revoked") {
          return yield* check(state);
        }

        if (state === "rotating") {
          return yield* new KeyUnavailable({ credential, rule: "key" });
        }

        const previous = yield* store.meta();

        if (
          (metadata.kind !== "github-app" &&
            metadata.githubApp !== undefined) ||
          (previous && previous.kind !== metadata.kind) ||
          (metadata.kind === "github-app" &&
            (!metadata.githubApp ||
              (previous &&
                githubMetadataIdentity(previous.githubApp) !==
                  githubMetadataIdentity(metadata.githubApp))))
        ) {
          return yield* new CredentialReferenceInvalid({
            credential,
            next: "Ask approver to POST /v1/approve with githubApp metadata, then POST /v1/set with the same approved metadata.",
            rule: "approval",
            what: "Credential metadata change requires approval",
            why: "Set cannot change the credential kind or GitHub App installation map",
          });
        }

        const encrypted = yield* encrypt(value, metadata.kind === "github-app");
        yield* clearSigning();

        const refreshToken = metadata.refreshToken
          ? yield* encrypt(metadata.refreshToken)
          : undefined;

        const baseMetadata: Metadata = {
          createdAt: metadata.createdAt,
          description: metadata.description,
          expiresAt: metadata.expiresAt,
          kind: metadata.kind,
          name: metadata.name,
          owner: metadata.owner,
        };

        const meta = metadata.githubApp
          ? { ...baseMetadata, githubApp: metadata.githubApp }
          : baseMetadata;

        yield* store.set(encrypted, meta, metadata.policy, refreshToken);

        return yield* transition({ type: "SET_VALUE" }, false);
      })
    );
  });

  const resolve = Effect.fn("Credential.resolve")(function* resolveOperation(
    caller: Caller,
    op: Operation,
    chain: readonly string[] = []
  ) {
    yield* ready();

    return yield* stable(
      Effect.gen(function* resolveAdmitted() {
        const operation = Effect.gen(function* operationOperation() {
          const grants = yield* store.policy();

          if (!grants || op.credential !== credential) {
            return yield* new CredentialNotFound({
              credential,
              rule: "missing",
            });
          }

          if (chain.length > 0) {
            yield* policy.authorizeDelegated(caller, grants, op);
          } else if (caller.run === undefined) {
            yield* policy.authorize(caller, grants, op);
          } else {
            return yield* new CallerNotAllowed({ credential, rule: "caller" });
          }

          const state = yield* persistedState();
          yield* check(state);
          const meta = yield* store.meta();

          if (
            meta?.expiresAt !== null &&
            meta?.expiresAt !== undefined &&
            meta.expiresAt <= (yield* Clock.currentTimeMillis)
          ) {
            yield* transition({ type: "EXPIRE" }, false);

            return yield* new CredentialExpired({
              credential,
              rule: "expired",
            });
          }

          const value = yield* store.value();

          if (!value) {
            return yield* new CredentialNotFound({
              credential,
              rule: "missing",
            });
          }

          if (meta?.kind === "github-app") {
            if (
              op.subkey === undefined ||
              op.subkey.length === 0 ||
              !/^[A-Za-z0-9._-]{1,64}$(?![\s\S])/u.test(op.subkey)
            ) {
              return yield* new CredentialReferenceInvalid({
                credential,
                next: `Use {{secret:${credential}/<owner>}} with an owner in the approved installation map.`,
                rule: "subkey",
                what: "GitHub App resolution requires an owner",
                why: "Installation tokens are scoped to an approved owner",
              });
            }

            return yield* Cache.get(installationTokens, op.subkey).pipe(
              Effect.map((token) => token.value),
              Effect.catchTag("GitHubMintFailed", (error) =>
                Effect.gen(function* mintFailed() {
                  if (error.reason === "auth") {
                    yield* clearSigning();
                    yield* transition({ type: "AUTH_FAILED" }, false);

                    return yield* new CredentialNeedsAuth({
                      credential,
                      rule: "needs-auth",
                    });
                  }

                  return yield* new KeyUnavailable({
                    credential,
                    rule: "upstream",
                  });
                })
              )
            );
          }

          if (op.subkey !== undefined) {
            return yield* new CredentialReferenceInvalid({
              credential,
              next: `Use {{secret:${credential}}} without the /owner suffix.`,
              rule: "subkey",
              what: "This credential kind has no sub-keys",
              why: "Only github-app credentials accept an owner sub-key",
            });
          }

          return yield* decrypt(value);
        });

        const log = (decision: "allowed" | "refused", reason: string) =>
          Effect.gen(function* writeUse() {
            const grants = yield* store.policy();

            const route = grants?.routes?.find(
              (allowed) =>
                allowed.method === op.method &&
                op.path.startsWith(allowed.pathPrefix)
            );

            const entry: Audit = {
              at: yield* Clock.currentTimeMillis,
              callerDid: caller.did,
              callerName: caller.name,
              decision,
              host: op.host,
              method: op.method,
              op: "resolve",
              pathPrefix: route?.pathPrefix ?? "",
              reason,
              sessionId: caller.sid,
            };

            yield* store.log(
              chain.length > 0 || caller.run !== undefined
                ? {
                    ...entry,
                    grants: [...chain],
                    runHandle: caller.run?.handle ?? "",
                  }
                : entry
            );
          });

        return yield* operation.pipe(
          Effect.matchEffect({
            onFailure: (error) =>
              log("refused", error._tag).pipe(
                Effect.andThen(Effect.fail(error))
              ),
            onSuccess: (value) =>
              log("allowed", "authorized").pipe(Effect.as(value)),
          })
        );
      })
    );
  });

  const rotateBegin = Effect.fn("Credential.rotateBegin")(
    function* rotateBeginOperation(value: Redacted.Redacted) {
      yield* ready();

      return yield* stable(
        Effect.gen(function* rotateBeginAdmitted() {
          const state = yield* persistedState();
          yield* check(state);

          if (state !== "active") {
            return yield* new KeyUnavailable({ credential, rule: "key" });
          }

          yield* store.rotateBegin(yield* encrypt(value));
          yield* clearSigning();

          return yield* transition({ type: "ROTATE_BEGIN" }, false);
        })
      );
    }
  );

  const finishRotation = (event: "ROTATE_COMMIT" | "ROTATE_ABORT") =>
    Effect.gen(function* rotationOperation() {
      yield* ready();

      return yield* stable(
        Effect.gen(function* finishRotationAdmitted() {
          const state = yield* persistedState();
          yield* check(state);

          if (state !== "rotating") {
            return yield* new KeyUnavailable({ credential, rule: "key" });
          }

          yield* clearSigning();
          yield* event === "ROTATE_COMMIT"
            ? store.rotateCommit()
            : store.rotateAbort();

          return yield* transition({ type: event }, false);
        })
      );
    });

  const refreshDue = Effect.fn("Credential.refreshDue")(
    function* refreshDueOperation() {
      return yield* mutex.withPermit(
        Effect.gen(function* refreshDueAdmitted() {
          const state = lifecycle.actor.getSnapshot().value;

          if (state === "restoring") {
            return yield* new KeyUnavailable({ credential, rule: "key" });
          }

          yield* check(state);

          if (state === "refreshing") {
            return yield* Effect.void;
          }

          yield* ready();

          if (state !== "active") {
            return yield* new KeyUnavailable({ credential, rule: "key" });
          }

          return yield* transition({ type: "REFRESH_DUE" }, true);
        })
      );
    }
  );

  const revoke = Effect.fn("Credential.revoke")(function* revokeOperation() {
    return yield* mutex.withPermit(
      Effect.gen(function* revokeAdmitted() {
        if ((yield* persistedState()) === "revoked") {
          return;
        }

        yield* clearSigning();
        yield* transition({ type: "REVOKE" }, false);
      })
    );
  });

  const expire = Effect.fn("Credential.expire")(function* expireOperation() {
    return yield* mutex.withPermit(
      Effect.gen(function* expireAdmitted() {
        const meta = yield* store.meta();
        const state = yield* persistedState();

        if (
          (state === "active" ||
            state === "refreshing" ||
            state === "rotating") &&
          meta?.expiresAt !== null &&
          meta?.expiresAt !== undefined &&
          meta.expiresAt <= (yield* Clock.currentTimeMillis)
        ) {
          yield* transition({ type: "EXPIRE" }, false);
        }
      })
    );
  });

  const describe = Effect.fn("Credential.describe")(
    function* describeOperation() {
      return {
        lifecycle: yield* store.snapshot(),
        meta: yield* store.meta(),
        policy: yield* store.policy(),
      };
    }
  );

  const approveGithubApp = (
    metadata: GitHubAppMetadata,
    grants: CredentialPolicy
  ) =>
    stable(
      Effect.gen(function* approveGithubAppOperation() {
        const decoded = yield* Schema.decodeUnknownEffect(GitHubAppMetadata)(
          metadata
        ).pipe(
          Effect.mapError(() => new KeyUnavailable({ credential, rule: "key" }))
        );

        yield* store.setGithubApp(decoded, grants);
        yield* clearSigning();
      })
    );

  return {
    approveGithubApp,
    describe,
    expire,
    refreshDue,
    resolve,
    revoke,
    rotateAbort: () => finishRotation("ROTATE_ABORT"),
    rotateBegin,
    rotateCommit: () => finishRotation("ROTATE_COMMIT"),
    set,
    settled: ready,
  };
});

export class Credential extends Context.Service<
  Credential,
  Effect.Success<ReturnType<typeof make>>
>()("secret-cell/Credential") {
  static readonly layer = (
    credential: CredentialName,
    github = GitHubApp.unavailableLayer
  ) => Layer.effect(Credential, make(credential)).pipe(Layer.provide(github));
  static readonly testLayer = Credential.layer;
}
