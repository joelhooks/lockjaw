// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
// oxlint-disable-next-line typescript/triple-slash-reference -- cloudflare:workers is a runtime built-in with no package; packages that compile this source through imports need its declaration.
/// <reference path="./cloudflare-workers.d.ts" />

import {
  Credential as Core,
  CredentialStore,
  Keyring,
  Refresher,
  RefreshFailure,
  durableSqlPort,
  makeKekLoader,
  selectKek,
} from "@lockjaw/cell";
import type {
  KekBindings,
  KekLoader,
  SetMetadata,
  StoreUnavailable,
  DurableStoragePort,
} from "@lockjaw/cell";
import {
  CredentialName,
  GitHubAppMetadata,
  Policy as Grants,
} from "@lockjaw/domain";
import type { Caller, Operation, Policy } from "@lockjaw/domain";
import { Policy as PolicyService } from "@lockjaw/gateway-rules";
import { DurableObject } from "cloudflare:workers";
import {
  Clock,
  Effect,
  Layer,
  Logger,
  ManagedRuntime,
  Redacted,
  Schema,
} from "effect";

import { unbase64 } from "./caller-auth.js";
import { boundaryFault, fault } from "./fault.js";
import { githubAppLayer } from "./github-app.js";
import { Upstream } from "./upstream.js";

const ResolvedSchema = Schema.Struct({
  credential: CredentialName,
  value: Schema.String,
  valueVersion: Schema.Int,
}).pipe(Schema.brand("ResolvedForFill"));

export type ResolvedForFill = typeof ResolvedSchema.Type;

export interface CellContext {
  readonly id: { readonly name?: string };
  readonly storage: DurableStoragePort & {
    readonly setAlarm: (at: number) => Promise<void>;
    readonly deleteAlarm: () => Promise<void>;
  };
}

export type CellBindings = KekBindings;

const Binding = Schema.Struct({
  kekId: Schema.NonEmptyString,
  key: Schema.NonEmptyString,
});

const keyBinding = (text: string) => {
  const binding = Schema.decodeUnknownSync(Schema.fromJsonString(Binding))(
    text
  );

  return { kekId: binding.kekId, key: Redacted.make(unbase64(binding.key)) };
};

const isolateKek = makeKekLoader((url, init) =>
  // @effect-diagnostics-next-line globalFetch:off -- Only the fixed loopback KEK loader may fetch; config would also permit unrelated fetches throughout this credential boundary.
  fetch(url, init)
);

const keyringLayer = (env: CellBindings, loader: KekLoader) => {
  const selected = selectKek(env);

  if (selected.mode === "binding") {
    return Keyring.layer(
      keyBinding(selected.current),
      selected.next === undefined ? undefined : keyBinding(selected.next)
    );
  }

  return selected.mode === "url"
    ? Keyring.urlLayer(selected.config, loader)
    : Keyring.refusedLayer(selected.error);
};

export interface RpcError {
  readonly credential: string;
  readonly rule: string;
  readonly what?: string;
  readonly why?: string;
  readonly next?: string;
}

export type Rpc<A> =
  | { readonly ok: true; readonly value: A }
  | { readonly ok: false; readonly error: RpcError };

const encodeFailure = (error: RpcError): Rpc<never> => {
  const base = { credential: error.credential, rule: error.rule };

  return {
    error:
      error.what !== undefined &&
      error.why !== undefined &&
      error.next !== undefined
        ? { ...base, next: error.next, what: error.what, why: error.why }
        : base,
    ok: false,
  };
};

const scheduleAlarms = Effect.fn("CredentialDO.schedule")(function* schedule(
  ctx: CellContext
) {
  const core = yield* Core;
  const store = yield* CredentialStore;
  const description = yield* core.describe();
  const retry = yield* store.refreshSchedule();
  const state = description.lifecycle?.state;
  const expiry = description.meta?.expiresAt;

  const candidates =
    state === "active" || state === "rotating"
      ? [expiry, retry?.at].filter(
          (at): at is number => at !== null && at !== undefined
        )
      : [];

  yield* Effect.tryPromise({
    catch: boundaryFault,
    try: () =>
      candidates.length > 0
        ? ctx.storage.setAlarm(Math.min(...candidates))
        : ctx.storage.deleteAlarm(),
  });
});

export class Credential extends DurableObject<CellBindings> {
  readonly #name: CredentialName;
  readonly #ctx: CellContext;
  readonly #runtime;
  constructor(
    ctx: CellContext,
    env: CellBindings,
    refresher = Refresher.layer({
      refresh: () => Effect.fail(new RefreshFailure({ reason: "retryable" })),
    }),
    upstream = Upstream.liveLayer,
    runtime: {
      readonly clock?: Clock.Clock;
      readonly kek?: KekLoader;
      readonly logger?: Logger.Logger<unknown, unknown>;
    } = {}
  ) {
    super(ctx, env);
    this.#ctx = ctx;
    this.#name = CredentialName.make(ctx.id.name ?? "invalid");

    const dependencies = Layer.mergeAll(
      CredentialStore.layer(durableSqlPort(ctx.storage)),
      keyringLayer(env, runtime.kek ?? isolateKek),
      PolicyService.layer,
      refresher
    );

    const coreLayer = Core.layer(
      this.#name,
      githubAppLayer.pipe(Layer.provide(upstream))
    ).pipe(Layer.provideMerge(dependencies));

    const clock = runtime.clock
      ? Layer.succeed(Clock.Clock, runtime.clock)
      : Layer.empty;

    const logging = runtime.logger
      ? Logger.layer([runtime.logger])
      : Layer.empty;

    this.#runtime = ManagedRuntime.make(
      coreLayer.pipe(Layer.provideMerge(Layer.mergeAll(clock, logging)))
    );
  }
  async #run<A, E extends RpcError | StoreUnavailable>(
    operation: Effect.Effect<A, E, Core | CredentialStore>
  ) {
    return await this.#runtime.runPromise(
      operation.pipe(
        Effect.tap(() => this.#schedule()),
        Effect.match({
          onFailure: (error) =>
            encodeFailure(
              "credential" in error
                ? error
                : { credential: this.#name, rule: "storage" }
            ),
          onSuccess: (value): Rpc<A> => ({ ok: true, value }),
        })
      )
    );
  }
  readonly #schedule = () => scheduleAlarms(this.#ctx);
  async describe() {
    return await this.#run(
      Effect.gen(function* describeRpc() {
        const core = yield* Core;
        const store = yield* CredentialStore;
        const info = yield* core.describe();

        return { ...info, version: (yield* store.value())?.version ?? 0 };
      })
    );
  }
  async resolve(caller: Caller, op: Operation, chain: readonly string[] = []) {
    return await this.#run(
      Effect.gen(
        function* resolveRpc(this: Credential) {
          const core = yield* Core;
          const value = yield* core.resolve(caller, op, chain);
          const store = yield* CredentialStore;
          const version = (yield* store.value())?.version ?? 0;

          return ResolvedSchema.make({
            credential: this.#name,
            value: Redacted.value(value),
            valueVersion: version,
          });
        }.bind(this)
      )
    );
  }
  async set(
    value: string,
    expiresAt: number | null = null,
    githubApp?: GitHubAppMetadata
  ) {
    return await this.#run(
      Effect.gen(
        function* setRpc(this: Credential) {
          const core = yield* Core;
          const description = yield* core.describe();
          const { meta } = description;

          const policy = description.policy ?? {
            callers: [],
            hosts: [],
            placements: [],
          };

          const configuration = githubApp ?? meta?.githubApp;

          const decodedConfiguration = configuration
            ? yield* Schema.decodeUnknownEffect(GitHubAppMetadata)(
                configuration
              ).pipe(
                Effect.mapError(() =>
                  fault("request", "Supply valid githubApp metadata.")
                )
              )
            : undefined;

          const setMetadata: SetMetadata = {
            createdAt: meta?.createdAt ?? (yield* Clock.currentTimeMillis),
            description: meta?.description ?? "",
            expiresAt,
            kind: meta?.kind ?? (githubApp ? "github-app" : "key"),

            name: this.#name,
            owner: "cell",
            policy,
          };

          yield* core.set(
            Redacted.make(value),
            decodedConfiguration
              ? { ...setMetadata, githubApp: decodedConfiguration }
              : setMetadata
          );
          yield* this.#schedule();
        }.bind(this)
      )
    );
  }
  async approve(policy: Policy, githubApp?: GitHubAppMetadata) {
    return await this.#run(
      Effect.gen(function* approveRpc() {
        const store = yield* CredentialStore;

        const decoded = yield* Schema.decodeUnknownEffect(Grants)(policy).pipe(
          Effect.mapError(() =>
            fault(
              "policy",
              "Supply a valid policy through sh.secretcell.approve."
            )
          )
        );

        if (githubApp) {
          const core = yield* Core;
          yield* core.approveGithubApp(githubApp, decoded);
        } else {
          yield* store.setPolicy(decoded);
        }
      })
    );
  }
  async revoke() {
    return await this.#run(
      Core.use((core) => core.revoke()).pipe(Effect.andThen(this.#schedule()))
    );
  }
  async rotate(value: string) {
    return await this.#run(
      Core.use((core) =>
        core
          .rotateBegin(Redacted.make(value))
          .pipe(Effect.andThen(core.rotateCommit()))
      ).pipe(Effect.andThen(this.#schedule()))
    );
  }
  async rotateBegin(value: string) {
    return await this.#run(
      Core.use((core) => core.rotateBegin(Redacted.make(value))).pipe(
        Effect.andThen(this.#schedule())
      )
    );
  }
  async rotateCommit() {
    return await this.#run(
      Core.use((core) => core.rotateCommit()).pipe(
        Effect.andThen(this.#schedule())
      )
    );
  }
  async rotateAbort() {
    return await this.#run(
      Core.use((core) => core.rotateAbort()).pipe(
        Effect.andThen(this.#schedule())
      )
    );
  }
  async alarm() {
    const schedule = this.#schedule;

    return await this.#run(
      Effect.gen(function* alarmRpc() {
        const core = yield* Core;
        const store = yield* CredentialStore;
        const now = yield* Clock.currentTimeMillis;
        const retry = yield* store.refreshSchedule();

        if (retry && retry.at <= now) {
          yield* core.refreshDue();
          yield* core.settled();
        }

        yield* core.expire();
        yield* schedule();
      })
    );
  }
  async dispose() {
    await this.#runtime.dispose();
  }
}
