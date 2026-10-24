import { expect, it } from "@effect/vitest";
import {
  Deferred,
  Effect,
  Fiber,
  Queue,
  Redacted,
  Ref,
  Result,
  Schema,
} from "effect";
import { TestClock } from "effect/testing";

import { CredentialStore } from "../src/credential-store.js";
import type { State, StoredValue } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Keyring } from "../src/keyring.js";
import { Refresher, RefreshFailure } from "../src/refresher.js";
import type { RefreshedTokens, RefreshTokens } from "../src/refresher.js";
import {
  caller,
  canary,
  credentialLayer,
  metadata,
  name,
  op,
  sameValue,
} from "./fixtures.js";

const Event = Schema.Literals([
  "set",
  "use",
  "begin",
  "commit",
  "abort",
  "expire",
  "revoke",
  "refresh-ok",
  "refresh-invalid",
  "refresh-retry",
]);

const Events = Schema.Array(Event).check(Schema.isMaxLength(35));

interface Model {
  state: State;
  value: string;
  previous: string;
}

interface Request {
  readonly tokens: RefreshTokens;
  readonly completion: Deferred.Deferred<RefreshedTokens, RefreshFailure>;
}

it.effect.prop(
  "model: lifecycle, single-flight, refresh persistence, and whole-value rotation",
  {
    concurrency: Schema.Int.check(
      Schema.isBetween({ maximum: 16, minimum: 2 })
    ),
    events: Events,
  },
  ({ events, concurrency }) =>
    Effect.gen(function* modelTest() {
      const requests = yield* Queue.unbounded<Request>();
      const calls = yield* Ref.make(0);
      const inFlight = yield* Ref.make(0);
      const maximum = yield* Ref.make(0);

      const refresher = Refresher.layer({
        refresh: (_credential, tokens) =>
          Effect.gen(function* refreshTestPort() {
            const completion = yield* Deferred.make<
              RefreshedTokens,
              RefreshFailure
            >();

            yield* Ref.update(calls, (n) => n + 1);
            const active = yield* Ref.updateAndGet(inFlight, (n) => n + 1);
            yield* Ref.update(maximum, (n) => Math.max(n, active));
            yield* Queue.offer(requests, { completion, tokens });

            return yield* Deferred.await(completion).pipe(
              Effect.ensuring(Ref.update(inFlight, (n) => n - 1))
            );
          }),
      });

      // oxlint-disable-next-line eslint/complexity -- Deliberately independent, small reference model; keeping all event rules together makes discrepancies reviewable.
      yield* Effect.gen(function* exerciseModel() {
        const credential = yield* Credential;
        const store = yield* CredentialStore;
        const ring = yield* Keyring;

        const model: Model = {
          previous: canary,
          state: "empty",
          value: canary,
        };

        const read = (value: StoredValue) =>
          ring
            .unwrap(value.wrapped, name, value.wrapped.kekId)
            .pipe(
              Effect.flatMap((dek) =>
                ring.decrypt(value.sealed, dek, name, value.version)
              )
            );

        const matches = Effect.fn("Model.matches")(function* matchesModel() {
          const description = yield* credential.describe();
          expect(description.lifecycle?.state).toBe(model.state);
          expect(description.lifecycle?.recoveryAttempt).toBe(0);

          const served = yield* credential
            .resolve(caller, op)
            .pipe(Effect.result);

          if (model.state === "active" || model.state === "rotating") {
            expect(Result.isSuccess(served)).toBe(true);

            if (Result.isSuccess(served)) {
              expect(
                sameValue(served.success, Redacted.make(model.value))
              ).toBe(true);
            }
          } else {
            expect(Result.isFailure(served)).toBe(true);
          }

          if (model.state === "revoked") {
            expect(yield* store.value()).toBeUndefined();
            expect(yield* store.value("previous")).toBeUndefined();
            expect(yield* store.value("refresh")).toBeUndefined();
          }
        });

        const trace = ["set", "refresh-ok", ...events] as const;

        for (const event of trace) {
          if (event === "set") {
            const result = yield* credential
              .set(Redacted.make(canary), {
                ...metadata,
                expiresAt: null,
                refreshToken: Redacted.make("refresh-initial"),
              })
              .pipe(Effect.result);

            if (model.state !== "revoked" && model.state !== "rotating") {
              expect(Result.isSuccess(result)).toBe(true);
              model.state = "active";
              model.value = canary;
            } else {
              expect(Result.isFailure(result)).toBe(true);
            }
          } else if (event === "begin") {
            const result = yield* credential
              .rotateBegin(Redacted.make("rotation-whole-new-token"))
              .pipe(Effect.result);

            if (model.state === "active") {
              model.previous = model.value;
              model.value = "rotation-whole-new-token";
              model.state = "rotating";
              expect(Result.isSuccess(result)).toBe(true);
            } else {
              expect(Result.isFailure(result)).toBe(true);
            }
          } else if (event === "commit" || event === "abort") {
            const result = yield* (
              event === "commit"
                ? credential.rotateCommit()
                : credential.rotateAbort()
            ).pipe(Effect.result);

            if (model.state === "rotating") {
              if (event === "abort") {
                model.value = model.previous;
              }

              model.state = "active";
              expect(Result.isSuccess(result)).toBe(true);
            } else {
              expect(Result.isFailure(result)).toBe(true);
            }
          } else if (event === "revoke") {
            yield* credential.revoke();
            model.state = "revoked";
          } else if (event === "expire" && model.state === "active") {
            yield* credential.set(Redacted.make(model.value), {
              ...metadata,
              expiresAt: 1,
            });
            yield* TestClock.setTime(2);
            yield* credential.expire();
            model.state = "expired";
          } else if (event.startsWith("refresh-") && model.state === "active") {
            const before = yield* Ref.get(calls);
            const previousRefresh = yield* store.value("refresh");
            yield* credential.refreshDue();
            const request = yield* Queue.take(requests);

            if (previousRefresh) {
              expect(request.tokens.refreshToken).toBeDefined();

              if (request.tokens.refreshToken) {
                expect(
                  sameValue(
                    request.tokens.refreshToken,
                    yield* read(previousRefresh)
                  )
                ).toBe(true);
              }
            }

            yield* Effect.forEach(
              Array.from({ length: concurrency }),
              () => credential.refreshDue(),
              { concurrency: "unbounded" }
            );

            const waiters = yield* Effect.forEach(
              Array.from({ length: concurrency }),
              () =>
                Effect.gen(function* useWaiter() {
                  const served = yield* credential
                    .resolve(caller, op)
                    .pipe(Effect.result);

                  if (event === "refresh-ok" && Result.isSuccess(served)) {
                    const stored = yield* store.value("refresh");
                    expect(stored).toBeDefined();

                    if (stored) {
                      expect(
                        sameValue(
                          yield* read(stored),
                          Redacted.make("refresh-rotated")
                        )
                      ).toBe(true);
                    }
                  }

                  return served;
                }),
              { concurrency: "unbounded" }
            ).pipe(Effect.forkChild);

            expect(yield* Ref.get(calls)).toBe(before + 1);
            expect(yield* Ref.get(maximum)).toBe(1);

            if (event === "refresh-ok") {
              yield* Deferred.succeed(request.completion, {
                expiresAt: null,
                refreshToken: Redacted.make("refresh-rotated"),
                value: Redacted.make("refreshed-whole-access-token"),
              });
              model.value = "refreshed-whole-access-token";
            } else {
              yield* Deferred.fail(
                request.completion,
                new RefreshFailure({
                  reason:
                    event === "refresh-invalid" ? "invalid_grant" : "retryable",
                })
              );

              if (event === "refresh-invalid") {
                model.state = "needsAuth";
              }
            }

            const results = yield* Fiber.join(waiters);
            expect(yield* Ref.get(maximum)).toBe(1);
            expect(yield* Ref.get(calls)).toBe(before + 1);
            expect(yield* Ref.get(inFlight)).toBe(0);

            if (event !== "refresh-ok") {
              expect(yield* store.value("refresh")).toEqual(previousRefresh);
            }

            for (const result of results) {
              if (model.state === "active") {
                expect(Result.isSuccess(result)).toBe(true);

                if (Result.isSuccess(result)) {
                  expect(
                    sameValue(result.success, Redacted.make(model.value))
                  ).toBe(true);
                }
              } else {
                expect(Result.isFailure(result)).toBe(true);
              }
            }
          }

          yield* matches();
        }
      }).pipe(Effect.provide(credentialLayer(refresher)));
    }).pipe(Effect.scoped),
  { arbitrary: { runs: 75 }, timeout: 30_000 }
);
