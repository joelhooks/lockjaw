import { expect, it } from "@effect/vitest";
import { Effect, Redacted, Ref } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Refresher, RefreshFailure } from "../src/refresher.js";
import {
  caller,
  canary,
  dependencies,
  metadata,
  name,
  op,
  sameValue,
} from "./fixtures.js";

for (const outcome of [
  "ok",
  "retryable",
  "invalid_grant",
  "second-crash",
] as const) {
  it.effect(`interrupted refresh recovery: ${outcome}`, () =>
    Effect.gen(function* recovery() {
      const calls = yield* Ref.make(0);

      const refresher = Refresher.layer({
        refresh: () =>
          Ref.update(calls, (n) => n + 1).pipe(
            Effect.andThen(
              outcome === "ok"
                ? Effect.succeed({
                    expiresAt: null,
                    refreshToken: Redacted.make(
                      "recovered-rotated-refresh-token"
                    ),
                    value: Redacted.make("recovered-new-access-token"),
                  })
                : Effect.fail(
                    new RefreshFailure({
                      reason:
                        outcome === "invalid_grant"
                          ? "invalid_grant"
                          : "retryable",
                    })
                  )
            )
          ),
      });

      yield* Effect.gen(function* exerciseRecovery() {
        const store = yield* CredentialStore;
        yield* Credential.use((core) =>
          core.set(Redacted.make(canary), {
            ...metadata,
            refreshToken: Redacted.make("old-refresh-token"),
          })
        ).pipe(Effect.scoped, Effect.provide(Credential.layer(name)));
        yield* store.transition(
          outcome === "second-crash"
            ? { recoveryAttempt: 1, revision: 2, state: "refreshing" }
            : { revision: 2, state: "refreshing" },
          0
        );
        yield* Credential.use((core) =>
          Effect.gen(function* checkRecovery() {
            expect((yield* core.describe()).lifecycle?.state).toBe(
              outcome === "ok" ? "active" : "needsAuth"
            );
            expect(yield* Ref.get(calls)).toBe(
              outcome === "second-crash" ? 0 : 1
            );

            if (outcome === "ok") {
              expect(
                sameValue(
                  yield* core.resolve(caller, op),
                  Redacted.make("recovered-new-access-token")
                )
              ).toBe(true);
            }
          })
        ).pipe(Effect.scoped, Effect.provide(Credential.layer(name)));
      }).pipe(Effect.provide(dependencies(refresher)));
    })
  );
}
