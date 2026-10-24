import { expect, it } from "@effect/vitest";
import { Deferred, Effect, Fiber, Redacted, Result, Schema } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Refresher } from "../src/refresher.js";
import {
  caller,
  canary,
  credentialLayer,
  metadata,
  op,
  sameValue,
} from "./fixtures.js";

it.effect.prop(
  "rotation grace window: racing uses see only an intact old or new token",
  {
    commit: Schema.Boolean,
    concurrency: Schema.Int.check(
      Schema.isBetween({ maximum: 32, minimum: 2 })
    ),
  },
  ({ commit, concurrency }) =>
    Effect.gen(function* rotationRace() {
      const credential = yield* Credential;
      yield* credential.set(Redacted.make(canary), metadata);

      const racing = yield* Effect.forEach(
        Array.from({ length: concurrency }),
        () => credential.resolve(caller, op),
        { concurrency: "unbounded" }
      ).pipe(Effect.forkChild);

      yield* credential.rotateBegin(Redacted.make("new-whole-token"));

      const grace = yield* Effect.forEach(
        Array.from({ length: concurrency }),
        () => credential.resolve(caller, op),
        { concurrency: "unbounded" }
      ).pipe(Effect.forkChild);

      yield* commit ? credential.rotateCommit() : credential.rotateAbort();

      const outputs = [
        ...(yield* Fiber.join(racing)),
        ...(yield* Fiber.join(grace)),
      ];

      for (const value of outputs) {
        expect(
          sameValue(value, Redacted.make(canary)) ||
            sameValue(value, Redacted.make("new-whole-token"))
        ).toBe(true);
      }

      expect(
        sameValue(
          yield* credential.resolve(caller, op),
          Redacted.make(commit ? "new-whole-token" : canary)
        )
      ).toBe(true);
    }).pipe(Effect.provide(credentialLayer())),
  { arbitrary: { runs: 30 } }
);

it.effect(
  "revoke interrupts the refresh actor, releases every waiter, and cannot resurrect ciphertext",
  () =>
    Effect.gen(function* revokeDuringRefresh() {
      const entered = yield* Deferred.make<boolean>();
      const release = yield* Deferred.make<boolean>();

      const refresh = Refresher.layer({
        refresh: () =>
          Effect.gen(function* blockedProvider() {
            yield* Deferred.succeed(entered, true);
            yield* Deferred.await(release);

            return {
              expiresAt: null,
              refreshToken: Redacted.make("late-refresh"),
              value: Redacted.make("late-access"),
            };
          }),
      });

      yield* Effect.gen(function* revokeScenario() {
        const credential = yield* Credential;
        const store = yield* CredentialStore;
        yield* credential.set(Redacted.make(canary), metadata);
        yield* credential.refreshDue();
        yield* Deferred.await(entered);

        const waiter = yield* credential
          .resolve(caller, op)
          .pipe(Effect.result, Effect.forkChild);

        yield* credential.revoke();
        yield* Deferred.succeed(release, true);
        const result = yield* Fiber.join(waiter);
        expect(Result.isFailure(result)).toBe(true);
        expect(yield* store.value()).toBeUndefined();
        expect(yield* store.value("refresh")).toBeUndefined();
        expect((yield* credential.describe()).lifecycle?.state).toBe("revoked");
      }).pipe(Effect.provide(credentialLayer(refresh)));
    }).pipe(Effect.scoped)
);
