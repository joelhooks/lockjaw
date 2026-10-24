import { expect, it } from "@effect/vitest";
import { Deferred, Effect, Fiber, Redacted, Ref, Result } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Refresher, RefreshFailure } from "../src/refresher.js";
import {
  caller,
  canary,
  credentialLayer,
  metadata,
  op,
  sameValue,
} from "./fixtures.js";

it.effect(
  "sets, authorizes, rotates atomically, expires and leaves a revocation tombstone",
  () =>
    Effect.gen(function* credentialTest() {
      const credential = yield* Credential;
      const store = yield* CredentialStore;
      yield* credential.set(Redacted.make(canary), metadata);
      expect(
        sameValue(yield* credential.resolve(caller, op), Redacted.make(canary))
      ).toBe(true);

      const denied = yield* credential
        .resolve({ ...caller, name: "outsider" }, op)
        .pipe(Effect.result);

      expect(Result.isFailure(denied)).toBe(true);
      yield* credential.rotateBegin(Redacted.make("new-token"));
      expect(
        sameValue(
          yield* credential.resolve(caller, op),
          Redacted.make("new-token")
        )
      ).toBe(true);
      yield* credential.rotateAbort();
      expect(
        sameValue(yield* credential.resolve(caller, op), Redacted.make(canary))
      ).toBe(true);
      yield* credential.rotateBegin(Redacted.make("new-token"));
      yield* credential.rotateCommit();
      expect(yield* store.value("previous")).toBeUndefined();
      yield* credential.set(Redacted.make(canary), {
        ...metadata,
        expiresAt: -1,
      });
      yield* credential.expire();
      expect(
        Result.isFailure(
          yield* credential.resolve(caller, op).pipe(Effect.result)
        )
      ).toBe(true);
      yield* credential.set(Redacted.make(canary), metadata);
      yield* credential.revoke();
      expect(yield* store.value()).toBeUndefined();
      expect(yield* store.value("refresh")).toBeUndefined();
      expect((yield* credential.describe()).lifecycle?.state).toBe("revoked");
      expect(
        Result.isFailure(
          yield* credential
            .set(Redacted.make(canary), metadata)
            .pipe(Effect.result)
        )
      ).toBe(true);
      expect(
        (yield* store.uses()).some((row) => row.decision === "refused")
      ).toBe(true);
    }).pipe(Effect.provide(credentialLayer()))
);

it.effect(
  "single-flight: concurrent refresh and use wait for the durable rotated refresh token",
  () =>
    Effect.gen(function* concurrentTest() {
      const entered = yield* Deferred.make<boolean>();
      const release = yield* Deferred.make<boolean>();
      const calls = yield* Ref.make(0);

      const refresh = Refresher.layer({
        refresh: () =>
          Effect.gen(function* refreshActor() {
            yield* Ref.update(calls, (n) => n + 1);
            yield* Deferred.succeed(entered, true);
            yield* Deferred.await(release);

            return {
              expiresAt: null,
              refreshToken: Redacted.make("new-refresh"),
              value: Redacted.make("new-access"),
            };
          }),
      });

      yield* Effect.gen(function* scenario() {
        const credential = yield* Credential;
        const store = yield* CredentialStore;
        yield* credential.set(Redacted.make(canary), {
          ...metadata,
          refreshToken: Redacted.make("old-refresh"),
        });
        yield* credential.refreshDue();
        yield* Deferred.await(entered);
        yield* Effect.forEach(
          Array.from({ length: 32 }),
          () => credential.refreshDue(),
          { concurrency: "unbounded" }
        );

        const waiters = yield* Effect.forEach(
          Array.from({ length: 32 }),
          () => credential.resolve(caller, op),
          { concurrency: "unbounded" }
        ).pipe(Effect.forkChild);

        expect(yield* Ref.get(calls)).toBe(1);
        yield* Deferred.succeed(release, true);
        const resolved = yield* Fiber.join(waiters);

        for (const value of resolved) {
          expect(sameValue(value, Redacted.make("new-access"))).toBe(true);
        }

        expect((yield* store.value("refresh"))?.version).toBeGreaterThan(2);
        expect(yield* Ref.get(calls)).toBe(1);
      }).pipe(Effect.provide(credentialLayer(refresh)));
    }).pipe(Effect.scoped)
);

it.effect(
  "invalid_grant requires authentication and never serves the stale value",
  () =>
    Effect.gen(function* invalidGrantTest() {
      const credential = yield* Credential;
      yield* credential.set(Redacted.make(canary), metadata);
      yield* credential.refreshDue();
      const result = yield* credential.resolve(caller, op).pipe(Effect.result);
      expect(Result.isFailure(result)).toBe(true);

      if (Result.isFailure(result)) {
        expect(result.failure._tag).toBe("CredentialNeedsAuth");
      }
    }).pipe(
      Effect.provide(
        credentialLayer(
          Refresher.layer({
            refresh: () =>
              Effect.fail(new RefreshFailure({ reason: "invalid_grant" })),
          })
        )
      )
    )
);
