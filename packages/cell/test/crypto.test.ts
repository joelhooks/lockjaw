import { expect, it } from "@effect/vitest";
import { CredentialName } from "@lockjaw/domain";
import { Effect, Redacted, Result } from "effect";

import { Keyring } from "../src/keyring.js";
import { canary, name, sameValue } from "./fixtures.js";

it.effect(
  "binds ciphertext to credential and version, and returns only Redacted values",
  () =>
    Effect.gen(function* cryptoTest() {
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();
      const wrapped = yield* ring.wrap(dek, name);
      const sealed = yield* ring.encrypt(Redacted.make(canary), dek, name, 1);
      const restored = yield* ring.unwrap(wrapped, name, wrapped.kekId);
      expect(restored.extractable).toBe(false);
      expect(
        sameValue(
          yield* ring.decrypt(sealed, restored, name, 1),
          Redacted.make(canary)
        )
      ).toBe(true);

      for (const failure of [
        ring
          .decrypt(sealed, restored, CredentialName.make("other"), 1)
          .pipe(Effect.asVoid),
        ring.decrypt(sealed, restored, name, 2).pipe(Effect.asVoid),
        ring
          .unwrap(wrapped, CredentialName.make("other"), wrapped.kekId)
          .pipe(Effect.asVoid),
        ring.unwrap(wrapped, name, "wrong-id").pipe(Effect.asVoid),
      ]) {
        const result = yield* failure.pipe(Effect.asVoid, Effect.result);
        expect(Result.isFailure(result)).toBe(true);
        expect(JSON.stringify(result)).not.toContain(canary);

        if (Result.isFailure(result)) {
          expect(result.failure._tag).toBe("KeyUnavailable");
        }
      }
    }).pipe(Effect.provide(Keyring.testLayer()))
);

const wrong = () =>
  Keyring.layer({
    kekId: "old",
    key: Redacted.make(new Uint8Array(32).fill(3)),
  });

it.effect(
  "rewrap changes only the envelope, and the wrong KEK fails typed",
  () =>
    Effect.gen(function* rewrapTest() {
      const ring = yield* Keyring;
      const values = [];

      for (const version of [1, 2, 3]) {
        const dek = yield* ring.newDek();
        const wrapped = yield* ring.wrap(dek, name);

        const sealed = yield* ring.encrypt(
          Redacted.make(canary),
          dek,
          name,
          version
        );

        const rotated = yield* ring.rewrap(wrapped, name, "next");
        expect(rotated).not.toEqual(wrapped);
        const key = yield* ring.unwrap(rotated, name, "next");
        expect(
          sameValue(
            yield* ring.decrypt(sealed, key, name, version),
            Redacted.make(canary)
          )
        ).toBe(true);
        values.push({ sealed, version, wrapped });
      }

      for (const value of values) {
        const result = yield* Keyring.use((bad) =>
          bad.unwrap(value.wrapped, name, "old")
        ).pipe(Effect.result, Effect.provide(wrong()));

        expect(Result.isFailure(result)).toBe(true);
      }
    }).pipe(
      Effect.provide(
        Keyring.layer(
          { kekId: "old", key: Redacted.make(new Uint8Array(32).fill(1)) },
          { kekId: "next", key: Redacted.make(new Uint8Array(32).fill(2)) }
        )
      )
    )
);
