// oxlint-disable typescript/promise-function-async -- Web Crypto callbacks return native Promises.
import { expect, it } from "@effect/vitest";
import { Effect, Redacted, Result } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Keyring } from "../src/keyring.js";
import { credentialLayer, metadata, name, sameValue } from "./fixtures.js";

it.effect(
  "set and encrypt refuse lone surrogates without saving a changed value",
  () =>
    Effect.gen(function* unicode() {
      const credential = yield* Credential;
      const store = yield* CredentialStore;
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();

      for (const value of ["\uD800", "private-\uDFFF-suffix"]) {
        for (const result of [
          yield* credential
            .set(Redacted.make(value), metadata)
            .pipe(Effect.asVoid, Effect.result),
          yield* ring
            .encrypt(Redacted.make(value), dek, name, 1)
            .pipe(Effect.asVoid, Effect.result),
        ]) {
          expect(Result.isFailure(result)).toBe(true);

          if (Result.isFailure(result)) {
            expect(result.failure._tag).toBe("ValueNotWellFormed");
            expect(result.failure).toMatchObject({
              next: "Send the value as valid UTF-8; `sc set` reads stdin bytes, so pipe the exact value",
              rule: "value",
              what: "The value is not well-formed Unicode text",
              why: "It has a lone UTF-16 surrogate, which UTF-8 cannot store without changing it.",
            });
            expect(JSON.stringify(result.failure)).not.toContain("private-");
            expect(JSON.stringify(result.failure)).not.toContain("suffix");
          }
        }

        expect(yield* store.meta()).toBeUndefined();
        expect(yield* store.value()).toBeUndefined();
      }
    }).pipe(Effect.provide(credentialLayer()))
);

it.effect(
  "leading BOM characters survive encryption and authenticated invalid UTF-8 is a typed key refusal",
  () =>
    Effect.gen(function* unicodeBytes() {
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();

      for (const value of ["\uFEFF", "\uFEFFprivate", "\uFEFF\uFEFF"]) {
        const encrypted = yield* ring.encrypt(
          Redacted.make(value),
          dek,
          name,
          1
        );

        expect(
          sameValue(
            yield* ring.decrypt(encrypted, dek, name, 1),
            Redacted.make(value)
          )
        ).toBe(true);
      }

      const iv = new Uint8Array(12);

      const encrypted = yield* Effect.promise(() =>
        crypto.subtle.encrypt(
          {
            additionalData: new TextEncoder().encode(
              `secret-cell.v1|${name}|1`
            ),
            iv,
            name: "AES-GCM",
            tagLength: 128,
          },
          dek,
          new Uint8Array([0xff])
        )
      );

      const result = yield* ring
        .decrypt(
          { ciphertext: [...new Uint8Array(encrypted)], iv: [...iv] },
          dek,
          name,
          1
        )
        .pipe(Effect.result);

      expect(result._tag).toBe("Failure");

      if (Result.isFailure(result)) {
        expect(result.failure._tag).toBe("KeyUnavailable");
      }
    }).pipe(Effect.provide(Keyring.testLayer()))
);
