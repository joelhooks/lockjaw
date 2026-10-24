import { expect, it } from "@effect/vitest";
import { Effect, Predicate, Redacted } from "effect";

import { Credential } from "../src/credential.js";
import { Keyring } from "../src/keyring.js";
import {
  caller,
  canary,
  credentialLayer,
  metadata,
  name,
  op,
} from "./fixtures.js";

it.effect(
  "imported signing keys are non-extractable, sign-only and verify under the generated public key",
  () =>
    Effect.gen(function* scenario1() {
      const pair = yield* Effect.promise(
        async () =>
          await crypto.subtle.generateKey(
            {
              hash: "SHA-256",
              modulusLength: 2048,
              name: "RSASSA-PKCS1-v1_5",
              publicExponent: new Uint8Array([1, 0, 1]),
            },
            true,
            ["sign", "verify"]
          )
      );

      const der = yield* Effect.promise(
        async () => await crypto.subtle.exportKey("pkcs8", pair.privateKey)
      );

      const begin = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
      const end = ["-----END", "PRIVATE KEY-----"].join(" ");
      const pem = `${begin}\n${btoa(Array.from(new Uint8Array(der), (byte) => String.fromCodePoint(byte)).join(""))}\n${end}\n`;
      const keyring = yield* Keyring;
      const dek = yield* keyring.newDek();
      yield* keyring.wrap(dek, name);

      const sealed = yield* keyring.encrypt(
        Redacted.make(pem),
        dek,
        name,
        1,
        "RSASSA-PKCS1-v1_5/SHA-256"
      );

      const key = yield* keyring.importSigningKey(
        sealed,
        dek,
        name,
        1,
        "RSASSA-PKCS1-v1_5/SHA-256"
      );

      expect(key.extractable).toBe(false);
      expect(key.usages).toEqual(["sign"]);
      expect(
        yield* Effect.promise(
          async () =>
            await crypto.subtle.exportKey("pkcs8", key).then(
              () => false,
              () => true
            )
        )
      ).toBe(true);
      const data = new TextEncoder().encode("test payload");

      const signature = yield* Effect.promise(
        async () => await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, data)
      );

      expect(
        yield* Effect.promise(
          async () =>
            await crypto.subtle.verify(
              "RSASSA-PKCS1-v1_5",
              pair.publicKey,
              signature,
              data
            )
        )
      ).toBe(true);
    }).pipe(Effect.provide(Keyring.testLayer()), Effect.scoped)
);

it.effect(
  "key credentials refuse owner sub-keys with the exact correction",
  () =>
    Effect.gen(function* scenario2() {
      const credential = yield* Credential;
      yield* credential.set(Redacted.make(canary), {
        ...metadata,
        kind: "key",
      });

      const result = yield* credential
        .resolve(caller, { ...op, subkey: "owner" })
        .pipe(Effect.flip);

      expect(result._tag).toBe("CredentialReferenceInvalid");

      if (Predicate.isTagged(result, "CredentialReferenceInvalid")) {
        expect(result.next).toBe(
          `Use {{secret:${name}}} without the /owner suffix.`
        );
      }
    }).pipe(Effect.provide(credentialLayer()), Effect.scoped)
);
