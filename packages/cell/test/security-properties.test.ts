// oxlint-disable typescript/promise-function-async -- Native fetch and Web Crypto fakes return Promises.
import { expect, it } from "@effect/vitest";
import { Arbitrary, Effect, Redacted, Result, Schema } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import {
  Keyring,
  deriveKekId,
  makeKekLoader,
  selectKek,
} from "../src/keyring.js";
import type { KekFetch, Sealed } from "../src/keyring.js";
import { credentialLayer, metadata, name, sameValue } from "./fixtures.js";

const access = "SC_PROPERTY_ACCESS_CANARY_fixture";

const config = { access: Redacted.make(access), url: "http://127.0.0.1:1/kek" };

const bounded = (minimum: number, maximum: number) =>
  Schema.Int.check(Schema.isBetween({ maximum, minimum }));

const Bytes = Schema.Array(bounded(0, 255)).check(Schema.isMaxLength(64));

const Key = Schema.Array(bounded(0, 255)).check(
  Schema.isMinLength(32),
  Schema.isMaxLength(32)
);

const flipByte = (byte: number) => (byte % 2 === 0 ? byte + 1 : byte - 1);

const seen = new Map<string, string>();

const options = { arbitrary: { runs: 30 } };

it.prop(
  "URL acceptance: only the exact loopback URL with a canonical port selects URL mode; refusals are three-part and secret-free",
  { arbitrary: Schema.String, port: bounded(1, 65_535) },
  ({ arbitrary, port }) => {
    const url = `http://127.0.0.1:${port}/kek`;

    const cases = [
      arbitrary,
      url,
      url.replace("127.0.0.1", "localhost"),
      url.replace("127.0.0.1", "127.0.0.2"),
      url.replace("127.0.0.1", "[::1]"),
      url.replace("127.0.0.1", "user:pass@127.0.0.1"),
      `${url}?x=1`,
      `${url}#fragment`,
      `${url}/`,
      `${url}\n`,
      ` ${url}`,
      url.replace("http:", "HTTP:"),
      url.toUpperCase(),
      url.replace(`:${port}/`, `:0${port}/`),
      "http://127.0.0.1:0/kek",
      "http://127.0.0.1:65536/kek",
    ];

    for (const candidate of cases) {
      const portText = candidate.slice(
        "http://127.0.0.1:".length,
        -"/kek".length
      );

      const number = Number(portText);

      const accepted =
        Number.isInteger(number) &&
        number >= 1 &&
        number <= 65_535 &&
        candidate === `http://127.0.0.1:${number}/kek`;

      const selected = selectKek({ KEK_ACCESS: access, KEK_URL: candidate });
      expect(selected.mode).toBe(accepted ? "url" : "refused");

      if (selected.mode === "refused") {
        for (const part of [
          selected.error.what,
          selected.error.why,
          selected.error.next,
        ]) {
          expect(part.length).toBeGreaterThan(0);
        }

        expect(
          [JSON.stringify(selected.error), String(selected.error)].join("\n")
        ).not.toContain(access);
      }
    }
  },
  options
);

it.effect.prop(
  "kekId: deterministic, fixed lowercase format, and injective over distinct generated 32-byte keys in this run",
  {
    keys: Schema.Array(Key).check(Schema.isMinLength(2), Schema.isMaxLength(6)),
  },
  ({ keys }) =>
    Effect.gen(function* ids() {
      for (const key of keys) {
        const bytes = Uint8Array.from(key);
        const id = yield* deriveKekId(bytes);
        expect(id).toMatch(/^kek-[0-9a-f]{16}$/u);
        expect(yield* deriveKekId(bytes)).toBe(id);
        const encoded = JSON.stringify(key);
        expect(seen.get(id) ?? encoded).toBe(encoded);
        seen.set(id, encoded);
      }

      const first = Uint8Array.from(keys[0] ?? new Uint8Array(32));
      const second = Uint8Array.from(first);
      second[0] = flipByte(second[0] ?? 0);
      expect(yield* deriveKekId(first)).not.toBe(yield* deriveKekId(second));
    }),
  options
);

it.effect.prop(
  "KEK body: accepts iff status 200, octet-stream media type, and exactly 32 bytes; chunking preserves the imported key",
  {
    body: Bytes,
    cuts: Schema.Array(bounded(0, 64)).check(Schema.isMaxLength(10)),
    status: bounded(0, 999),
    type: Schema.String,
  },
  ({ body, cuts, status, type }) =>
    Effect.gen(function* bodies() {
      for (const input of [
        body,
        Array.from(
          { length: 32 },
          (_, index) => body[index % Math.max(1, body.length)] ?? index
        ),
      ]) {
        for (const [code, media] of [
          [200, "application/octet-stream"],
          [status, "application/octet-stream"],
          [200, type],
          [200, " Application/Octet-Stream ; version=1"],
          [200, "text/plain"],
        ] as const) {
          const bytes = Uint8Array.from(input);

          const boundaries = [
            ...new Set([
              0,
              ...cuts.map((cut) => cut % (bytes.length + 1)),
              bytes.length,
            ]),
          ].toSorted((a, b) => a - b);

          const stream = new ReadableStream<Uint8Array>({
            start(controller) {
              for (let index = 1; index < boundaries.length; index += 1) {
                controller.enqueue(
                  bytes.slice(boundaries[index - 1], boundaries[index])
                );
              }

              controller.close();
            },
          });

          const response = new Response(stream);
          Object.defineProperties(response, {
            headers: { value: { get: () => media } },
            status: { value: code },
          });
          const fetcher: KekFetch = () => Promise.resolve(response);

          const result = yield* makeKekLoader(fetcher)
            .load(config)
            .pipe(Effect.result);

          const accepted =
            code === 200 &&
            media.split(";")[0]?.trim().toLowerCase() ===
              "application/octet-stream" &&
            bytes.length === 32;

          expect(Result.isSuccess(result)).toBe(accepted);

          if (Result.isSuccess(result)) {
            const reference = yield* Effect.promise(() =>
              crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
                "encrypt",
              ])
            );

            const algorithm = { iv: new Uint8Array(12), name: "AES-GCM" };
            const probe = new Uint8Array([1, 2, 3]);

            const actual = yield* Effect.promise(() =>
              crypto.subtle.encrypt(algorithm, result.success.current, probe)
            );

            const expected = yield* Effect.promise(() =>
              crypto.subtle.encrypt(algorithm, reference, probe)
            );

            expect(new Uint8Array(actual)).toEqual(new Uint8Array(expected));
          }
        }
      }
    }),
  options
);

const flip = (bytes: readonly number[], index: number) =>
  bytes.map((byte, at) => (at === index ? flipByte(byte) : byte));

const corruptions = (sealed: Sealed): readonly Sealed[] => [
  ...sealed.ciphertext.map((_, index) => ({
    ...sealed,
    ciphertext: flip(sealed.ciphertext, index),
  })),
  ...sealed.iv.map((_, index) => ({ ...sealed, iv: flip(sealed.iv, index) })),
];

it.effect.prop(
  "envelope: plaintext round-trips and every single-byte ciphertext, tag, IV mutation or changed kekId refuses",
  {
    prefix: Schema.Literals(["", "\uFEFF", "\u0000", "😀"]),
    text: Arbitrary.schema(Schema.String.check(Schema.isMaxLength(32))).pipe(
      Arbitrary.filter((value) => value.isWellFormed())
    ),
  },
  ({ prefix, text }) =>
    Effect.gen(function* envelopes() {
      const value = prefix + text;
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();
      const wrapped = yield* ring.wrap(dek, name);
      const sealed = yield* ring.encrypt(Redacted.make(value), dek, name, 1);
      const opened = yield* ring.unwrap(wrapped, name, wrapped.kekId);
      expect(
        sameValue(
          yield* ring.decrypt(sealed, opened, name, 1),
          Redacted.make(value)
        )
      ).toBe(true);

      for (const changed of corruptions(sealed)) {
        expect(
          (yield* ring.decrypt(changed, opened, name, 1).pipe(Effect.result))
            ._tag
        ).toBe("Failure");
      }

      for (const changed of corruptions(wrapped)) {
        expect(
          (yield* ring
            .unwrap({ ...changed, kekId: wrapped.kekId }, name, wrapped.kekId)
            .pipe(Effect.result))._tag
        ).toBe("Failure");
      }

      for (const expectedId of [wrapped.kekId, `${wrapped.kekId}-changed`]) {
        expect(
          (yield* ring
            .unwrap(
              { ...wrapped, kekId: `${wrapped.kekId}-changed` },
              name,
              expectedId
            )
            .pipe(Effect.result))._tag
        ).toBe("Failure");
      }
    }).pipe(Effect.provide(Keyring.testLayer())),
  { arbitrary: { runs: 12 }, timeout: 15_000 }
);

it.effect.prop(
  "Unicode refusal: every ill-formed credential refuses at set and encrypt without writing a value or metadata row",
  {
    prefix: Schema.String,
    suffix: Schema.String,
    surrogate: bounded(0xd8_00, 0xdf_ff),
  },
  ({ prefix, suffix, surrogate }) =>
    Effect.gen(function* malformed() {
      const value = `${prefix.toWellFormed()}!${String.fromCodePoint(surrogate)}!${suffix.toWellFormed()}`;
      expect(value.isWellFormed()).toBe(false);
      const credential = yield* Credential;
      const store = yield* CredentialStore;
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();

      for (const result of [
        yield* credential
          .set(Redacted.make(value), metadata)
          .pipe(Effect.asVoid, Effect.result),
        yield* ring
          .encrypt(Redacted.make(value), dek, name, 1)
          .pipe(Effect.asVoid, Effect.result),
      ]) {
        expect(result._tag).toBe("Failure");

        if (Result.isFailure(result)) {
          expect(result.failure._tag).toBe("ValueNotWellFormed");
          expect(JSON.stringify(result.failure)).not.toContain(
            JSON.stringify(value).slice(1, -1)
          );
        }
      }

      expect(yield* store.value()).toBeUndefined();
      expect(yield* store.meta()).toBeUndefined();
    }).pipe(Effect.provide(credentialLayer())),
  { arbitrary: { runs: 20 }, timeout: 15_000 }
);

it.effect.prop(
  "leading BOM: U+FEFF is credential data and survives with every generated well-formed suffix",
  {
    suffix: Arbitrary.schema(Schema.String.check(Schema.isMaxLength(32))).pipe(
      Arbitrary.filter((value) => value.isWellFormed())
    ),
  },
  ({ suffix }) =>
    Effect.gen(function* bom() {
      const value = `\uFEFF${suffix}`;
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();
      const encrypted = yield* ring.encrypt(Redacted.make(value), dek, name, 1);
      expect(
        sameValue(
          yield* ring.decrypt(encrypted, dek, name, 1),
          Redacted.make(value)
        )
      ).toBe(true);
    }).pipe(Effect.provide(Keyring.testLayer())),
  { arbitrary: { runs: 12 } }
);

it.effect.prop(
  "fatal UTF-8: authenticated malformed credential bytes refuse through the typed key-error channel",
  { byte: bounded(128, 255) },
  ({ byte }) =>
    Effect.gen(function* malformedBytes() {
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();
      const iv = new Uint8Array(12);

      const ciphertext = yield* Effect.promise(() =>
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
          new Uint8Array([byte])
        )
      );

      const result = yield* ring
        .decrypt(
          { ciphertext: [...new Uint8Array(ciphertext)], iv: [...iv] },
          dek,
          name,
          1
        )
        .pipe(Effect.result);

      expect(result._tag).toBe("Failure");

      if (Result.isFailure(result)) {
        expect(result.failure._tag).toBe("KeyUnavailable");
      }
    }).pipe(Effect.provide(Keyring.testLayer())),
  { arbitrary: { runs: 12 } }
);
