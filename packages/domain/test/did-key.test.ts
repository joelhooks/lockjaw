import { expect, it } from "@effect/vitest";
import { Effect, Schema } from "effect";

import {
  decodeDidKeyP256,
  didKeyRefusal,
  encodeDidKeyP256,
} from "../src/index.js";

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const p256Prime =
  0xff_ff_ff_ff_00_00_00_01_00_00_00_00_00_00_00_00_00_00_00_00_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ffn;

const base58 = (bytes: Uint8Array) => {
  let value = bytes.reduce((total, byte) => total * 256n + BigInt(byte), 0n);
  let text = "";

  while (value > 0n) {
    text = `${alphabet[Number(value % 58n)] ?? ""}${text}`;
    value /= 58n;
  }

  return text;
};

const didFor = (codec: readonly number[], point: Uint8Array) => {
  const bytes = new Uint8Array(codec.length + point.length);
  bytes.set(codec);
  bytes.set(point, codec.length);

  return `did:key:z${base58(bytes)}`;
};

const xBytes = (x: bigint) => {
  const bytes = new Uint8Array(32);
  let rest = x;

  for (let index = 31; index >= 0; index -= 1) {
    bytes[index] = Number(rest % 256n);
    rest /= 256n;
  }

  return bytes;
};

const compressed = (prefix: number, x: Uint8Array) => {
  const point = new Uint8Array(33);
  point[0] = prefix;
  point.set(x, 1);

  return point;
};

const generated = Effect.promise(async () => {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  return await crypto.subtle.exportKey("jwk", pair.publicKey);
});

it.effect.prop(
  "did:key P-256 round-trips and agrees with WebCrypto's exported JWK",
  { seed: Schema.Int },
  () =>
    Effect.gen(function* roundTrip() {
      const jwk = yield* generated;
      const x = jwk.x ?? "";
      const y = jwk.y ?? "";
      const did = encodeDidKeyP256({ crv: "P-256", kty: "EC", x, y });

      expect(did?.startsWith("did:key:zDn")).toBe(true);

      const decoded = decodeDidKeyP256(did ?? "");

      expect(decoded).toEqual({
        jwk: { crv: "P-256", kty: "EC", x, y },
        ok: true,
      });

      if (decoded.ok) {
        const key = yield* Effect.promise(
          async () =>
            await crypto.subtle.importKey(
              "jwk",
              decoded.jwk,
              { name: "ECDSA", namedCurve: "P-256" },
              false,
              ["verify"]
            )
        );

        expect(key.type).toBe("public");
      }
    }),
  { arbitrary: { runs: 40 } }
);

it("refuses non-z multibase, wrong multicodec, wrong lengths, uncompressed, x >= p and off-curve points, each with three parts", () => {
  const one = xBytes(1n);
  const valid = didFor([0x80, 0x24], compressed(0x02, xBytes(3n)));
  let offCurve: bigint | undefined;

  for (let x = 1n; x < 64n && offCurve === undefined; x += 1n) {
    const result = decodeDidKeyP256(
      didFor([0x80, 0x24], compressed(0x02, xBytes(x)))
    );

    if (!result.ok) {
      expect(result.reason).toBe("off-curve");
      offCurve = x;
    }
  }

  expect(offCurve).toBeDefined();

  const cases = [
    ["multibase", valid.replace("did:key:z", "did:key:m")],
    ["multibase", "did:web:example.invalid"],
    ["multicodec", didFor([0xed, 0x01], compressed(0x02, one))],
    ["length", didFor([0x80, 0x24], one)],
    ["length", didFor([0x80, 0x24], Uint8Array.from([0x02, ...one, 0x00]))],
    ["prefix", didFor([0x80, 0x24], compressed(0x04, one))],
    ["range", didFor([0x80, 0x24], compressed(0x02, xBytes(p256Prime)))],
    [
      "off-curve",
      didFor([0x80, 0x24], compressed(0x02, xBytes(offCurve ?? 0n))),
    ],
  ] as const;

  for (const [reason, did] of cases) {
    const result = decodeDidKeyP256(did);

    expect([reason, result.ok ? "ok" : result.reason]).toEqual([
      reason,
      reason,
    ]);

    const message = didKeyRefusal(reason);

    expect(
      message.what.length > 0 &&
        message.why.length > 0 &&
        message.next.length > 0
    ).toBe(true);
  }
});
