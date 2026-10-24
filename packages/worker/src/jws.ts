// oxlint-disable typescript/promise-function-async -- Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
import { Effect, Schema } from "effect";

import { fault } from "./fault.js";

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Jwk = Schema.Struct({
  crv: Schema.String,
  d: Schema.optionalKey(Schema.Never),
  kty: Schema.String,
  x: Schema.String,
  y: Schema.optionalKey(Schema.String),
});

export type Jwk = typeof Jwk.Type;

export const denied = () =>
  fault(
    "caller-auth",
    "Mint a fresh service JWT with this cell's audience, the operation lxm, a unique jti, and a signed sid.",
    401
  );

const compact =
  /^(?:Bearer )?(?<header>[A-Za-z0-9_-]+)\.(?<claims>[A-Za-z0-9_-]+)\.(?<signature>[A-Za-z0-9_-]+)$/u;

export const splitCompact = (text: string | null | undefined) => {
  const [, header = "", payload = "", signature = ""] =
    compact.exec(text ?? "") ?? [];

  return header === "" || payload === "" || signature === ""
    ? undefined
    : { header, payload, signature };
};

export const unbase64 = (text: string) =>
  Uint8Array.from(
    atob(text.replaceAll("-", "+").replaceAll("_", "/")),
    (c) => c.codePointAt(0) ?? 0
  );

export const base64url = (bytes: Uint8Array) =>
  btoa(Array.from(bytes, (b) => String.fromCodePoint(b)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

export const validKey = (alg: string, jwk: typeof Jwk.Type) =>
  alg === "ES256"
    ? jwk.kty === "EC" &&
      jwk.crv === "P-256" &&
      jwk.y !== undefined &&
      jwk.y !== ""
    : jwk.kty === "OKP" && jwk.crv === "Ed25519";

export const parse = (text: string) =>
  Effect.try({
    catch: denied,
    try: () => new TextDecoder("utf-8", { fatal: true }).decode(unbase64(text)),
  });

export const verify = (
  alg: "EdDSA" | "ES256",
  jwk: typeof Jwk.Type,
  signature: string,
  input: string
) =>
  Effect.gen(function* verifySignature() {
    const algorithm =
      alg === "ES256"
        ? { hash: "SHA-256", name: "ECDSA", namedCurve: "P-256" }
        : { name: "Ed25519" };

    const key = yield* Effect.tryPromise({
      catch: denied,
      try: async () =>
        await crypto.subtle.importKey("jwk", jwk, algorithm, false, ["verify"]),
    });

    return yield* Effect.tryPromise({
      catch: denied,
      try: async () =>
        await crypto.subtle.verify(
          algorithm,
          key,
          unbase64(signature),
          new TextEncoder().encode(input)
        ),
    });
  });
