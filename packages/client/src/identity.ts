import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";

import {
  decodeDidKeyP256,
  didKeyRefusal,
  encodeDidKeyP256,
} from "@lockjaw/domain";
import type { DidKeyRefusal } from "@lockjaw/domain";
import { signingKey } from "@rat-king/lexicon/pass-webcrypto";
import { signPass as mintPass, SignedPass } from "@rat-king/lexicon/passes";
import { Clock, Effect, Schema } from "effect";

import { ClientFailure, usage } from "./failure.js";

const PrivateJwk = Schema.Struct({
  crv: Schema.Literal("P-256"),
  d: Schema.NonEmptyString,
  kty: Schema.Literal("EC"),
  x: Schema.NonEmptyString,
  y: Schema.NonEmptyString,
});

const Identity = Schema.Struct({
  did: Schema.String.check(Schema.isPattern(/^did:(?:web|key):/u)),
  kid: Schema.optionalKey(Schema.NonEmptyString),
  signing: PrivateJwk,
});

export const readProtectedFile = (path: string, metadata = false) =>
  Effect.tryPromise({
    catch: () =>
      usage(
        metadata
          ? "metadata file must be a regular 0600 or 0644 file without PEM data"
          : "identity file must be a regular 0600 file",
        metadata
          ? "sc set <name> --kind github-app --github-app-file <metadata.json> < <key.pem>"
          : "chmod 600 <identity-file>"
      ),
    try: async () => {
      // oxlint-disable-next-line eslint/no-bitwise -- Combine OS open flags to refuse symlinks.
      const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);

      try {
        const stat = await file.stat();
        const allowed = metadata ? [0o600, 0o644] : [0o600];

        // oxlint-disable-next-line eslint/no-bitwise -- Only the POSIX mode bits participate in the permission check.
        if (!stat.isFile() || !allowed.includes(stat.mode & 0o7777)) {
          throw usage("unsafe file mode");
        }

        const text = await file.readFile("utf-8");

        if (metadata && text.includes("-----BEGIN")) {
          throw usage("pipe the key through stdin");
        }

        return text;
      } finally {
        await file.close();
      }
    },
  });

const invalid = () =>
  usage(
    "identity is missing or invalid",
    "sc --identity-file <identity.json> list"
  );

export const loadIdentity = Effect.fn("Client.loadIdentity")(
  function* loadIdentity(
    identityFile: string | undefined,
    identityEnv: string | undefined
  ) {
    const text =
      identityFile === undefined
        ? identityEnv
        : yield* readProtectedFile(identityFile);

    const identity = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(Identity)
    )(text).pipe(Effect.mapError(invalid));

    const key = yield* Effect.tryPromise({
      catch: invalid,
      try: async () =>
        await crypto.subtle.importKey(
          "jwk",
          identity.signing,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["sign"]
        ),
    });

    return { identity, key };
  }
);

const signCompact = (key: CryptoKey, header: string, payload: string) =>
  Effect.tryPromise({
    catch: invalid,
    try: async () =>
      await crypto.subtle.sign(
        { hash: "SHA-256", name: "ECDSA" },
        key,
        new TextEncoder().encode(`${header}.${payload}`)
      ),
  }).pipe(
    Effect.map(
      (signature) =>
        `${header}.${payload}.${Buffer.from(signature).toString("base64url")}`
    )
  );

const PublicJwk = Schema.Struct({
  crv: Schema.Literal("P-256"),
  d: Schema.optionalKey(Schema.String),
  kty: Schema.Literal("EC"),
  x: Schema.NonEmptyString,
  y: Schema.NonEmptyString,
});

const workerKeyNext =
  "sc pass --desk <desk-name> --handle <run> --worker-key <did:key:z...|public-jwk.json> --scope sh.secretcell.fetch";

const invalidKey = (reason: DidKeyRefusal) => {
  const refusal = didKeyRefusal(reason);

  return new ClientFailure({ code: 2, ...refusal });
};

export const workerDid = (value: string) =>
  Effect.gen(function* parseWorkerKey() {
    if (value.startsWith("did:")) {
      const decoded = decodeDidKeyP256(value);

      return decoded.ok ? value : yield* invalidKey(decoded.reason);
    }

    const text = yield* readProtectedFile(value, true);

    const parsed = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(PublicJwk)
    )(text).pipe(
      Effect.mapError(() =>
        usage("worker key must be a P-256 did:key or public JWK", workerKeyNext)
      )
    );

    if (parsed.d !== undefined) {
      return yield* new ClientFailure({
        code: 2,
        next: "Export only {kty, crv, x, y} from the worker's ephemeral key and pass that file to --worker-key.",
        what: "a private key component was supplied",
        why: "Only the worker's public key goes to the desk.",
      });
    }

    const did = encodeDidKeyP256({
      crv: parsed.crv,
      kty: parsed.kty,
      x: parsed.x,
      y: parsed.y,
    });

    return did ?? (yield* invalidKey("length"));
  });

export const maxPassSeconds = 600;

export interface PassRequest {
  readonly desk: string;
  readonly run: string;
  readonly scope: readonly string[];
  readonly seconds: number;
  readonly worker: string;
}

export const signPass = Effect.fn("Client.signPass")(function* signPass(
  identityFile: string | undefined,
  identityEnv: string | undefined,
  request: PassRequest
) {
  const { identity, key: signing } = yield* loadIdentity(
    identityFile,
    identityEnv
  );

  const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

  const { x, y } = identity.signing;

  const signed = yield* mintPass(
    signingKey({ crv: "P-256", kty: "EC", x, y }, signing),
    {
      $type: "sh.ratking.pass",
      desk: request.desk,
      deskDid: identity.did,
      exp: now + request.seconds,
      iat: now,
      nonce: randomBytes(16).toString("base64url"),
      run: request.run,
      scope: [...request.scope],
      v: 1,
      worker: request.worker,
    }
  ).pipe(Effect.mapError(() => usage("Pass minting failed", workerKeyNext)));

  return JSON.stringify(signed);
});

export const identityKeyDid = Effect.fn("Client.identityKeyDid")(
  function* identityKeyDid(
    identityFile: string | undefined,
    identityEnv: string | undefined
  ) {
    const { identity } = yield* loadIdentity(identityFile, identityEnv);
    const { crv, kty, x, y } = identity.signing;

    return encodeDidKeyP256({ crv, kty, x, y }) ?? (yield* invalid());
  }
);

export const passRun = (pass: string) =>
  Effect.gen(function* readPassRun() {
    const decoded = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(SignedPass)
    )(pass).pipe(
      Effect.mapError(() =>
        usage(
          "worker pass is not a valid signed DAG-CBOR envelope",
          "Ask your desk for a fresh pass with sc pass, then pass it with --pass <file>."
        )
      )
    );

    return decoded.record.run;
  });

export const directPassLive = Effect.fn("Client.directPassLive")(
  function* directPassLive(pass: string) {
    const decoded = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(SignedPass)
    )(pass).pipe(
      Effect.mapError(() =>
        usage("Invalid worker pass", "Ask the desk queue for a fresh sc pass.")
      )
    );

    const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

    if (decoded.record.exp <= now) {
      return yield* new ClientFailure({
        code: 1,
        next: "Ask your desk queue for a fresh pass, then retry with sc --pass <file>.",
        what: "worker pass expired",
        why: "A desk-minted --pass is never renewed by sc. No gateway request was sent.",
      });
    }

    return yield* Effect.void;
  }
);

export const loadSigner = Effect.fn("Client.loadSigner")(function* loadSigner(
  identityFile: string | undefined,
  identityEnv: string | undefined,
  audience: string,
  runHandle?: string
) {
  const { identity, key } = yield* loadIdentity(identityFile, identityEnv);
  const { did } = identity;
  const sid = runHandle ?? randomBytes(16).toString("base64url");

  const header = Buffer.from(
    JSON.stringify({
      alg: "ES256",
      kid: identity.kid ?? "#atproto",
      typ: "JWT",
    })
  ).toString("base64url");

  return Effect.fn("Client.sign")(function* sign(operation: string) {
    const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

    const payload = Buffer.from(
      JSON.stringify({
        aud: audience,
        exp: now + 60,
        iat: now,
        iss: did,
        jti: randomBytes(16).toString("base64url"),
        lxm: `sh.secretcell.${operation}`,
        sid,
      })
    ).toString("base64url");

    return yield* signCompact(key, header, payload);
  });
});
