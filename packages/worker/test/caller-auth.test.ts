// oxlint-disable typescript/promise-function-async -- Web Crypto test signer is an injected native Promise boundary.
import { expect, it } from "@effect/vitest";
import { Clock, Effect } from "effect";

import { CallerAuth, base64url } from "../src/caller-auth.js";
import { boundaryFault } from "../src/fault.js";

it.effect(
  "static DID documents verify P-256 JWTs and bind caller identity, rather than trusting token display claims",
  () =>
    Effect.gen(function* authenticateP256() {
      const pair = yield* Effect.tryPromise({
        catch: boundaryFault,
        try: () =>
          crypto.subtle.generateKey(
            { name: "ECDSA", namedCurve: "P-256" },
            true,
            ["sign", "verify"]
          ),
      });

      const publicKeyJwk = yield* Effect.tryPromise({
        catch: boundaryFault,
        try: () => crypto.subtle.exportKey("jwk", pair.publicKey),
      });

      const did = "did:web:p256.invalid";
      const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

      const header = base64url(
        new TextEncoder().encode(JSON.stringify({ alg: "ES256", kid: "#key" }))
      );

      const payload = base64url(
        new TextEncoder().encode(
          JSON.stringify({
            aud: "did:web:cell.invalid",
            exp: now + 60,
            iat: now,
            iss: did,
            issuer: "forged-host",
            jti: "unique-test-jti-long-enough",
            lxm: "sh.secretcell.fetch",
            name: "forged/admin",
            sid: "signed-session",
          })
        )
      );

      const data = `${header}.${payload}`;

      const signature = yield* Effect.tryPromise({
        catch: boundaryFault,
        try: () =>
          crypto.subtle.sign(
            { hash: "SHA-256", name: "ECDSA" },
            pair.privateKey,
            new TextEncoder().encode(data)
          ),
      });

      const documents = JSON.stringify([
        {
          authentication: [`${did}#key`],
          id: did,
          issuer: "approved-host",
          name: "test/agent",
          verificationMethod: [
            { controller: did, id: `${did}#key`, publicKeyJwk },
          ],
        },
      ]);

      const result = yield* CallerAuth.use((auth) =>
        auth.authenticate({
          lxm: "sh.secretcell.fetch",
          token: `Bearer ${data}.${base64url(new Uint8Array(signature))}`,
        })
      ).pipe(
        Effect.provide(CallerAuth.layer(documents, "did:web:cell.invalid"))
      );

      expect(result.caller).toEqual({
        did,
        issuer: "approved-host",
        name: "test/agent",
        sid: "signed-session",
      });

      const denied = yield* CallerAuth.use((auth) =>
        auth.authenticate({
          lxm: "sh.secretcell.fetch",
          token: `Bearer ${data}.${base64url(new Uint8Array(signature))}`,
        })
      ).pipe(
        Effect.provide(
          CallerAuth.layer(
            documents
              .replace(
                '"authentication":[',
                '"authentication":["unauthorized",'
              )
              .replace(`${did}#key`, "not-a-key"),
            "did:web:cell.invalid"
          )
        ),
        Effect.result
      );

      expect(denied._tag).toBe("Failure");
    })
);
