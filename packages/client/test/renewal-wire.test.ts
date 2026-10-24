import { expect, it } from "@effect/vitest";
import { encodeDidKeyP256 } from "@lockjaw/domain";
import { PublicKey, Signatures } from "@rat-king/lexicon/trust";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Effect, Schema } from "effect";

import { renewalProofBytes, renewalRequest } from "../src/renewal-wire.js";
import { identity } from "./harness.js";

const Request = Schema.Struct({
  proof: Schema.Struct({
    nonce: Schema.String,
    now: Schema.Int,
    run: Schema.String,
    signature: Schema.String,
  }),
  run: Schema.String,
  workerDid: Schema.String,
});

it.effect(
  "the renewal wire packet 3e mirrors is one JSON line with a domain-tagged worker proof",
  () =>
    Effect.gen(function* wire() {
      const worker = yield* identity("did:web:desk.invalid", "acme/desk");

      const publicKey = yield* Schema.decodeUnknownEffect(PublicKey)(
        worker.publicJwk
      );

      const workerDid = encodeDidKeyP256(publicKey) ?? "";

      const key = yield* Effect.promise(
        async () =>
          await crypto.subtle.importKey(
            "jwk",
            worker.signing,
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign"]
          )
      );

      const line = yield* renewalRequest(
        publicKey,
        key,
        "run-1",
        workerDid,
        1_700_000_000
      );

      expect(line.endsWith("\n")).toBe(true);
      expect(line.indexOf("\n")).toBe(line.length - 1);

      const received = yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(Request),
        { onExcessProperty: "error" }
      )(line.trim());

      expect(received.run).toBe("run-1");
      expect(received.proof.run).toBe("run-1");
      expect(received.proof.now).toBe(1_700_000_000);
      expect(received.workerDid).toBe(workerDid);
      expect(received.proof.nonce.length).toBeGreaterThanOrEqual(22);

      const again = yield* renewalRequest(
        publicKey,
        key,
        "run-1",
        workerDid,
        1_700_000_000
      );

      expect(again).not.toBe(line);

      const verify = (run: string) =>
        Signatures.use((signer) =>
          signer.verify(
            publicKey,
            renewalProofBytes({
              nonce: received.proof.nonce,
              now: received.proof.now,
              run,
              workerDid,
            }),
            received.proof.signature
          )
        ).pipe(Effect.provide(signatures));

      expect(yield* verify("run-1")).toBe(true);
      expect(yield* verify("run-2")).toBe(false);
      expect(line).not.toContain(worker.d);
    })
);
