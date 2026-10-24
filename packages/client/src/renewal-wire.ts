import { randomBytes } from "node:crypto";

import { encode } from "@ipld/dag-cbor";
import { signingKey } from "@rat-king/lexicon/pass-webcrypto";
import type { PublicKeyValue } from "@rat-king/lexicon/trust";
import { Effect } from "effect";

export const renewalDomain = "sh.ratking.pass.renew.v1";

export interface RenewalProofInput {
  readonly nonce: string;
  readonly now: number;
  readonly run: string;
  readonly workerDid: string;
}

export const renewalProofBytes = (input: RenewalProofInput): Uint8Array =>
  encode({
    domain: renewalDomain,
    nonce: input.nonce,
    now: input.now,
    run: input.run,
    workerDid: input.workerDid,
  });

export const renewalRequest = Effect.fn("RenewalWire.request")(
  function* renewalRequest(
    publicKey: PublicKeyValue,
    key: CryptoKey,
    run: string,
    workerDid: string,
    now: number,
    nonce: string = randomBytes(16).toString("base64url")
  ) {
    const signature = yield* signingKey(publicKey, key).sign(
      renewalProofBytes({ nonce, now, run, workerDid })
    );

    return `${JSON.stringify({
      proof: { nonce, now, run, signature },
      run,
      workerDid,
    })}\n`;
  }
);
