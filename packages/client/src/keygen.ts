import { open } from "node:fs/promises";

import { encodeDidKeyP256 } from "@lockjaw/domain";
import { Effect } from "effect";

import { usage } from "./failure.js";

const failed = () =>
  usage(
    "key generation or exclusive public document write failed",
    "sc keygen --public-out <new-public-document.json> | op document create - --vault Private --title lockjaw-approver --file-name identity.json"
  );

export const keygen = Effect.fn("Client.keygen")(function* keygen(
  publicOut: string | undefined,
  stdoutIsTTY: boolean
) {
  if (stdoutIsTTY) {
    return yield* usage(
      "pipe it into op document create -",
      "sc keygen --public-out ~/approver.did.json | op document create - --vault Private --title lockjaw-approver --file-name identity.json"
    );
  }

  if (publicOut === undefined) {
    return yield* usage(
      "keygen requires --public-out",
      "sc keygen --public-out <public-document.json> | op document create - --vault Private --title lockjaw-approver --file-name identity.json"
    );
  }

  const pair = yield* Effect.tryPromise({
    catch: failed,
    try: async () =>
      await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      ),
  });

  const signing = yield* Effect.tryPromise({
    catch: failed,
    try: async () => await crypto.subtle.exportKey("jwk", pair.privateKey),
  });

  const publicKeyJwk = yield* Effect.tryPromise({
    catch: failed,
    try: async () => await crypto.subtle.exportKey("jwk", pair.publicKey),
  });

  const did = encodeDidKeyP256({
    crv: "P-256",
    kty: "EC",
    x: publicKeyJwk.x ?? "",
    y: publicKeyJwk.y ?? "",
  });

  if (did === undefined) {
    return yield* failed();
  }

  const kid = `#${did.slice("did:key:".length)}`;

  const document = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
    ],
    assertionMethod: [`${did}${kid}`],
    authentication: [`${did}${kid}`],
    id: did,
    issuer: "approver",
    name: "approver",
    verificationMethod: [
      {
        controller: did,
        id: `${did}${kid}`,
        publicKeyJwk,
        type: "JsonWebKey2020",
      },
    ],
  };

  yield* Effect.tryPromise({
    catch: failed,
    try: async () => {
      const file = await open(publicOut, "wx", 0o644);

      try {
        await file.chmod(0o644);
        await file.writeFile(`${JSON.stringify(document, null, 2)}\n`);
      } finally {
        await file.close();
      }
    },
  });

  return `${JSON.stringify({ did, kid, signing })}\n`;
});
