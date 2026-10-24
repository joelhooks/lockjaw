import { RunHandle } from "@lockjaw/domain";
import {
  activeChain,
  lxmFor,
  passableLxm,
  parsePassScope,
} from "@lockjaw/gateway-rules";
import {
  decodeDidKey,
  NonceBinding,
  SignedPass,
  verifyPass,
} from "@rat-king/lexicon/passes";
import { PublicKey, TrustFailure } from "@rat-king/lexicon/trust";
import type { TrustFailure as TrustError } from "@rat-king/lexicon/trust";
// oxlint-disable typescript/promise-function-async -- Durable Object RPC callbacks are lazy Promise boundaries.
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Effect, Result, Schema } from "effect";

import { named } from "./bindings.js";
import type { Bindings } from "./bindings.js";
import { boundary } from "./boundary.js";
import type { Documents } from "./caller-auth.js";
import { GatewayFault } from "./fault.js";

export const passRefused = (why: string, next: string) =>
  new GatewayFault({
    credential: "request",
    next,
    rule: "pass",
    status: 401,
    what: "Lockjaw refused the worker pass",
    why,
  });

const freshPass =
  "Ask your desk for a fresh pass with sc pass --handle <run> --worker-key <did:key> --scope <lxm[:pattern]>, then retry with sc --pass <file>.";

export const trustFault = (failure: TrustError) => {
  const [
    what = "Pass refused",
    why = "Trust verification failed",
    next = freshPass,
  ] = failure.reason.split(";").map((clause) => clause.trim());

  return new GatewayFault({
    credential: "request",
    next,
    rule: "pass",
    status: 401,
    what,
    why,
  });
};

export const nonceBinding = (env: Bindings, now: number) =>
  NonceBinding.of({
    bind: (deskDid, nonce, identity, until) =>
      Effect.tryPromise({
        catch: () =>
          new TrustFailure({
            reason:
              "Nonce refused; durable binding failed; ask the desk queue for a fresh pass",
          }),
        try: async () =>
          await named(env.REPLAY, `pass:${deskDid}`).bind(
            deskDid,
            nonce,
            JSON.stringify(identity),
            until * 1000,
            now * 1000
          ),
      }),
  });

export const passVerifier = (documents: typeof Documents.Type) =>
  Effect.fn("Pass.verify")(function* verifyCellPass(
    text: string,
    now: number,
    env: Bindings
  ) {
    const signed = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(SignedPass)
    )(text).pipe(
      Effect.mapError(() =>
        passRefused(
          "The x-sc-pass header is not a signed DAG-CBOR worker pass envelope.",
          freshPass
        )
      )
    );

    const pass = signed.record;
    yield* Schema.decodeUnknownEffect(RunHandle)(pass.run).pipe(
      Effect.mapError(() =>
        passRefused("The run handle is invalid.", freshPass)
      )
    );

    const desk = documents.find(
      (doc) => doc.id === pass.deskDid && doc.name === pass.desk
    );

    const methods = desk?.verificationMethod.filter(
      (entry) =>
        entry.controller === desk.id &&
        desk.authentication.includes(entry.id) &&
        Schema.is(PublicKey)(entry.publicKeyJwk)
    );

    if (desk === undefined || methods === undefined || methods.length === 0) {
      return yield* passRefused(
        "The desk has no authenticated P-256 key in the callers documents.",
        freshPass
      );
    }

    const workerKey = yield* decodeDidKey(pass.worker).pipe(
      Effect.mapError(trustFault)
    );

    if (
      methods.some(
        (method) =>
          method.publicKeyJwk.x === workerKey.x &&
          method.publicKeyJwk.y === workerKey.y
      )
    ) {
      return yield* passRefused(
        "The worker borrowed an authenticated desk key.",
        freshPass
      );
    }

    if (parsePassScope(pass.scope) === undefined) {
      return yield* passRefused(
        "The pass names an lxm or credential pattern that workers cannot carry.",
        freshPass
      );
    }

    const records = yield* boundary(
      async () => await named(env.GRANTS, "grants").list()
    );

    const issuerScope = records.flatMap(({ grant }) =>
      grant.grantee.desk === desk.name &&
      grant.grantee.runHandle === undefined &&
      activeChain(records, grant.id, now * 1000) !== undefined
        ? [
            "sh.secretcell.list",
            ...grant.scope.ops.map(lxmFor).filter(passableLxm),
          ].flatMap((scopeLxm) =>
            grant.scope.credentials.map((pattern) =>
              pattern === "*" ? scopeLxm : `${scopeLxm}:${pattern}`
            )
          )
        : []
    );

    const grantable = new Set(
      pass.scope.map((scope) => scope.split(":")[0] ?? "").filter(passableLxm)
    );

    let failure = passRefused(
      "No authenticated desk key verifies this pass.",
      freshPass
    );

    for (const method of methods) {
      const key = yield* Schema.decodeUnknownEffect(PublicKey)(
        method.publicKeyJwk
      ).pipe(
        Effect.mapError(() =>
          passRefused("The authenticated desk key is not P-256.", freshPass)
        )
      );

      const result = yield* verifyPass(
        {
          grantable,
          issuerScope,
          knownDesk: { did: desk.id, key, name: desk.name },
        },
        signed,
        now
      ).pipe(
        Effect.provideService(NonceBinding, nonceBinding(env, now)),
        Effect.provide(signatures),
        Effect.result
      );

      if (Result.isSuccess(result)) {
        return {
          issuer: desk.issuer,
          pass: { ...pass, run: RunHandle.make(pass.run) },
          verified: result.success,
        };
      }

      failure = trustFault(result.failure);
    }

    return yield* failure;
  });
