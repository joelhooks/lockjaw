// oxlint-disable typescript/promise-function-async -- RPC callbacks are lazy Promise boundaries; Effect owns the workflow.
import { Effect, Schema } from "effect";

import type { Rpc, RpcError } from "./credential-do.js";
import { GatewayFault, boundaryFault, fault } from "./fault.js";

export const jsonBody = (request: Request) =>
  Effect.tryPromise({
    catch: () => fault("request", "Send a valid JSON request body.", 400),
    try: async () => await request.text(),
  });

export const parse = <A, I>(schema: Schema.Codec<A, I>, text: string) =>
  Schema.decodeUnknownEffect(Schema.fromJsonString(schema))(text).pipe(
    Effect.mapError(() =>
      fault("request", "Send a JSON body matching this route's contract.", 400)
    )
  );

export const rpcFailure = (error: RpcError) => {
  if (
    error.what !== undefined &&
    error.why !== undefined &&
    error.next !== undefined
  ) {
    return new GatewayFault({
      credential: error.credential,
      next: error.next,
      rule: error.rule,
      status: error.rule === "kek" ? 503 : 403,
      what: error.what,
      why: error.why,
    });
  }

  return fault(
    error.rule,
    "Check the named credential policy and lifecycle, then retry with a fresh caller token.",
    403,
    error.credential
  );
};

export const rpc = <A>(call: () => Promise<Rpc<A>>) =>
  Effect.tryPromise({ catch: boundaryFault, try: call }).pipe(
    Effect.flatMap((result) =>
      result.ok
        ? Effect.succeed(result.value)
        : Effect.fail(rpcFailure(result.error))
    )
  );

export const boundary = <A>(call: () => Promise<A>) =>
  Effect.tryPromise({ catch: boundaryFault, try: call });
