// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
import { EchoRedactor, Fill, Policy } from "@lockjaw/gateway-rules";
import { Effect, Layer } from "effect";

import { CallerAuth } from "./caller-auth.js";
import { handle } from "./gateway.js";
import type { Bindings } from "./gateway.js";
import { Upstream } from "./upstream.js";

export { Credential } from "./credential-do.js";

export { Registry } from "./directory-do.js";

export { Grants } from "./grants-do.js";

export { Replay } from "./replay-do.js";

interface Environment extends Bindings {
  readonly CALLER_DOCUMENTS: string;
  readonly CELL_DID: string;
}

export default {
  fetch: async (request: Request, env: Environment) =>
    await Effect.runPromise(
      handle(request, env).pipe(
        Effect.provide(
          Layer.mergeAll(
            CallerAuth.layer(env.CALLER_DOCUMENTS, env.CELL_DID),
            Upstream.liveLayer,
            Fill.layer,
            EchoRedactor.layer,
            Policy.layer
          )
        ),
        Effect.catch(() =>
          Effect.succeed(
            Response.json(
              {
                error: {
                  next: "Ask the cell operator to check the static caller documents, KEK and Durable Object storage, then retry with a fresh token.",
                  what: "Lockjaw could not complete the request",
                  why: "A required binding or storage operation failed",
                },
              },
              { status: 503 }
            )
          )
        )
      )
    ),
};
