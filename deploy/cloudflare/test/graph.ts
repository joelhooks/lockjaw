import { NodeServices } from "@effect/platform-node";
import { AlchemyContextLive } from "alchemy/AlchemyContext";
import { AuthProviders } from "alchemy/Auth";
import { Stage } from "alchemy/Stage";
import { Effect, Layer } from "effect";
import { FetchHttpClient } from "effect/http";

import stack from "../alchemy.run.ts";

// oxlint-disable-next-line typescript/promise-function-async -- This rejecting transport never performs I/O.
const offlineFetch: typeof fetch = () =>
  Promise.reject(new Error("OFFLINE_HTTP_REFUSED"));

export const compiled = stack.pipe(
  Effect.scoped,
  Effect.provideService(AuthProviders, {}),
  Effect.provideService(FetchHttpClient.Fetch, offlineFetch),
  Effect.provide(
    Layer.mergeAll(AlchemyContextLive, Layer.succeed(Stage, "test")).pipe(
      Layer.provideMerge(NodeServices.layer)
    )
  )
);
