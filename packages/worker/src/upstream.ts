// oxlint-disable typescript/promise-function-async -- Fetch adapter callbacks return transport promises; Effect owns cancellation and deadlines.
import type { GatewayRequest } from "@lockjaw/gateway-rules";
import { Clock, Context, Effect, Layer, Stream } from "effect";
import { FetchHttpClient, HttpClient, HttpClientRequest } from "effect/http";

import { fault } from "./fault.js";
import type { GatewayFault } from "./fault.js";

export interface UpstreamResponse {
  readonly body: Stream.Stream<Uint8Array, GatewayFault>;
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  readonly headers: readonly {
    readonly name: string;
    readonly value: string;
  }[];
}

const failed = () =>
  fault(
    "upstream",
    "Retry with a fresh caller token; if it fails again, check the approved upstream's availability.",
    502
  );

const outgoingRequest = (request: GatewayRequest) =>
  Effect.try({
    catch: () =>
      fault(
        "request",
        "Use a valid HTTP method, headers and a body supported by that method.",
        400
      ),
    try: () => {
      const init: RequestInit = {
        headers: request.headers.map((header): [string, string] => [
          header.name,
          header.value,
        ]),
        method: request.method,
      };

      if (request.body !== undefined) {
        init.body = request.body;
      }

      return HttpClientRequest.fromWeb(new Request(request.url, init));
    },
  });

export class Upstream extends Context.Service<
  Upstream,
  {
    readonly send: (
      request: GatewayRequest
    ) => Effect.Effect<UpstreamResponse, GatewayFault>;
  }
>()("secret-cell/Upstream") {
  static readonly layer = (deadlineMs = 10_000) =>
    Layer.effect(
      Upstream,
      Effect.gen(function* upstreamLayer() {
        const client = yield* HttpClient.HttpClient;

        return Upstream.of({
          send: Effect.fn("Upstream.send")(function* send(request) {
            const end = (yield* Clock.currentTimeMillis) + deadlineMs;
            const outgoing = yield* outgoingRequest(request);

            const response = yield* client.execute(outgoing).pipe(
              Effect.provideService(FetchHttpClient.RequestInit, {
                redirect: "manual",
              }),
              Effect.timeout(deadlineMs),
              Effect.mapError(failed)
            );

            return {
              body: Stream.unwrap(
                Clock.currentTimeMillis.pipe(
                  Effect.map((now) =>
                    response.stream.pipe(
                      Stream.mapError(failed),
                      Stream.interruptWhen(
                        Effect.sleep(Math.max(0, end - now)).pipe(
                          Effect.andThen(Effect.fail(failed()))
                        )
                      )
                    )
                  )
                )
              ),
              headers: Object.entries(response.headers).map(
                ([name, value]) => ({ name, value })
              ),
              status: response.status,
              statusText: "",
              url: response.url ?? request.url,
            };
          }),
        });
      })
    );

  static readonly liveLayer = Upstream.layer().pipe(
    Layer.provide(FetchHttpClient.layer)
  );
  static readonly testLayer = (service: Upstream["Service"]) =>
    Layer.succeed(Upstream, service);
}
