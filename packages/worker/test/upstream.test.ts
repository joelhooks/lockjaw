// oxlint-disable typescript/promise-function-async -- Injected fetch transport is a native Promise boundary.
import { expect, it } from "@effect/vitest";
import { Deferred, Effect, Fiber, Layer, Stream } from "effect";
import { FetchHttpClient, HttpClient, HttpClientResponse } from "effect/http";
import { TestClock } from "effect/testing";

import { Upstream } from "../src/upstream.js";

it.effect(
  "the real Effect fetch adapter sets manual redirects and passes a non-success status through",
  () =>
    Effect.gen(function* transportTest() {
      const received: RequestInit[] = [];

      const transport: typeof fetch = (_input, init) => {
        if (init) {
          received.push(init);
        }

        return Promise.resolve(
          new Response("redirect", {
            headers: { location: "https://other.example/" },
            status: 307,
          })
        );
      };

      const response = yield* Upstream.use((upstream) =>
        upstream.send({
          headers: [],
          method: "GET",
          url: "https://api.example.com/",
        })
      ).pipe(
        Effect.provide(
          Upstream.layer().pipe(Layer.provide(FetchHttpClient.layer))
        ),
        Effect.provideService(FetchHttpClient.Fetch, transport)
      );

      expect(response.status).toBe(307);
      expect(received[0]?.redirect).toBe("manual");
      expect(received[0]?.signal).toBeDefined();
    })
);

it.effect("the deadline covers response headers", () =>
  Effect.gen(function* deadline() {
    const ready = yield* Deferred.make<boolean>();

    const client = HttpClient.make(() =>
      Deferred.succeed(ready, true).pipe(Effect.andThen(Effect.never))
    );

    const task = yield* Upstream.use((upstream) =>
      upstream.send({
        headers: [],
        method: "GET",
        url: "https://api.example.com/",
      })
    ).pipe(
      Effect.provide(Upstream.layer(1000)),
      Effect.provideService(HttpClient.HttpClient, client),
      Effect.result,
      Effect.forkChild
    );

    yield* Deferred.await(ready);
    yield* TestClock.adjust(1000);
    const result = yield* Fiber.join(task);
    expect(result._tag).toBe("Failure");
  })
);

it.effect("one overall deadline also interrupts a stalled response body", () =>
  Effect.gen(function* deadline() {
    const started = yield* Deferred.make<boolean>();

    const client = HttpClient.make((request) =>
      Effect.succeed(
        HttpClientResponse.fromWeb(
          request,
          new Response(
            new ReadableStream<Uint8Array>({
              start: (controller) => {
                controller.enqueue(new Uint8Array([1]));
              },
            })
          )
        )
      )
    );

    const response = yield* Upstream.use((upstream) =>
      upstream.send({
        headers: [],
        method: "GET",
        url: "https://api.example.com/",
      })
    ).pipe(
      Effect.provide(Upstream.layer(1000)),
      Effect.provideService(HttpClient.HttpClient, client)
    );

    const task = yield* response.body.pipe(
      Stream.tap(() => Deferred.succeed(started, true)),
      Stream.runCollect,
      Effect.result,
      Effect.forkChild
    );

    yield* Deferred.await(started);
    yield* TestClock.adjust(1000);
    const result = yield* Fiber.join(task);
    expect(result._tag).toBe("Failure");
  })
);
