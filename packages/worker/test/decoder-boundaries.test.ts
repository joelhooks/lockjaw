// oxlint-disable typescript/promise-function-async -- Web Crypto key generation returns a native Promise.
import { expect, it } from "@effect/vitest";
import { GitHubApp } from "@lockjaw/cell";
import { Effect, Layer, Redacted, Result, Stream } from "effect";

import { githubAppLayer } from "../src/github-app.js";
import { Upstream } from "../src/upstream.js";
import { name } from "./fixtures.js";

it.effect(
  "GitHub token decoding preserves a token BOM and maps malformed or truncated UTF-8 to a mint refusal",
  () =>
    Effect.gen(function* tokenBytes() {
      const pair = yield* Effect.promise(() =>
        crypto.subtle.generateKey(
          {
            hash: "SHA-256",
            modulusLength: 2048,
            name: "RSASSA-PKCS1-v1_5",
            publicExponent: new Uint8Array([1, 0, 1]),
          },
          false,
          ["sign", "verify"]
        )
      );

      const encoder = new TextEncoder();

      const prefix = encoder.encode(
        '{"expires_at":"2100-01-01T00:00:00Z","token":"'
      );

      const suffix = encoder.encode('"}');
      const token = "\uFEFFtest-token-canary";

      const bodies = [
        encoder.encode(
          JSON.stringify({ expires_at: "2100-01-01T00:00:00Z", token })
        ),
        new Uint8Array([...prefix, 0xff, ...suffix]),
        new Uint8Array([...prefix, 0xe2]),
      ];

      for (const [index, bytes] of bodies.entries()) {
        const upstream = Upstream.testLayer({
          send: () =>
            Effect.succeed({
              body: Stream.fromIterable(
                Array.from(bytes, (byte) => new Uint8Array([byte]))
              ),
              headers: [],
              status: 201,
              statusText: "Created",
              url: "https://api.github.com/fixture",
            }),
        });

        const result = yield* GitHubApp.use((app) =>
          app.mint({
            appId: "123",
            credential: name,
            installationId: 1,
            key: pair.privateKey,
          })
        ).pipe(
          Effect.provide(githubAppLayer.pipe(Layer.provide(upstream))),
          Effect.result
        );

        if (index === 0) {
          expect(result._tag).toBe("Success");

          if (Result.isSuccess(result)) {
            expect(Redacted.value(result.success.value)).toBe(token);
          }
        } else {
          expect(result._tag).toBe("Failure");

          if (Result.isFailure(result)) {
            expect(result.failure._tag).toBe("GitHubMintFailed");
            expect(JSON.stringify(result.failure)).not.toContain(
              "test-token-canary"
            );
          }
        }
      }
    })
);
