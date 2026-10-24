// oxlint-disable typescript/promise-function-async -- Web Crypto is a native Promise boundary.
import { GitHubApp, GitHubMintFailed } from "@lockjaw/cell";
import { Clock, Effect, Layer, Redacted, Schema, Stream } from "effect";

import { base64url } from "./caller-auth.js";
import { Upstream } from "./upstream.js";

const failed = () => new GitHubMintFailed({ reason: "retryable" });

const TokenResponse = Schema.Struct({
  expires_at: Schema.String,
  token: Schema.NonEmptyString,
});

type JwtPart =
  | { readonly alg: "RS256"; readonly typ: "JWT" }
  | { readonly exp: number; readonly iat: number; readonly iss: string };

const encode = (value: JwtPart) =>
  base64url(new TextEncoder().encode(JSON.stringify(value)));

export const githubAppLayer = Layer.effect(
  GitHubApp,
  Effect.gen(function* githubAppAdapter() {
    const upstream = yield* Upstream;

    return GitHubApp.of({
      mint: Effect.fn("GitHubApp.mint")(function* mint({
        key,
        appId,
        installationId,
      }) {
        const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);
        const unsigned = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ exp: now + 540, iat: now - 60, iss: appId })}`;

        const signature = yield* Effect.tryPromise({
          catch: failed,
          try: () =>
            crypto.subtle.sign(
              "RSASSA-PKCS1-v1_5",
              key,
              new TextEncoder().encode(unsigned)
            ),
        });

        const jwt = `${unsigned}.${base64url(new Uint8Array(signature))}`;

        const send = () =>
          upstream
            .send({
              headers: [
                { name: "authorization", value: `Bearer ${jwt}` },
                { name: "accept", value: "application/vnd.github+json" },
                { name: "x-github-api-version", value: "2022-11-28" },
                { name: "user-agent", value: "secret-cell" },
              ],
              method: "POST",
              redirect: "manual",
              url: `https://api.github.com/app/installations/${installationId}/access_tokens`,
            })
            .pipe(Effect.mapError(failed));

        let response = yield* send();

        if (response.status >= 500 && response.status <= 599) {
          response = yield* send();
        }

        if (response.status === 401 || response.status === 403) {
          return yield* new GitHubMintFailed({ reason: "auth" });
        }

        if (response.status !== 201) {
          return yield* failed();
        }

        const decoder = new TextDecoder("utf-8", {
          fatal: true,
          ignoreBOM: true,
        });

        const body = yield* Stream.runFoldEffect(
          response.body,
          () => ({ bytes: 0, text: "" }),
          (state, chunk) => {
            const bytes = state.bytes + chunk.length;

            return bytes > 16_384
              ? Effect.fail(failed())
              : Effect.try({
                  catch: failed,
                  try: () => ({
                    bytes,
                    text: state.text + decoder.decode(chunk, { stream: true }),
                  }),
                });
          }
        ).pipe(Effect.mapError(failed));

        const text = yield* Effect.try({
          catch: failed,
          try: () => body.text + decoder.decode(),
        });

        const result = yield* Schema.decodeUnknownEffect(
          Schema.fromJsonString(TokenResponse)
        )(text).pipe(Effect.mapError(failed));

        const expiresAt = Date.parse(result.expires_at);

        if (
          !Number.isFinite(expiresAt) ||
          expiresAt <= (yield* Clock.currentTimeMillis) + 300_000 ||
          /[\r\n\0]/u.test(result.token)
        ) {
          return yield* failed();
        }

        return { expiresAt, value: Redacted.make(result.token) };
      }),
    });
  })
);
