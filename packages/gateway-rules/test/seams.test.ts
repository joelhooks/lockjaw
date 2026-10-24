import { expect, it as rootTest } from "@effect/vitest";
import { Host, Policy as CredentialPolicy } from "@lockjaw/domain";
import { CredentialExpired } from "@lockjaw/domain/errors";
import { Effect, Layer, Predicate, Redacted, Stream } from "effect";

import { base64 } from "../src/fill.js";
import {
  EchoRedactor,
  Fill,
  Placement,
  Policy,
  hostMatches,
} from "../src/index.js";
import {
  credential,
  encodings,
  placeholder,
  policies,
  policy,
  request,
  second,
} from "./fixtures.js";

rootTest.layer(
  Layer.mergeAll(
    Placement.layer(policies),
    Fill.layer,
    EchoRedactor.layer,
    Policy.layer
  )
)((it) => {
  it.effect(
    "caller, issuer, routes, host and injection each deny independently",
    () =>
      Effect.gen(function* operation() {
        const auth = yield* Policy;

        const caller = {
          did: "did:test",
          issuer: "test-host",
          name: "secret-cell/test",
          sid: "test-session",
        };

        const op = {
          credential,
          host: "api.example.com",
          method: "POST",
          path: "/allowed/test",
        };

        yield* auth.authorize(caller, policy, op);

        const denials = [
          auth.authorize({ ...caller, name: "other/test" }, policy, op),
          auth.authorize({ ...caller, issuer: "other" }, policy, op),
          auth.authorize(caller, policy, { ...op, method: "DELETE" }),
          auth.authorize(caller, policy, { ...op, path: "/elsewhere" }),
          auth.authorize(caller, policy, { ...op, host: "evil.example.com" }),
        ];

        for (const denial of denials) {
          expect((yield* denial.pipe(Effect.result))._tag).toBe("Failure");
        }

        const placement = yield* Placement;

        for (const headers of [
          [{ name: "x-wrong", value: `Bearer ${placeholder}` }],
          [{ name: "Authorization", value: `Basic ${placeholder}` }],
        ]) {
          expect(
            (yield* placement
              .check({ ...request, headers })
              .pipe(Effect.result))._tag
          ).toBe("Failure");
        }
      })
  );

  it.effect(
    "redacts headers, URL, status, errors and equal-length range bytes",
    () =>
      Effect.gen(function* operation() {
        const fill = yield* Fill;
        const placement = yield* Placement;
        const echo = yield* EchoRedactor;
        const canary = "CANARY-private-8c7bc48be272-internal";

        const filled = yield* fill.apply(
          request,
          yield* placement.check(request),
          () => Effect.succeed(Redacted.make(canary))
        );

        const body = new TextEncoder().encode(`before:${canary}:after`);

        const response = echo.response(filled.redaction, {
          body: Stream.fromIterable(
            [...body].map((byte) => new Uint8Array([byte]))
          ),
          headers: [
            { name: "Content-Length", value: String(body.length) },
            { name: "x-echo", value: canary },
            { name: `x-${canary}`, value: "header-name" },
          ],
          status: 206,
          statusText: canary,
          url: `https://example.com/${canary}`,
        });

        expect(
          response.headers.some(
            (header) => header.name.toLowerCase() === "content-length"
          )
        ).toBe(false);
        expect(
          JSON.stringify({
            headers: response.headers,
            statusText: response.statusText,
            url: response.url,
          })
        ).not.toContain(canary);
        const chunks = yield* response.body.pipe(Stream.runCollect);
        const bytes = Uint8Array.from(chunks.flatMap((chunk) => [...chunk]));
        expect(bytes.length).toBe(body.length);
        expect(new TextDecoder().decode(bytes)).toBe(
          `before:${"\0".repeat(canary.length)}:after`
        );

        for (const encoded of encodings(canary)) {
          const error = echo.error(
            filled.redaction,
            new Error(`provider echoed ${encoded}`)
          );

          expect(error.message).not.toContain(encoded);
          expect(String(error)).not.toContain(canary);
          expect(JSON.stringify(error)).not.toContain(canary);
        }

        expect(JSON.stringify(filled.redaction)).not.toContain(canary);

        const failure = yield* fill
          .apply(request, yield* placement.check(request), () =>
            Effect.fail(new CredentialExpired({ credential, rule: "expired" }))
          )
          .pipe(Effect.flip);

        expect(JSON.stringify(failure)).not.toContain(canary);
      })
  );

  it.effect(
    "stream state is isolated across repeated and concurrent subscriptions",
    () =>
      Effect.gen(function* operation() {
        const fill = yield* Fill;
        const placement = yield* Placement;
        const echo = yield* EchoRedactor;
        const value = "overlapping-ababababababa";

        const filled = yield* fill.apply(
          request,
          yield* placement.check(request),
          () => Effect.succeed(Redacted.make(value))
        );

        const source = echo.stream(
          filled.redaction,
          Stream.fromIterable(
            [...new TextEncoder().encode(`${value}${value}`)].map(
              (byte) => new Uint8Array([byte])
            )
          )
        );

        const result = yield* Effect.all(
          [Stream.runCollect(source), Stream.runCollect(source)],
          { concurrency: 2 }
        );

        expect(
          result.map((chunks) => chunks.flatMap((chunk) => [...chunk]))
        ).toEqual([
          Array.from({ length: value.length * 2 }, () => 0),
          Array.from({ length: value.length * 2 }, () => 0),
        ]);
      })
  );
});

rootTest(
  "wildcards match exactly one level, never the base or an attacker suffix",
  () => {
    const wildcard = Host.make("*.example.com");
    expect(hostMatches("api.example.com", wildcard)).toBe(true);

    for (const host of [
      "example.com",
      "a.b.example.com",
      "example.com.evil",
      "badexample.com",
      ".example.com",
    ]) {
      expect(hostMatches(host, wildcard)).toBe(false);
    }
  }
);

rootTest.effect(
  "Basic fills check both credentials and redact raw parts and base64",
  () =>
    Effect.gen(function* operation() {
      const basicPolicy = CredentialPolicy.make({
        ...policy,
        inject: { header: "Authorization", template: "Basic {value}" },
      });

      const layer = Layer.mergeAll(
        Placement.testLayer(
          new Map([
            [credential, basicPolicy],
            [second, basicPolicy],
          ])
        ),
        Fill.testLayer,
        EchoRedactor.testLayer
      );

      yield* Effect.gen(function* scenario() {
        const placement = yield* Placement;
        const fill = yield* Fill;
        const echo = yield* EchoRedactor;
        const username = "user-123456789";
        const password = ["synthetic", "fixture", "password"].join("-");

        const input = {
          ...request,
          headers: [
            {
              name: "Authorization",
              value: `Basic {{secret-basic:username=${credential},password=${second}}}`,
            },
          ],
        };

        const filled = yield* fill.apply(
          input,
          yield* placement.check(input),
          (name) =>
            Effect.succeed(
              Redacted.make(name === credential ? username : password)
            )
        );

        const encoded = base64(`${username}:${password}`);
        expect(filled.request.headers[0]?.value).toBe(`Basic ${encoded}`);
        expect(filled.values.size).toBe(3);

        for (const value of [username, password, encoded, `Basic ${encoded}`]) {
          expect(echo.text(filled.redaction, value)).toBe("");
        }
      }).pipe(Effect.provide(layer));
    })
);

rootTest.effect(
  "no placeholder is refused as NothingToFill with what, why and next",
  () =>
    Effect.gen(function* operation() {
      const placement = yield* Placement;

      for (const input of [
        { ...request, headers: [] },
        {
          ...request,
          headers: [{ name: "Authorization", value: "Bearer public" }],
        },
        { ...request, headers: [], url: "https://192.0.2.10/" },
      ]) {
        const error = yield* placement.check(input).pipe(Effect.flip);

        expect(error._tag).toBe("NothingToFill");

        if (Predicate.isTagged(error, "NothingToFill")) {
          expect(error.rule).toBe("nothing-to-fill");
          expect(error.what).toBe(
            "The request carries no credential placeholder"
          );
          expect(error.why).toContain("forwards only requests it fills");
          expect(error.next).toContain("{{secret:<name>}}");
        }
      }
    }).pipe(Effect.provide(Placement.testLayer(policies)))
);

rootTest.effect("refuses invalid header values without echoing them", () =>
  Effect.gen(function* operation() {
    const layer = Layer.mergeAll(Placement.testLayer(policies), Fill.testLayer);
    yield* Effect.gen(function* scenario() {
      const placement = yield* Placement;
      const fill = yield* Fill;

      for (const value of [
        "",
        "private-canary\r\nInjected: yes",
        "private-canary\0",
      ]) {
        const result = yield* fill
          .apply(request, yield* placement.check(request), () =>
            Effect.succeed(Redacted.make(value))
          )
          .pipe(Effect.flip);

        expect(JSON.stringify(result)).not.toContain("private-canary");
      }
    }).pipe(Effect.provide(layer));
  })
);

rootTest.effect("normalizes hosts and refuses route escape encodings", () =>
  Effect.gen(function* operation() {
    const layer = Placement.testLayer(policies);
    yield* Effect.gen(function* scenario() {
      const placement = yield* Placement;
      expect(
        (yield* placement.check({
          ...request,
          url: "https://API.EXAMPLE.COM./allowed/path",
        })).length
      ).toBe(1);

      for (const url of [
        "https://api.example.com/allowed/../outside",
        "https://api.example.com/allowed/%2e%2e/outside",
        "https://api.example.com/allowed/%2f..%2foutside",
      ]) {
        expect(
          (yield* placement.check({ ...request, url }).pipe(Effect.result))._tag
        ).toBe("Failure");
      }
    }).pipe(Effect.provide(layer));
  })
);
