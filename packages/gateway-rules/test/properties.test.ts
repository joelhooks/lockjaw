import { it as test, expect } from "@effect/vitest";
import { CredentialName } from "@lockjaw/domain";
import {
  Effect,
  Layer,
  Predicate,
  Redacted,
  Result,
  Schema,
  Stream,
} from "effect";

import { base64 } from "../src/fill.js";
import { EchoRedactor, Fill, Placement } from "../src/index.js";
import {
  Value,
  GeneratedName,
  assertNoWindows,
  byteChunks,
  encodings,
  placeholder,
  policies,
  request,
} from "./fixtures.js";

const layers = Layer.mergeAll(
  Placement.testLayer(policies),
  Fill.testLayer,
  EchoRedactor.testLayer
);

const Cuts = Schema.Array(
  Schema.Int.check(Schema.isBetween({ maximum: 500, minimum: 0 }))
).check(Schema.isMaxLength(32));

test.layer(layers)((it) => {
  it.effect.prop(
    "writes values only into the declared header",
    {
      extra: Schema.String,
      method: Schema.Literals(["POST", "GET", "DELETE"]),
      path: Schema.String,
      value: Value,
    },
    ({ value, path, method, extra }) =>
      Effect.gen(function* operation() {
        const placement = yield* Placement;
        const fill = yield* Fill;

        const input = {
          ...request,
          headers: [...request.headers, { name: "x-public", value: extra }],
          method,
          url: `https://api.example.com/allowed/${encodeURIComponent(new TextDecoder().decode(new TextEncoder().encode(path)))}`,
        };

        const checked = yield* placement.check(input).pipe(Effect.result);

        if (Result.isFailure(checked)) {
          return;
        }

        const output = yield* fill.apply(input, checked.success, () =>
          Effect.succeed(Redacted.make(value))
        );

        expect(output.request.url).toBe(input.url);
        expect(output.request.method).toBe(input.method);
        expect(output.request.body).toBe(input.body);
        expect(output.request.headers[1]).toEqual(input.headers[1]);
        expect(output.request.headers[0]?.value).toBe(`Bearer ${value}`);
        expect(output.request.redirect).toBe("manual");
        expect(JSON.stringify([...output.values])).not.toContain(value);
      }),
    { arbitrary: { runs: 150 } }
  );

  it.effect.prop(
    "never fills outside approved hosts or over HTTP",
    { http: Schema.Boolean, name: GeneratedName },
    ({ name, http }) =>
      Effect.gen(function* operation() {
        const placement = yield* Placement;

        const url = http
          ? "http://api.example.com/allowed/path"
          : `https://${encodeURIComponent(name)}.invalid/allowed/path`;

        const result = yield* placement
          .check({ ...request, url })
          .pipe(Effect.result);

        expect(result._tag).toBe("Failure");
      }),
    { arbitrary: { runs: 150 } }
  );

  it.effect.prop(
    "refuses every outside placeholder before resolution",
    {
      encoding: Schema.Int.check(Schema.isBetween({ maximum: 5, minimum: 0 })),
      location: Schema.Literals(["host", "userinfo", "path", "query", "body"]),
      name: GeneratedName,
    },
    ({ name, encoding, location }) =>
      Effect.gen(function* operation() {
        const placement = yield* Placement;
        const token = `{{secret:${CredentialName.make(name)}}}`;

        const forms = [
          token,
          encodeURIComponent(token),
          Array.from(
            new TextEncoder().encode(token),
            (byte) => `%${byte.toString(16)}`
          ).join(""),
          base64(token),
          encodeURIComponent(encodeURIComponent(token)),
          encodeURIComponent(base64(token)),
        ];

        const encoded = forms[encoding] ?? token;

        const urls = {
          body: request.url,
          host: `https://${encoded}.example.com/allowed/`,
          path: `https://api.example.com/allowed/${encoded}`,
          query: `https://api.example.com/allowed/?q=${encoded}`,
          userinfo: `https://${encoded}@api.example.com/allowed/`,
        };

        const input = {
          ...request,
          body: location === "body" ? `prefix:${encoded}:suffix` : "public",
          url: urls[location],
        };

        const result = yield* placement.check(input).pipe(Effect.result);
        expect(result._tag).toBe("Failure");

        if (Result.isFailure(result)) {
          expect([
            "PlaceholderOutsideHeader",
            "EncodedPlaceholderRefused",
          ]).toContain(result.failure._tag);
        }
      }),
    { arbitrary: { runs: 250 } }
  );

  it.effect.prop(
    "redacts every encoding at arbitrary byte chunk boundaries",
    { cuts: Cuts, value: Value },
    ({ value, cuts }) =>
      Effect.gen(function* operation() {
        const placement = yield* Placement;
        const fill = yield* Fill;
        const echo = yield* EchoRedactor;
        const fills = yield* placement.check(request);

        const output = yield* fill.apply(request, fills, () =>
          Effect.succeed(Redacted.make(value))
        );

        for (const encoded of encodings(value)) {
          const bytes = new TextEncoder().encode(
            `prefix|${encoded}|${encoded}|suffix`
          );

          const chunks = yield* echo
            .stream(
              output.redaction,
              Stream.fromIterable(byteChunks(bytes, cuts))
            )
            .pipe(Stream.runCollect);

          const actual = Uint8Array.from(chunks.flatMap((chunk) => [...chunk]));
          const text = new TextDecoder().decode(actual);

          assertNoWindows(actual, value, expect);

          if (encoded.length >= 8) {
            expect(text).not.toContain(encoded);
          }

          expect(text).toContain("prefix|");
          expect(text).toContain("|suffix");
        }
      }),
    { arbitrary: { runs: 200 }, timeout: 20_000 }
  );

  it.effect("opt-out is a header, not text in a body or query", () =>
    Effect.gen(function* operation() {
      const placement = yield* Placement;

      const refused = yield* placement
        .check({
          ...request,
          body: placeholder,
          headers: [
            ...request.headers,
            { name: "x-sc-resolution", value: "off" },
          ],
        })
        .pipe(Effect.flip);

      expect(refused._tag).toBe("NothingToFill");

      if (Predicate.isTagged(refused, "NothingToFill")) {
        expect(refused.what).toContain("x-sc-resolution: off");
        expect(refused.next).toContain("remove x-sc-resolution: off");
      }

      for (const input of [
        { ...request, body: `x-sc-resolution: off ${placeholder}` },
        {
          ...request,
          body: placeholder,
          url: `${request.url}?x-sc-resolution=off`,
        },
      ]) {
        expect((yield* placement.check(input).pipe(Effect.result))._tag).toBe(
          "Failure"
        );
      }

      expect(
        (yield* placement
          .check({
            ...request,
            headers: [{ name: "x-sc-resolution", value: "off" }],
            url: `${request.url}?q=${placeholder}`,
          })
          .pipe(Effect.result))._tag
      ).toBe("Failure");
    })
  );
});
