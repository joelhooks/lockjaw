// oxlint-disable typescript/promise-function-async -- Response text capture is a native Promise boundary.
import { expect, it } from "@effect/vitest";
import { Arbitrary, Effect, Logger, Schema, Stream } from "effect";

import { Upstream } from "../src/upstream.js";
import { canary, grants, name, setupWith, target } from "./fixtures.js";

it.effect.prop(
  "redaction: generated credential canaries never enter fetch, set, describe refusals or captured logs",
  {
    value: Arbitrary.schema(Schema.String.check(Schema.isMaxLength(64))).pipe(
      Arbitrary.filter((value) => value.isWellFormed())
    ),
  },
  ({ value }) =>
    Effect.gen(function* redaction() {
      const secret = `${canary}:${value}`;
      const lines: string[] = [];

      const logger = Logger.make(({ cause, message }) => {
        lines.push(`${JSON.stringify(message)} ${String(cause)}`);
      });

      const upstream = Upstream.testLayer({
        send: () =>
          Effect.succeed({
            body: Stream.fromIterable([new TextEncoder().encode(secret)]),
            headers: [{ name: "x-echo", value: secret }],
            status: 502,
            statusText: "Fake upstream failure",
            url: target.url,
          }),
      });

      const denied = { did: "did:web:denied.invalid", name: "denied/agent" };

      const fixture = yield* setupWith({
        identities: [denied],
        logger,
        upstream,
      });

      const texts: string[] = [];

      const capture = (...args: Parameters<typeof fixture.call>) =>
        fixture.call(...args).pipe(
          Effect.flatMap((response) =>
            Effect.promise(() => response.text()).pipe(
              Effect.map((text) => {
                texts.push(text, JSON.stringify([...response.headers]));

                return response.status;
              })
            )
          )
        );

      expect(
        yield* capture(
          "/v1/set",
          JSON.stringify({ name, value: secret }),
          yield* fixture.token("sh.secretcell.set")
        )
      ).toBe(200);
      yield* Effect.promise(() => fixture.credential.approve(grants));
      const descriptionToken = yield* fixture.token("sh.secretcell.describe");
      expect(
        yield* capture(
          `/v1/describe?name=${name}`,
          undefined,
          descriptionToken,
          "GET"
        )
      ).toBe(200);

      const fetchStatus = yield* capture(
        "/v1/fetch",
        JSON.stringify(target),
        yield* fixture.token()
      );

      expect([502, 503]).toContain(fetchStatus);

      for (const [path, body, method, scope] of [
        [
          "/v1/set",
          JSON.stringify({ name, value: secret }),
          "POST",
          "sh.secretcell.set",
        ],
        [
          `/v1/describe?name=${name}`,
          undefined,
          "GET",
          "sh.secretcell.describe",
        ],
        ["/v1/fetch", JSON.stringify(target), "POST", "sh.secretcell.fetch"],
      ] as const) {
        const status = yield* capture(
          path,
          body,
          scope === "sh.secretcell.describe"
            ? descriptionToken
            : yield* fixture.tokenAs(denied.did, scope),
          method
        );

        expect(status).toBeGreaterThanOrEqual(400);
      }

      expect(texts.length).toBe(12);

      const audit = [
        ...(fixture.contexts
          .get("registry")
          ?.storage.sql.exec("SELECT json FROM attempts") ?? []),
      ].map((row) => JSON.stringify(row));

      expect(audit.length).toBeGreaterThan(0);

      for (const output of [...texts, ...lines, ...audit]) {
        expect(output).not.toContain(secret);
        expect(output).not.toContain(canary);
      }
    }).pipe(Effect.scoped),
  { arbitrary: { runs: 12 }, timeout: 15_000 }
);

it.effect.prop(
  "Unicode boundary: every ill-formed value is a secret-free 400 at set and rotate with no credential row written",
  {
    prefix: Schema.String,
    suffix: Schema.String,
    surrogate: Schema.Int.check(
      Schema.isBetween({ maximum: 0xdf_ff, minimum: 0xd8_00 })
    ),
  },
  ({ prefix, suffix, surrogate }) =>
    Effect.gen(function* malformed() {
      const value = `${canary}${prefix.toWellFormed()}!${String.fromCodePoint(surrogate)}!${suffix.toWellFormed()}`;
      expect(value.isWellFormed()).toBe(false);
      const lines: string[] = [];

      const fixture = yield* setupWith({
        logger: Logger.make(({ cause, message }) => {
          lines.push(`${JSON.stringify(message)} ${String(cause)}`);
        }),
      });

      for (const path of ["set", "rotate"]) {
        const response = yield* fixture.call(
          `/v1/${path}`,
          JSON.stringify({ name, value }),
          yield* fixture.token(`sh.secretcell.${path}`)
        );

        expect(response.status).toBe(400);
        const text = yield* Effect.promise(() => response.text());
        expect(text).toContain('"rule":"value"');
        expect(text).toContain("The value is not well-formed Unicode text");
        expect(text).toContain("lone UTF-16 surrogate");
        expect(text).toContain("pipe the exact value");
        expect([text, ...lines].join("\n")).not.toContain(canary);
        expect(fixture.registry.list()).toEqual([]);

        const description = yield* Effect.promise(() =>
          fixture.credential.describe()
        );

        expect(description.ok).toBe(true);

        if (description.ok) {
          expect(description.value.meta).toBeUndefined();
        }

        const context = fixture.contexts.get(name);
        expect(context).toBeDefined();
        expect([
          ...(context?.storage.sql.exec("SELECT json FROM value") ?? []),
        ]).toEqual([]);
      }
    }).pipe(Effect.scoped),
  { arbitrary: { runs: 20 }, timeout: 15_000 }
);
