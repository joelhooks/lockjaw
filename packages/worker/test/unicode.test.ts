// oxlint-disable typescript/promise-function-async -- Response capture is a native Promise boundary.
import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { name, setup } from "./fixtures.js";

it.effect(
  "set and rotate reject lone surrogates with a secret-free three-part 400 before writing",
  () =>
    Effect.gen(function* unicode() {
      const fixture = yield* setup;

      for (const path of ["set", "rotate"]) {
        const response = yield* fixture.call(
          `/v1/${path}`,
          JSON.stringify({ name, value: "private-\uD800-suffix" }),
          yield* fixture.token(`sh.secretcell.${path}`)
        );

        expect(response.status).toBe(400);
        const text = yield* Effect.promise(() => response.text());
        expect(text).toContain('"rule":"value"');
        expect(text).toContain("The value is not well-formed Unicode text");
        expect(text).toContain("lone UTF-16 surrogate");
        expect(text).toContain("pipe the exact value");
        expect(text).not.toContain("private-");
        expect(text).not.toContain("suffix");
        expect(fixture.registry.list()).toEqual([]);
      }

      for (const body of [
        "{",
        JSON.stringify({ name, value: 42 }),
        JSON.stringify({ name, value: "" }),
      ]) {
        const response = yield* fixture.call(
          "/v1/set",
          body,
          yield* fixture.token("sh.secretcell.set")
        );

        expect(response.status).toBe(400);
        expect(yield* Effect.promise(() => response.text())).toContain(
          '"rule":"request"'
        );
      }
    }).pipe(Effect.scoped)
);
