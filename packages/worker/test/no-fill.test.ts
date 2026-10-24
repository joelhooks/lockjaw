// oxlint-disable typescript/promise-function-async -- Native response readers are Promise boundaries.
import { expect, it } from "@effect/vitest";
import { Effect, Schema } from "effect";

import { canary, grants, name, setup } from "./fixtures.js";

const Refusal = Schema.Struct({
  error: Schema.Struct({
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.String,
    what: Schema.String,
    why: Schema.String,
  }),
});

const refusal = (response: Response) =>
  Effect.promise(() => response.text()).pipe(
    Effect.flatMap(Schema.decodeUnknownEffect(Schema.fromJsonString(Refusal)))
  );

const seeded = Effect.gen(function* seededFixture() {
  const fixture = yield* setup;
  yield* fixture.call(
    "/v1/set",
    JSON.stringify({ name, value: canary }),
    yield* fixture.token("sh.secretcell.set")
  );
  yield* fixture.call(
    "/v1/approve",
    JSON.stringify({ name, policy: grants }),
    yield* fixture.token("sh.secretcell.approve")
  );

  return fixture;
});

const cases = [
  {
    label: "/v1/fetch with no placeholder to an IP-literal HTTPS host",
    off: false,
    request: (fixture: Effect.Success<typeof setup>) =>
      Effect.gen(function* lanHost() {
        return yield* fixture.call(
          "/v1/fetch",
          JSON.stringify({
            headers: [{ name: "accept", value: "application/json" }],
            method: "GET",
            url: "https://192.0.2.10/",
          }),
          yield* fixture.token()
        );
      }),
  },
  {
    label: "/v1/fetch with x-sc-resolution: off and a placeholder",
    off: true,
    request: (fixture: Effect.Success<typeof setup>) =>
      Effect.gen(function* resolutionOff() {
        return yield* fixture.call(
          "/v1/fetch",
          JSON.stringify({
            headers: [
              { name: "authorization", value: "Bearer {{secret:canary/key}}" },
              { name: "x-sc-resolution", value: "off" },
            ],
            method: "GET",
            url: "https://api.example.com/resource",
          }),
          yield* fixture.token()
        );
      }),
  },
  {
    label: "the base-URL route with no placeholder",
    off: false,
    request: (fixture: Effect.Success<typeof setup>) =>
      Effect.gen(function* baseUrl() {
        return yield* fixture.call(
          "/v1/u/api.example.com/resource",
          undefined,
          yield* fixture.token(),
          "GET",
          { accept: "application/json", authorization: "Bearer public" }
        );
      }),
  },
];

it.live.each(cases)(
  "$label is refused as NothingToFill with zero upstream calls",
  ({ off, request }) =>
    Effect.gen(function* test() {
      const fixture = yield* seeded;
      const response = yield* request(fixture);
      const body = yield* refusal(response);

      expect(response.status).toBe(403);
      expect(body.error.rule).toBe("nothing-to-fill");
      expect(body.error.what).toBe(
        off
          ? "The request sets x-sc-resolution: off, so it carries no credential placeholder to fill"
          : "The request carries no credential placeholder"
      );
      expect(body.error.why).toBe(
        "Lockjaw forwards only requests it fills, to hosts declared for those credentials."
      );
      expect(body.error.next).toContain("Send this request directly");
      expect(body.error.next).toContain("{{secret:<name>}}");
      expect(fixture.received).toHaveLength(0);
      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);
