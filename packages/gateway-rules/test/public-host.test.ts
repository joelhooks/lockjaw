import { expect, it } from "@effect/vitest";
import { Host, Policy } from "@lockjaw/domain";
import { Effect, Result, Schema } from "effect";

import { makeCheck } from "../src/placement.js";
import { checkTarget } from "../src/policy.js";
import { credential, policies, policy, request } from "./fixtures.js";

const refused = [
  "127.0.0.1",
  [10, 0, 0, 5].join("."),
  [100, 64, 1, 1].join("."),
  "127.1",
  "0x7f.1",
  "2130706433",
  "[::1]",
  ...[
    "localhost",
    "localdomain",
    "local",
    "internal",
    "lan",
    "home.arpa",
    "intranet",
    "corp",
    "private",
    "test",
    "invalid",
    "example",
    "onion",
    "alt",
    "ts.net",
  ].flatMap((suffix) => [suffix, `example.${suffix}`]),
];

const expectPublicRefusal = (
  result: Result.Result<
    unknown,
    { readonly _tag: string; readonly rule: string }
  >
) => {
  expect(Result.isFailure(result)).toBe(true);

  if (Result.isFailure(result)) {
    expect(result.failure._tag).toBe("HostNotAllowed");
    expect(result.failure.rule).toBe("host-not-public");
  }
};

it.effect(
  "public-host target table refuses internal hosts before policy matching or port approval",
  () =>
    Effect.gen(function* table() {
      for (const host of refused) {
        for (const form of [
          host,
          host.toUpperCase(),
          ...(host.includes("[") ? [] : [`${host}.`]),
        ]) {
          expectPublicRefusal(
            yield* checkTarget(policy, {
              credential,
              host: form,
              method: "POST",
              path: "/allowed/path",
            }).pipe(Effect.result)
          );
          expectPublicRefusal(
            yield* makeCheck(policies)({
              ...request,
              url: `https://${form}:8443/allowed/path`,
            }).pipe(Effect.result)
          );
        }
      }
    })
);

it.effect(
  "public-host target table permits approved public exact and wildcard hosts",
  () =>
    Effect.gen(function* publicTargets() {
      for (const allowed of ["api.github.com", "*.github.com"]) {
        const publicPolicy = Policy.make({
          ...policy,
          hosts: [Host.make(allowed)],
        });

        const result = yield* checkTarget(publicPolicy, {
          credential,
          host: "api.github.com",
          method: "POST",
          path: "/allowed/path",
        }).pipe(Effect.result);

        expect(Result.isSuccess(result), allowed).toBe(true);
      }

      for (const host of [
        "api.example.com",
        "API.EXAMPLE.COM",
        "api.example.com.",
      ]) {
        const result = yield* makeCheck(policies)({
          ...request,
          url: `https://${host}/allowed/path`,
        }).pipe(Effect.result);

        expect(Result.isSuccess(result), host).toBe(true);
      }
    })
);

it.effect.prop(
  "contest: every numeric last label is refused at target check",
  {
    digits: Schema.Array(
      Schema.Int.check(Schema.isBetween({ maximum: 9, minimum: 0 }))
    ).check(Schema.isMinLength(1), Schema.isMaxLength(63)),
    prefix: Schema.String,
  },
  ({ prefix, digits }) =>
    Effect.gen(function* numericLabel() {
      const host = `${prefix}.${digits.join("")}`;
      expectPublicRefusal(
        yield* checkTarget(policy, {
          credential,
          host,
          method: "POST",
          path: "/allowed/path",
        }).pipe(Effect.result)
      );
    }),
  { arbitrary: { runs: 200 } }
);

it.effect.prop(
  "contest: numeric URL hosts are refused after URL canonicalization",
  {
    address: Schema.Int.check(
      Schema.isBetween({ maximum: 4_294_967_295, minimum: 0 })
    ),
  },
  ({ address }) =>
    Effect.gen(function* numericUrl() {
      expectPublicRefusal(
        yield* makeCheck(policies)({
          ...request,
          url: `https://${address}/allowed/path`,
        }).pipe(Effect.result)
      );
    }),
  { arbitrary: { runs: 200 } }
);
