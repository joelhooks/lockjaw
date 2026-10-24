import { expect, it } from "@effect/vitest";
import {
  GrantId,
  GrantRecord,
  Host,
  NamePattern,
  Scope,
} from "@lockjaw/domain";
import { Effect, Result, Schema } from "effect";

import { Placement, admitDelegated } from "../src/index.js";
import { policies, request } from "./fixtures.js";

const caller = {
  did: "did:test:caller",
  issuer: "test-host",
  name: "test/agent",
  sid: "property-session",
};

const safe = (value: string) =>
  Array.from(new TextEncoder().encode(value), (byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");

const options = { arbitrary: { runs: 40 } };

it.effect.prop(
  "zero fill: approved-host requests without placeholders always refuse with NothingToFill",
  {
    body: Schema.String,
    headers: Schema.Array(Schema.String).check(Schema.isMaxLength(5)),
    path: Schema.String,
  },
  ({ body, headers, path }) =>
    Effect.gen(function* empty() {
      const placement = yield* Placement;

      const result = yield* placement
        .check({
          ...request,
          body: safe(body),
          headers: headers.map((value, index) => ({
            name: `x-public-${index}`,
            value: safe(value),
          })),
          url: `${request.url}/${safe(path)}`,
        })
        .pipe(Effect.result);

      expect(Result.isFailure(result)).toBe(true);

      if (Result.isFailure(result)) {
        expect(result.failure._tag).toBe("NothingToFill");
      }
    }).pipe(Effect.provide(Placement.testLayer(policies))),
  options
);

const selections = <A extends string>(values: readonly A[]) =>
  Schema.Array(Schema.Literals(values)).check(Schema.isMaxLength(4));

const Input = Schema.Struct({
  credentials: selections([
    "acme/*",
    "acme/a",
    "acme/sub/*",
    "acme/sub/x",
    "beta/b",
  ]).check(Schema.isMinLength(1)),
  exp: Schema.Int.check(Schema.isBetween({ maximum: 2000, minimum: 1100 })),
  grantees: selections(["test/*", "test/agent", "test/child", "other/child"]),
  hosts: selections([
    "*.example.com",
    "api.example.com",
    "x.example.com",
    "api.example.org",
  ]),
  ops: selections(["use", "describe", "set", "grant"]).check(
    Schema.isMinLength(1)
  ),
  routes: Schema.optionalKey(
    Schema.Array(Schema.Literals([0, 1, 2])).check(Schema.isMaxLength(3))
  ),
});

const routes = [
  { method: "GET", pathPrefix: "/" },
  { method: "GET", pathPrefix: "/v1/" },
  { method: "POST", pathPrefix: "/v1/" },
] as const;

const scopeOf = (input: typeof Input.Type): Scope => {
  const base = Scope.make({
    credentials: input.credentials.map((value) => NamePattern.make(value)),
    exp: input.exp,
    grantees: input.grantees.map((value) => NamePattern.make(value)),
    hosts: input.hosts.map((value) => Host.make(value)),
    ops: input.ops,
  });

  return input.routes === undefined
    ? base
    : Scope.make({
        ...base,
        routes: input.routes.map((index) => routes[index]),
      });
};

const record = (scope: Scope, index: number, desk: string): GrantRecord => {
  const grant = {
    createdAt: 1000,
    grantee: { desk },
    grantor: "approver",
    id: GrantId.make(`g_${index.toString(16).padStart(32, "0")}`),
    scope,
  };

  return GrantRecord.make({
    grant:
      index === 1
        ? grant
        : {
            ...grant,
            parent: GrantId.make(
              `g_${(index - 1).toString(16).padStart(32, "0")}`
            ),
          },
    revokedAt: null,
  });
};

const coversName = (outer: string, inner: string) =>
  outer === inner ||
  (outer.endsWith("/*") && inner.startsWith(outer.slice(0, -1)));

const subset = (child: Scope, parent: Scope) => {
  expect(
    child.credentials.every((value) =>
      parent.credentials.some((outer) => coversName(outer, value))
    )
  ).toBe(true);
  expect(
    child.grantees.every((value) =>
      parent.grantees.some((outer) => coversName(outer, value))
    )
  ).toBe(true);
  expect(
    child.hosts.every((value) =>
      parent.hosts.some(
        (outer) =>
          outer === value ||
          (outer.startsWith("*.") &&
            !value.startsWith("*.") &&
            value.endsWith(outer.slice(1)))
      )
    )
  ).toBe(true);
  expect(child.ops.every((value) => parent.ops.includes(value))).toBe(true);
  expect(child.exp).toBeLessThanOrEqual(parent.exp);

  if (parent.routes !== undefined) {
    expect(child.routes).toBeDefined();
    expect(
      child.routes?.every(
        (route) =>
          parent.routes?.some(
            (outer) =>
              outer.method === route.method &&
              route.pathPrefix.startsWith(outer.pathPrefix)
          ) === true
      )
    ).toBe(true);
  }
};

it.prop(
  "grant narrowing: every admitted generated child is a subset of its parent in every scope dimension",
  { child: Input, parent: Input },
  ({ child, parent }) => {
    const outer = scopeOf(parent);
    const inner = scopeOf(child);

    const delegator = Scope.make({
      ...outer,
      grantees: [...outer.grantees, NamePattern.make("test/*")],
      ops: [...outer.ops, "grant"],
    });

    const root = record(delegator, 1, caller.name);

    for (const candidate of [inner, outer]) {
      const decision = admitDelegated(
        [root],
        caller,
        { grantee: { desk: "test/child" }, scope: candidate },
        1000
      );

      if (candidate === outer) {
        expect(decision.admitted).toBe(true);
      }

      if (decision.admitted) {
        expect(decision.parent).toBe(root.grant.id);
        subset(candidate, delegator);
      }
    }
  },
  options
);

it.prop(
  "grant depth: a child beyond depth three always refuses even with identical scopes",
  {
    depth: Schema.Int.check(Schema.isBetween({ maximum: 7, minimum: 3 })),
    input: Input,
  },
  ({ input, depth }) => {
    const scope = Scope.make({
      ...scopeOf(input),
      grantees: [NamePattern.make("test/*")],
      ops: ["grant", "use"],
    });

    const chain = Array.from({ length: depth }, (_, index) =>
      record(
        scope,
        index + 1,
        index === depth - 1 ? caller.name : "test/ancestor"
      )
    );

    const decision = admitDelegated(
      chain,
      caller,
      { grantee: { desk: "test/child" }, scope },
      1000
    );

    expect(decision.admitted).toBe(false);
  },
  options
);
