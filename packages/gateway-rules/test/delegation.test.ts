import { describe, expect, it } from "@effect/vitest";
import {
  GrantId,
  GrantRecord,
  Host,
  NamePattern,
  Scope,
} from "@lockjaw/domain";
import type { Caller, Op } from "@lockjaw/domain";
import { Effect, Schema } from "effect";

import {
  admitDelegated,
  authorizeUse,
  clipRefusal,
  effective,
  isSubScope,
  patternCovers,
  scopeAllows,
  widened,
} from "../src/index.js";
import type { Use } from "../src/index.js";

const credentialPool = [
  "acme/*",
  "acme/a",
  "acme/sub/*",
  "acme/sub/x",
  "beta/*",
  "beta/b",
] as const;

const hostPool = [
  "api.example.com",
  "*.example.com",
  "x.example.com",
  "api.example.org",
] as const;

const opPool = ["use", "describe", "set", "rotate", "revoke", "grant"] as const;

const granteePool = ["acme/*", "acme/desk", "beta/*", "beta/desk"] as const;

const routePool = [
  { method: "GET", pathPrefix: "/" },
  { method: "GET", pathPrefix: "/v1/" },
  { method: "POST", pathPrefix: "/v1/items" },
] as const;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
const Input = Schema.Struct({
  credentials: Schema.Array(Schema.Literals(credentialPool)).check(
    Schema.isMinLength(1)
  ),
  exp: Schema.Int.check(Schema.isBetween({ maximum: 2000, minimum: 1100 })),
  grantees: Schema.Array(Schema.Literals(granteePool)),
  hosts: Schema.Array(Schema.Literals(hostPool)),
  ops: Schema.Array(Schema.Literals(opPool)).check(Schema.isMinLength(1)),
  routes: Schema.optionalKey(
    Schema.Array(Schema.Literals([0, 1, 2])).check(Schema.isMinLength(1))
  ),
});

type Input = typeof Input.Type;

const scopeOf = (input: Input): Scope => {
  const base = Scope.make({
    credentials: input.credentials.map((pattern) => NamePattern.make(pattern)),
    exp: input.exp,
    grantees: input.grantees.map((pattern) => NamePattern.make(pattern)),
    hosts: input.hosts.map((host) => Host.make(host)),
    ops: [...input.ops],
  });

  return input.routes === undefined
    ? base
    : Scope.make({
        ...base,
        routes: input.routes.map((index) => routePool[index]),
      });
};

const Mask = Schema.Array(Schema.Boolean).check(Schema.isMaxLength(8));

const keep = <A>(items: readonly A[], mask: readonly boolean[]): A[] =>
  items.filter(
    (_, position) => mask[position % Math.max(mask.length, 1)] ?? true
  );

const narrow = (scope: Scope, mask: readonly boolean[], cut: number): Scope => {
  const credentials = keep(scope.credentials, mask);
  const ops = keep(scope.ops, mask.toReversed());

  const base = Scope.make({
    credentials: credentials.length > 0 ? credentials : [...scope.credentials],
    exp: Math.max(1, scope.exp - cut),
    grantees: keep(scope.grantees, mask),
    hosts: keep(scope.hosts, mask.toReversed()),
    ops: ops.length > 0 ? ops : [...scope.ops],
  });

  return scope.routes === undefined
    ? base
    : Scope.make({ ...base, routes: [...scope.routes] });
};

let sequence = 0;

const id = () => {
  sequence += 1;

  return GrantId.make(`g_${sequence.toString(16).padStart(32, "0")}`);
};

const record = (
  scope: Scope,
  desk: string,
  parent?: GrantId,
  runHandle?: string
): GrantRecord => {
  const grant = {
    createdAt: 1000,
    grantee: runHandle === undefined ? { desk } : { desk, runHandle },
    grantor: "approver",
    id: id(),
    scope,
  };

  return GrantRecord.make({
    grant: parent === undefined ? grant : { ...grant, parent },
    revokedAt: null,
  });
};

const caller = (name: string, runHandle?: string): Caller => {
  const base: Caller = {
    did: `did:web:${name.replaceAll("/", ".")}.invalid`,
    issuer: "test-host",
    name,
    sid: runHandle ?? "sid",
  };

  return runHandle === undefined
    ? base
    : {
        ...base,
        run: {
          expiresAt: 1050,
          handle: runHandle,
          scope: ["sh.secretcell.fetch", "sh.secretcell.describe"],
        },
      };
};

const UseInput = Schema.Struct({
  credential: Schema.Literals([
    "acme/a",
    "acme/sub/x",
    "acme/z",
    "beta/b",
    "zeta/q",
  ]),
  host: Schema.Literals([
    "api.example.com",
    "x.example.com",
    "y.example.com",
    "api.example.org",
    "evil.example.net",
  ]),
  method: Schema.Literals(["GET", "POST"]),
  op: Schema.Literals(opPool),
  path: Schema.Literals(["/", "/v1/items/1", "/v2/x"]),
});

const base = scopeOf({
  credentials: ["acme/*"],
  exp: 2000,
  grantees: ["acme/*"],
  hosts: ["api.example.com", "*.example.com"],
  ops: ["use", "set", "grant"],
});

describe("isSubScope table", () => {
  const rows: readonly (readonly [string, Scope, Scope, string | undefined])[] =
    [
      ["identical", base, base, undefined],
      [
        "narrower credential pattern",
        Scope.make({ ...base, credentials: [NamePattern.make("acme/sub/*")] }),
        base,
        undefined,
      ],
      [
        "exact credential inside pattern",
        Scope.make({ ...base, credentials: [NamePattern.make("acme/x")] }),
        base,
        undefined,
      ],
      [
        "pattern never covered by exact",
        base,
        Scope.make({ ...base, credentials: [NamePattern.make("acme/x")] }),
        "credentials",
      ],
      [
        "sibling prefix",
        Scope.make({ ...base, credentials: [NamePattern.make("acmeevil/*")] }),
        base,
        "credentials",
      ],
      [
        "subdomain under wildcard host",
        Scope.make({ ...base, hosts: [Host.make("x.example.com")] }),
        base,
        undefined,
      ],
      [
        "extra host",
        Scope.make({
          ...base,
          hosts: [...base.hosts, Host.make("api.example.org")],
        }),
        base,
        "hosts",
      ],
      [
        "routes added under all-routes parent",
        Scope.make({ ...base, routes: [routePool[1]] }),
        base,
        undefined,
      ],
      [
        "routes dropped under routed parent",
        base,
        Scope.make({ ...base, routes: [routePool[1]] }),
        "routes",
      ],
      [
        "wider route prefix",
        Scope.make({ ...base, routes: [routePool[0]] }),
        Scope.make({ ...base, routes: [routePool[1]] }),
        "routes",
      ],
      [
        "extra op",
        Scope.make({ ...base, ops: [...base.ops, "revoke"] }),
        base,
        "ops",
      ],
      [
        "grant op passed down only when held",
        Scope.make({ ...base, ops: ["grant"] }),
        Scope.make({ ...base, ops: ["use"] }),
        "ops",
      ],
      [
        "wider grantees",
        Scope.make({ ...base, grantees: [NamePattern.make("*")] }),
        base,
        "grantees",
      ],
      ["later exp", Scope.make({ ...base, exp: base.exp + 1 }), base, "exp"],
    ];

  for (const [label, child, parent, field] of rows) {
    it(label, () => {
      expect(widened(child, parent)).toBe(field);
      expect(isSubScope(child, parent)).toBe(field === undefined);
    });
  }

  it("pattern coverage", () => {
    expect(patternCovers("acme/*", "acme/x")).toBe(true);
    expect(patternCovers("acme/*", "acme/sub/*")).toBe(true);
    expect(patternCovers("acme/sub/*", "acme/*")).toBe(false);
    expect(patternCovers("acme/x", "acme/*")).toBe(false);
    expect(patternCovers("*", "anything/*")).toBe(true);
  });
});

it.effect.prop(
  "isSubScope is reflexive",
  { scope: Input },
  ({ scope }) =>
    Effect.sync(() => {
      expect(isSubScope(scopeOf(scope), scopeOf(scope))).toBe(true);
    }),
  { arbitrary: { runs: 300 } }
);

it.effect.prop(
  "isSubScope is transitive",
  { a: Input, b: Input, c: Input, cut: Schema.Int, mask: Mask },
  ({ a, b, c, mask, cut }) =>
    Effect.sync(() => {
      const [left, middle, right] = [scopeOf(a), scopeOf(b), scopeOf(c)];

      if (isSubScope(left, middle) && isSubScope(middle, right)) {
        expect(isSubScope(left, right)).toBe(true);
      }

      const child = narrow(right, mask, Math.abs(cut % 50));
      const grandchild = narrow(child, mask.toReversed(), Math.abs(cut % 7));
      expect(isSubScope(child, right)).toBe(true);
      expect(isSubScope(grandchild, child)).toBe(true);
      expect(isSubScope(grandchild, right)).toBe(true);
    }),
  { arbitrary: { runs: 400 } }
);

it.effect.prop(
  "any single widening is refused and named",
  {
    field: Schema.Literals(["credentials", "hosts", "ops", "grantees", "exp"]),
    scope: Input,
  },
  ({ scope, field }) =>
    Effect.sync(() => {
      const parent = scopeOf(scope);
      const missing = opPool.find((op) => !parent.ops.includes(op));

      const child: Scope | undefined = {
        credentials: Scope.make({
          ...parent,
          credentials: [...parent.credentials, NamePattern.make("zeta/*")],
        }),
        exp: Scope.make({ ...parent, exp: parent.exp + 1 }),
        grantees: Scope.make({
          ...parent,
          grantees: [...parent.grantees, NamePattern.make("zeta/*")],
        }),
        hosts: Scope.make({
          ...parent,
          hosts: [...parent.hosts, Host.make("evil.example.net")],
        }),
        ops:
          missing === undefined
            ? undefined
            : Scope.make({ ...parent, ops: [...parent.ops, missing] }),
      }[field];

      if (child !== undefined) {
        expect(widened(child, parent)).toBe(field);
        expect(isSubScope(child, parent)).toBe(false);
      }
    }),
  { arbitrary: { runs: 400 } }
);

it.effect.prop(
  "chains of depth up to 3 never authorise outside the root",
  {
    child: Input,
    grandchild: Input,
    root: Input,
    run: Schema.Boolean,
    use: UseInput,
  },
  ({ root, child, grandchild, use, run }) =>
    Effect.sync(() => {
      const top = record(scopeOf(root), "acme/desk");
      const middle = record(scopeOf(child), "acme/desk", top.grant.id);

      const leaf = record(
        scopeOf(grandchild),
        "acme/desk",
        middle.grant.id,
        run ? "run-1" : undefined
      );

      const records = [top, middle, leaf];
      const request: Use = { ...use };

      for (const who of [caller("acme/desk"), caller("acme/desk", "run-1")]) {
        const decision = authorizeUse(records, who, request, 1000);

        if (decision.allowed) {
          expect(scopeAllows(top.grant.scope, request, 1000)).toBe(true);

          for (const link of decision.chain) {
            const linked = records.find((entry) => entry.grant.id === link);
            expect(
              linked && scopeAllows(linked.grant.scope, request, 1000)
            ).toBe(true);
          }
        }
      }
    }),
  { arbitrary: { runs: 500 } }
);

it("a fourth link, a revoked or expired ancestor, and a widened stored link are not effective", () => {
  const root = record(base, "acme/desk");
  const one = record(base, "acme/desk", root.grant.id);
  const two = record(base, "acme/desk", one.grant.id);
  const three = record(base, "acme/desk", two.grant.id);
  const records = [root, one, two, three];
  const desk = caller("acme/desk");

  const use: Use = {
    credential: "acme/a",
    host: "api.example.com",
    method: "GET",
    op: "use",
    path: "/",
  };

  expect(effective([root, one, two], 1000)).toBe(true);
  expect(authorizeUse([three], desk, use, 1000).allowed).toBe(false);
  expect(authorizeUse(records.slice(0, 3), desk, use, 1000).allowed).toBe(true);

  expect(
    effective([GrantRecord.make({ ...root, revokedAt: 5 }), one], 1000)
  ).toBe(false);
  expect(effective([root, one], 2000)).toBe(false);

  const widenedLink = record(
    Scope.make({ ...base, hosts: [Host.make("api.example.org")] }),
    "acme/desk",
    root.grant.id
  );

  expect(effective([root, widenedLink], 1000)).toBe(false);
});

it("admission refuses bare *, uncovered grantees, depth and widening, naming the field", () => {
  const root = record(base, "acme/desk");
  const desk = caller("acme/desk");

  const ask = (scope: Scope, desk2 = "acme/desk", records = [root]) =>
    admitDelegated(records, desk, { grantee: { desk: desk2 }, scope }, 1000);

  expect(
    ask(Scope.make({ ...base, credentials: [NamePattern.make("*")] }))
  ).toEqual({
    admitted: false,
    field: "credentials",
  });
  expect(ask(base, "beta/desk")).toEqual({ admitted: false, field: "grantee" });
  expect(
    ask(Scope.make({ ...base, hosts: [Host.make("api.example.org")] }))
  ).toEqual({ admitted: false, field: "hosts" });
  expect(ask(Scope.make({ ...base, ops: ["use"] }))).toEqual({
    admitted: true,
    parent: root.grant.id,
  });

  const boss = record(base, "acme/boss");
  const one = record(base, "acme/boss", boss.grant.id);
  const two = record(base, "acme/desk", one.grant.id);

  expect(
    admitDelegated(
      [boss, one, two],
      desk,
      { grantee: { desk: "acme/desk" }, scope: base },
      1000
    )
  ).toEqual({
    admitted: false,
    field: "depth",
  });
  expect(
    admitDelegated(
      [boss, one],
      caller("acme/boss"),
      { grantee: { desk: "acme/desk" }, scope: base },
      1000
    )
  ).toEqual({
    admitted: true,
    parent: boss.grant.id,
  });
  expect(
    admitDelegated(
      [two],
      desk,
      { grantee: { desk: "acme/desk" }, scope: base },
      1000
    )
  ).toEqual({ admitted: false, field: "parent" });

  const withoutGrant = record(
    Scope.make({ ...base, ops: ["use"] }),
    "acme/desk"
  );

  expect(
    admitDelegated(
      [withoutGrant],
      desk,
      {
        grantee: { desk: "acme/desk" },
        scope: Scope.make({ ...base, ops: ["use"] }),
      },
      1000
    )
  ).toEqual({ admitted: false, field: "parent" });
});

it("clipping refuses policy fields outside the grant", () => {
  const { grant } = record(base, "acme/desk");

  const policy = {
    callers: ["acme/desk"],
    hosts: [Host.make("api.example.com")],
    placements: ["test-host"],
  };

  expect(clipRefusal(policy, grant)).toBeUndefined();
  expect(clipRefusal({ ...policy, callers: ["beta/x"] }, grant)).toBe(
    "callers"
  );
  expect(clipRefusal({ ...policy, callers: ["*"] }, grant)).toBe("callers");
  expect(
    clipRefusal({ ...policy, hosts: [Host.make("api.example.org")] }, grant)
  ).toBe("hosts");
  expect(clipRefusal({ ...policy, ports: [8443] }, grant)).toBe("ports");
  expect(
    clipRefusal(policy, {
      ...grant,
      scope: Scope.make({ ...base, routes: [routePool[1]] }),
    })
  ).toBe("routes");
});

it("run callers match only grants naming their exact handle, and pass expiry is bounded by the chain", () => {
  const root = record(base, "acme/desk");

  const runGrant = record(
    Scope.make({ ...base, exp: 1040 }),
    "acme/desk",
    root.grant.id,
    "run-1"
  );

  const records = [root, runGrant];
  const use: Op = "use";

  const request: Use = {
    credential: "acme/a",
    host: "api.example.com",
    method: "GET",
    op: use,
    path: "/",
  };

  expect(
    authorizeUse(records, caller("acme/desk", "run-2"), request, 1000)
  ).toEqual({ allowed: false, reason: "grant" });
  expect(
    authorizeUse(records, caller("acme/desk", "run-1"), request, 1000)
  ).toEqual({ allowed: false, reason: "pass-expiry" });
  expect(authorizeUse(records, caller("acme/desk"), request, 1000)).toEqual({
    allowed: true,
    chain: [root.grant.id],
  });
});
