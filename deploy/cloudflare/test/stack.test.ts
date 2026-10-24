import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { Effect, Exit, Redacted, Schema } from "effect";
import { expect } from "vitest";

import wrangler from "../../../packages/worker/wrangler.json" with { type: "json" };
import {
  baseSettings,
  CANARY,
  compile,
  kekText,
  NEXT_CANARY,
} from "./fixture.ts";
import type { SettingsDocument } from "./fixture.ts";

const byText = <A>(left: A, right: A) =>
  JSON.stringify(left).localeCompare(JSON.stringify(right));

const WireBinding = Schema.Struct({
  className: Schema.optionalKey(Schema.String),
  name: Schema.String,
  text: Schema.optionalKey(Schema.String),
  type: Schema.String,
});

const Bindings = Schema.Array(
  Schema.Struct({
    data: Schema.Struct({ bindings: Schema.Array(WireBinding) }),
    sid: Schema.String,
  })
);

const Props = Schema.Struct({
  access: Schema.optionalKey(Schema.Unknown),
  compatibility: Schema.Struct({ date: Schema.String }),
  domain: Schema.optionalKey(Schema.String),
  env: Schema.Record(Schema.String, Schema.Unknown),
  main: Schema.String,
  name: Schema.String,
  routes: Schema.optionalKey(Schema.Unknown),
  workersDev: Schema.Boolean,
});

const graph = Effect.fn(function* graph(
  document: SettingsDocument,
  extra: Readonly<Record<string, string>> = {}
) {
  const stack = yield* compile(document, extra);
  const resources = Object.values(stack.resources);
  const [worker] = resources;

  return {
    bindings: (yield* Schema.decodeUnknownEffect(Bindings)(
      stack.bindings.cell
    )).flatMap((entry) => entry.data.bindings),
    props: yield* Schema.decodeUnknownEffect(Props)(worker?.Props),
    propsText: JSON.stringify(worker?.Props),
    resources: resources.map((resource) => ({
      id: resource.FQN,
      type: resource.Type,
    })),
  };
});

it.effect(
  "declares one Worker with four SQLite Durable Objects, the vars and the KEK secret by name",
  () =>
    Effect.gen(function* declared() {
      const { bindings, props, propsText, resources } =
        yield* graph(baseSettings);

      expect(resources).toEqual([{ id: "cell", type: "Cloudflare.Worker" }]);
      expect(props.name).toBe("secret-cell");
      expect(props.main.endsWith("packages/worker/src/index.ts")).toBe(true);
      expect(props.compatibility.date).toBe(wrangler.compatibility_date);
      expect(props.workersDev).toBe(true);
      expect(props).not.toHaveProperty("access");
      expect(props).not.toHaveProperty("domain");

      expect(
        bindings.map((binding) => [binding.name, binding.type]).toSorted(byText)
      ).toEqual([
        ["APPROVER_DID", "plain_text"],
        ["CALLER_DOCUMENTS", "plain_text"],
        ["CELL_DID", "plain_text"],
        ["CREDENTIAL", "durable_object_namespace"],
        ["GRANTS", "durable_object_namespace"],
        ["LOCKJAW_KEK", "secret_text"],
        ["REGISTRY", "durable_object_namespace"],
        ["REPLAY", "durable_object_namespace"],
        ["SETTERS", "plain_text"],
      ]);

      const classes = bindings
        .filter((binding) => binding.type === "durable_object_namespace")
        .map((binding) => binding.className);

      expect(classes.toSorted(byText)).toEqual([
        "Credential",
        "Grants",
        "Registry",
        "Replay",
      ]);
      expect(wrangler.migrations).toEqual([
        {
          new_sqlite_classes: ["Credential", "Registry", "Replay"],
          tag: "v1",
        },
        { new_sqlite_classes: ["Grants"], tag: "v2" },
      ]);

      const text = (name: string) =>
        bindings.find((binding) => binding.name === name)?.text;

      expect(text("CELL_DID")).toBe("did:web:cell.example.com");
      expect(text("APPROVER_DID")).toBe("did:web:operator.example.com");
      expect(JSON.parse(text("SETTERS") ?? "null")).toEqual(
        baseSettings.setters
      );
      expect(JSON.parse(text("CALLER_DOCUMENTS") ?? "null")).toEqual(
        baseSettings.callerDocuments
      );
      expect(Redacted.isRedacted(props.env.LOCKJAW_KEK)).toBe(true);
      expect(props.env).not.toHaveProperty("LOCKJAW_KEK_NEXT");
      expect(propsText.includes(CANARY)).toBe(false);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect("binds the optional next KEK as its own secret", () =>
  Effect.gen(function* next() {
    const { bindings, props, propsText } = yield* graph(
      {
        ...baseSettings,
        secrets: { kek: "LOCKJAW_KEK", kekNext: "LOCKJAW_KEK_NEXT" },
      },
      { LOCKJAW_KEK_NEXT: kekText("kek-2", NEXT_CANARY) }
    );

    expect(
      bindings.find((binding) => binding.name === "LOCKJAW_KEK_NEXT")?.type
    ).toBe("secret_text");
    expect(Redacted.isRedacted(props.env.LOCKJAW_KEK_NEXT)).toBe(true);
    expect(propsText.includes(NEXT_CANARY)).toBe(false);
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect(
  "maps the reach and Access choices from the private file onto the Worker",
  () =>
    Effect.gen(function* reach() {
      const domain = yield* graph({
        ...baseSettings,
        reach: { kind: "domain", name: "cell.example.com" },
      });

      expect(domain.props.workersDev).toBe(false);
      expect(domain.props.domain).toBe("cell.example.com");

      const route = yield* graph({
        ...baseSettings,
        reach: {
          kind: "route",
          pattern: "cell.example.com/*",
          zoneName: "example.com",
        },
      });

      expect(route.props.workersDev).toBe(false);
      expect(route.props.routes).toEqual([
        { pattern: "cell.example.com/*", zoneName: "example.com" },
      ]);

      const off = yield* graph({ ...baseSettings, access: { enabled: false } });

      expect(off.props).not.toHaveProperty("access");

      const gated = yield* graph({
        ...baseSettings,
        access: {
          enabled: true,
          serviceTokenId: "00000000-0000-4000-8000-000000000000",
        },
      });

      expect(gated.props.access).toEqual({
        policies: [
          {
            decision: "non_identity",
            include: [{ serviceToken: "00000000-0000-4000-8000-000000000000" }],
          },
        ],
        previews: true,
      });
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

const refusal = Effect.fn(function* refusal(
  document: SettingsDocument,
  extra: Readonly<Record<string, string>>
) {
  const exit = yield* graph(document, extra).pipe(Effect.exit);

  expect(Exit.isFailure(exit)).toBe(true);

  return Exit.isFailure(exit) ? String(exit.cause) : "";
});

it.effect(
  "refuses a foreign account, a missing or malformed KEK and a shared kekId without echoing the value",
  () =>
    Effect.gen(function* refusals() {
      const account = yield* refusal(baseSettings, {
        CLOUDFLARE_ACCOUNT_ID: "fedcba9876543210fedcba9876543210",
      });

      expect(account).toMatch(
        /What: CLOUDFLARE_ACCOUNT_ID does not match.*Why: .*Next: /su
      );

      const missing = yield* refusal(
        { ...baseSettings, secrets: { kek: "UNSET_KEK" } },
        {}
      );

      expect(missing).toMatch(
        /What: Secret input UNSET_KEK is not set\..*Why: .*Next: /su
      );

      const malformed = yield* refusal(baseSettings, {
        LOCKJAW_KEK: `{"kekId":"kek-1","key":"${CANARY}!"}`,
      });

      expect(malformed).toMatch(
        /What: Secret input LOCKJAW_KEK is not a KEK binding\..*Why: .*Next: /su
      );
      expect(malformed.includes(CANARY)).toBe(false);

      const shared = yield* refusal(
        {
          ...baseSettings,
          secrets: { kek: "LOCKJAW_KEK", kekNext: "LOCKJAW_KEK_NEXT" },
        },
        { LOCKJAW_KEK_NEXT: kekText("kek-1", NEXT_CANARY) }
      );

      expect(shared).toMatch(/What: .*share one kekId\..*Why: .*Next: /su);
      expect(shared.includes(NEXT_CANARY)).toBe(false);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);
