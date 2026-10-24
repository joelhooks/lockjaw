import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { Effect, Schema } from "effect";
import { expect } from "vitest";

import wrangler from "../../../packages/worker/wrangler.json" with { type: "json" };
import { bindingSource, secretNames } from "../inputs.ts";
import { chosenSettings, compile } from "./fixture.ts";

const Generated = Schema.Struct({
  compatibility_date: Schema.String,
  durable_objects: Schema.Struct({
    bindings: Schema.Array(
      Schema.Struct({ class_name: Schema.String, name: Schema.String })
    ),
  }),
  migrations: Schema.Array(
    Schema.Struct({
      new_sqlite_classes: Schema.Array(Schema.String),
      tag: Schema.String,
    })
  ),
  vars: Schema.Record(Schema.String, Schema.String),
});

it.effect(
  "compiles the full graph and bundles the real Worker offline with secret references only",
  () =>
    Effect.gen(function* graph() {
      const chosen = yield* chosenSettings;
      const { resources, props } = yield* compile(chosen);

      expect(
        resources.filter((resource) => resource.Type === "Celld.Node")
      ).toHaveLength(1);
      expect(
        resources.filter((resource) => resource.Type === "Celld.Deployment")
      ).toHaveLength(1);
      expect(
        resources.some((resource) => resource.FQN === "store/bucket")
      ).toBe(true);
      expect(
        resources.some((resource) => resource.FQN === "worker-bindings")
      ).toBe(true);
      expect(
        resources.every((resource) => !resource.Type.startsWith("SecretCell."))
      ).toBe(true);

      const text = resources
        .map((resource) => JSON.stringify(resource.Props))
        .join("\n");

      expect(text).not.toMatch(
        /restart-gate|peer-tunnel|nft|Proxmox|Alchemy.Random/u
      );
      expect(text).toContain("192.0.2.10:32000");
      expect(props.secretNames).toEqual(["LOCKJAW_KEK"]);
      expect(props.workerUrl).toBe(chosen.workerUrl);
      expect(props.commit).toMatch(/^[a-f0-9]{40}$/u);
      expect(props.version).toBe(props.commit);
      expect(props.bundle).toContain("/.well-known/rat-king/version");
      expect(props.bundle).toContain(props.commit);
      expect(props.configuration).not.toContain("LOCKJAW_KEK");

      const configuration = yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(Generated)
      )(props.configuration);

      expect(configuration.compatibility_date).toBe(
        wrangler.compatibility_date
      );
      expect(configuration.durable_objects).toEqual(wrangler.durable_objects);
      expect(configuration.migrations).toEqual(wrangler.migrations);
      expect(configuration.vars.APPROVER_DID).toBe(chosen.approverDid);
      expect(configuration.vars.CELL_DID).toBe(chosen.cellDid);
      expect(JSON.parse(configuration.vars.CALLER_DOCUMENTS ?? "null")).toEqual(
        chosen.callerDocuments
      );
      expect(JSON.parse(configuration.vars.SETTERS ?? "null")).toEqual(
        chosen.setters
      );
      expect(configuration.vars.LOCKJAW_BINDINGS_REVISION).toBe(
        "fixture-binding-revision"
      );
      expect(configuration.vars).not.toHaveProperty("KEK_URL");
      expect(bindingSource(chosen.kek)).toEqual({
        format: "json",
        secrets: { KEK: "EXAMPLE_LOCKJAW_KEK" },
        template: '{"LOCKJAW_KEK":{{KEK}}}',
      });
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect("URL mode binds only KEK_ACCESS and keeps KEK_URL public", () =>
  Effect.gen(function* urlMode() {
    const base = yield* chosenSettings;

    const chosen = {
      ...base,
      kek: {
        access: "EXAMPLE_KEK_ACCESS",
        kind: "url" as const,
        url: "http://127.0.0.1:32100/kek",
      },
    };

    const { props } = yield* compile(chosen);

    const configuration = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(Generated)
    )(props.configuration);

    expect(props.secretNames).toEqual(["KEK_ACCESS"]);
    expect(configuration.vars.KEK_URL).toBe(chosen.kek.url);
    expect(props.configuration).not.toContain("EXAMPLE_KEK_ACCESS");
    expect(bindingSource(chosen.kek).template).toBe(
      '{"KEK_ACCESS":{{ACCESS}}}'
    );
    expect(
      secretNames({ kek: "KEK", kekNext: "NEXT", kind: "binding" })
    ).toEqual(["LOCKJAW_KEK", "LOCKJAW_KEK_NEXT"]);
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);
