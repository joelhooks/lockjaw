import { it } from "@effect/vitest";
import { Effect, Schema } from "effect";
import { describe, expect } from "vitest";

import { Instance, violations } from "./rules.ts";

const inventory = {
  domains: ["network.example"],
  hosts: ["another-node.example"],
  ips: ["203.0.113.11"],
  secretNames: ["example_credential"],
  sites: ["site-a"],
};

const node = {
  dataRoot: "/srv/example",
  home: "/home/example",
  ssh: "node-a.example",
  tailnetIPv4: "198.18.0.10",
};

const decode = Schema.decodeUnknownEffect(Instance, {
  onExcessProperty: "error",
});

describe("private nodes", () => {
  it.effect(
    "keeps legacy inventory valid and feeds every node value into the denylist",
    () =>
      Effect.gen(function* nodes() {
        expect((yield* decode(inventory)).nodes).toBeUndefined();

        const decoded = yield* decode({
          ...inventory,
          nodes: { "node-a": node },
        });

        for (const value of ["node-a", ...Object.values(node)]) {
          expect(violations({ content: value, inventory: decoded })).toContain(
            "instance-nodes"
          );
        }
      })
  );

  it.effect("fails closed on malformed nodes and unknown properties", () =>
    Effect.gen(function* malformed() {
      for (const nodes of [
        null,
        [],
        "node-a",
        { "node-a": {} },
        { "node-a": { ...node, home: "relative" } },
        { "node-a": { ...node, ssh: "-oCommand" } },
        { "node-a": { ...node, tailnetIPv4: "999.0.0.1" } },
        { "node-a": { ...node, dataRoot: 1 } },
        { "node-a": { ...node, unexpected: "invented" } },
      ]) {
        expect(
          yield* decode({ ...inventory, nodes }).pipe(Effect.isFailure)
        ).toBe(true);
      }

      expect(
        yield* decode({ ...inventory, nodes: {}, unexpected: "invented" }).pipe(
          Effect.isFailure
        )
      ).toBe(true);
    })
  );
});
