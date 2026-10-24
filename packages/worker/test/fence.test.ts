import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { expect, it } from "@effect/vitest";

it("only the approved RPC encoder unwraps, and the branded transport stays in its two modules", () => {
  const files = readdirSync("packages", {
    recursive: true,
    withFileTypes: true,
  })
    .filter(
      (entry) =>
        entry.isFile() &&
        entry.name.endsWith(".ts") &&
        entry.parentPath.includes("/src") &&
        !entry.parentPath.includes("node_modules")
    )
    .map((entry) => path.join(entry.parentPath, entry.name));

  const unwraps: string[] = [];

  for (const file of files) {
    const source = readFileSync(file, "utf-8");

    if (source.includes("ResolvedForFill")) {
      expect([
        "packages/worker/src/credential-do.ts",
        "packages/worker/src/gateway.ts",
      ]).toContain(file);
    }

    for (const match of source.matchAll(/Redacted\s*\.\s*value/gu)) {
      expect(match[0]).toBe("Redacted.value");
      unwraps.push(file);
    }
  }

  expect(unwraps.toSorted()).toEqual([
    "packages/cell/src/keyring.ts",
    "packages/cell/src/keyring.ts",
    "packages/cell/src/keyring.ts",
    "packages/gateway-rules/src/fill.ts",
    "packages/worker/src/credential-do.ts",
  ]);
  const gateway = readFileSync("packages/worker/src/gateway.ts", "utf-8");
  expect(gateway).toContain("Effect.map(decodeResolved)");
  expect(gateway).toContain("Redacted.make(input.value)");
}, 30_000);
