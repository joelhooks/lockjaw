import { readFileSync, readdirSync } from "node:fs";
import nodePath from "node:path";

import { expect, it } from "@effect/vitest";

it("Redacted.value occurs only at the four reviewed unwrap boundaries", () => {
  const sources = [
    "packages/domain/src",
    "packages/gateway-rules/src",
    "packages/cell/src",
  ].flatMap((directory) =>
    readdirSync(directory, { recursive: true, withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith(".ts"))
      .map((entry) => nodePath.resolve(entry.parentPath, entry.name))
  );

  const uses: string[] = [];
  const boundaries: string[] = [];

  for (const path of sources) {
    const source = readFileSync(path, "utf-8");
    expect(source).not.toMatch(/from\s*["']effect\/Redacted["']/u);
    expect(source).not.toMatch(/Redacted\s+as\s+/u);
    expect(source).not.toMatch(/Redacted\s*\[/u);
    expect(source).not.toMatch(/\{[^}]*value[^}]*\}\s*=\s*Redacted/u);

    for (const match of source.matchAll(/Redacted\s*\.\s*value/gu)) {
      if (path.endsWith("/cell/src/keyring.ts")) {
        const spans = [
          ...source
            .slice(0, match.index)
            .matchAll(/Effect\.fn\("(?<span>Keyring\.[A-Za-z]+)"\)/gu),
        ];

        const span = spans.at(-1)?.groups?.span ?? "outside";
        boundaries.push(span);

        const end = {
          "Keyring.encrypt": 'Effect.fn("Keyring.importSigningKey")',
          "Keyring.fetchKek": "const wrongBody",
          "Keyring.importKek": 'Effect.fn("Keyring.fromBinding")',
        }[span];

        expect(end).toBeDefined();
        expect(match.index).toBeLessThan(source.indexOf(end ?? "\0"));
      } else {
        boundaries.push("Fill.apply");
        expect(path.endsWith("/gateway-rules/src/fill.ts")).toBe(true);
        expect(match.index).toBeGreaterThan(
          source.indexOf('Effect.fn("Fill.apply")')
        );
        expect(match.index).toBeLessThan(source.indexOf("export class Fill"));
      }

      uses.push(path);
    }
  }

  expect(
    uses.filter((path) => path.endsWith("/gateway-rules/src/fill.ts"))
  ).toHaveLength(1);
  expect(
    uses.filter((path) => path.endsWith("/cell/src/keyring.ts"))
  ).toHaveLength(3);
  expect(uses).toHaveLength(4);
  expect(boundaries.toSorted()).toEqual([
    "Fill.apply",
    "Keyring.encrypt",
    "Keyring.fetchKek",
    "Keyring.importKek",
  ]);
});
