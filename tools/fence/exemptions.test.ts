import { expect, it } from "vitest";

import { blobHash, exemptions, isExempt } from "./exemptions.ts";
import { treeExempt } from "./tree-exemption.ts";

it("has no content exemptions", () => {
  expect(exemptions).toEqual([]);
  expect(isExempt("test.ts", blobHash("test"), "email")).toBe(false);
});

it("excludes exactly the fleet infra directory from tree scans", () => {
  expect(treeExempt("infra/alchemy.run.ts")).toBe(true);

  for (const name of [
    "infra.ts",
    "infra-other/file",
    "packages/infra/file",
    ".brain/file.svx",
    "tools/fence/scan.ts",
  ]) {
    expect(treeExempt(name)).toBe(false);
  }
});
