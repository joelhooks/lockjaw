import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { ConfigProvider, Effect, FileSystem, Path, Predicate } from "effect";
import { expect } from "vitest";

import { execute, loadInstance, scan } from "./scan.ts";

const inventory = {
  domains: ["network.production.dev"],
  hosts: ["node-a"],
  ips: ["198.18.0.1"],
  secretNames: ["example-credential"],
  sites: ["site-a"],
};

const fixture = Effect.gen(function* fixture() {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const root = yield* fs.makeTempDirectoryScoped();
  yield* fs.makeDirectory(path.join(root, "tools/fence"), { recursive: true });
  yield* fs.writeFileString(
    path.join(root, "tools/fence/gitleaks.toml"),
    yield* fs.readFileString("tools/fence/gitleaks.toml")
  );
  yield* fs.writeFileString(
    path.join(root, ".gitignore"),
    ".fence-tmp/\n.brain/\n"
  );

  const init = yield* execute({
    args: ["init", "--quiet"],
    cwd: root,
    executable: "git",
  });

  expect(init.code).toBe(0);

  return { fs, path, root };
});

it.effect(
  "tree skips infra only, scans untracked files, and staged mode never skips infra",
  () =>
    Effect.gen(function* tree() {
      const { fs, path, root } = yield* fixture;
      yield* fs.makeDirectory(path.join(root, "infra"));
      yield* fs.writeFileString(
        path.join(root, "infra/private.txt"),
        ["", "Users", "example", "private"].join("/")
      );
      expect((yield* scan({ generic: true, mode: "tree", root })).count).toBe(
        2
      );
      yield* fs.writeFileString(
        path.join(root, "planted.txt"),
        `public\n${[10, 78, 0, 1].join(".")}`
      );

      const rejected = yield* scan({ generic: true, mode: "tree", root }).pipe(
        Effect.flip
      );

      if (!Predicate.isTagged(rejected, "FenceError")) {
        throw new Error("Expected fence rejection");
      }

      expect(rejected.reason).toContain(
        'path="planted.txt" line=2 rule=private-ip'
      );
      expect(rejected.reason).toContain("\nWhy:");
      expect(rejected.reason).toContain("\nNext:");
      expect(rejected.reason).not.toContain([10, 78, 0, 1].join("."));

      const add = yield* execute({
        args: ["add", "infra/private.txt"],
        cwd: root,
        executable: "git",
      });

      expect(add.code).toBe(0);
      expect(
        yield* scan({ generic: true, mode: "staged", root }).pipe(
          Effect.isFailure
        )
      ).toBe(true);
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped)
);

it.effect(
  "loads a private symlink target and fails closed on unsafe modes, malformed or missing inventory",
  () =>
    Effect.gen(function* permissions() {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const dir = yield* fs.makeTempDirectoryScoped();
      const file = path.join(dir, "instance.json");
      const link = path.join(dir, "instance-link.json");
      yield* fs.writeFileString(file, JSON.stringify(inventory));
      yield* fs.chmod(file, 0o600);
      yield* fs.symlink(file, link);

      const layer = ConfigProvider.layer(
        ConfigProvider.fromUnknown({ RATS_NEST_INSTANCE: link })
      );

      expect(
        yield* loadInstance({ generic: false }).pipe(Effect.provide(layer))
      ).toEqual(inventory);
      yield* fs.chmod(file, 0o644);
      expect(
        yield* loadInstance({ generic: false }).pipe(
          Effect.provide(layer),
          Effect.isFailure
        )
      ).toBe(true);
      yield* fs.chmod(file, 0o600);
      yield* fs.writeFileString(file, "{}");
      expect(
        yield* loadInstance({ generic: false }).pipe(
          Effect.provide(layer),
          Effect.isFailure
        )
      ).toBe(true);
      yield* fs.remove(file);
      expect(
        yield* loadInstance({ generic: false }).pipe(
          Effect.provide(layer),
          Effect.isFailure
        )
      ).toBe(true);
      expect(
        yield* loadInstance({ generic: true }).pipe(Effect.provide(layer))
      ).toBeNull();
    }).pipe(Effect.provide(NodeServices.layer), Effect.scoped)
);
