import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import {
  Cause,
  ConfigProvider,
  Effect,
  Exit,
  FileSystem,
  Path,
  Schema,
} from "effect";
import { expect } from "vitest";

import { CloudflareRefusal, loadSettings, settingsPath } from "../config.ts";
import {
  baseSettings,
  documents,
  writeConfig,
  writeConfigFile,
} from "./fixture.ts";

const refused = Effect.fn(function* refused(file: string) {
  const exit = yield* loadSettings(file).pipe(Effect.exit);

  expect(Exit.isFailure(exit)).toBe(true);

  const error = Exit.isFailure(exit)
    ? exit.cause.reasons.find(Cause.isFailReason)?.error
    : undefined;

  expect(error).toBeInstanceOf(CloudflareRefusal);

  return Schema.is(CloudflareRefusal)(error)
    ? error
    : new CloudflareRefusal({ next: "", what: "", why: "" });
});

const threePart = (error: CloudflareRefusal) => {
  expect(error.what.length).toBeGreaterThan(0);
  expect(error.why.length).toBeGreaterThan(0);
  expect(error.next.length).toBeGreaterThan(0);
  expect(error.message).toBe(
    `What: ${error.what} Why: ${error.why} Next: ${error.next}`
  );
};

it.effect("refuses a missing config file with a three-part error", () =>
  Effect.gen(function* missing() {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const directory = yield* fs.makeTempDirectoryScoped();
    const file = path.join(directory, "absent.json");
    const error = yield* refused(file);

    threePart(error);
    expect(error.what).toBe(`No Cloudflare config file at ${file}.`);
    expect(error.next).toContain("SECRET_CELL_CLOUDFLARE_CONFIG");
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect("refuses a 0644 or 0640 config file and a directory", () =>
  Effect.gen(function* loose() {
    const fs = yield* FileSystem.FileSystem;
    const directory = yield* fs.makeTempDirectoryScoped();

    for (const mode of [0o644, 0o640]) {
      const file = yield* writeConfigFile(
        directory,
        JSON.stringify(baseSettings),
        mode
      );

      const error = yield* refused(file);

      threePart(error);
      expect(error.what).toContain(`mode 0${mode.toString(8)}`);
      expect(error.next).toBe(`Run chmod 600 ${file}, then rerun.`);
    }

    const error = yield* refused(directory);

    threePart(error);
    expect(error.what).toContain("is not a regular file");
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect(
  "names invalid fields without echoing their values, and rejects private JWKs",
  () =>
    Effect.gen(function* invalid() {
      const fs = yield* FileSystem.FileSystem;
      const directory = yield* fs.makeTempDirectoryScoped();

      const file = yield* writeConfig(
        directory,
        JSON.stringify({
          ...baseSettings,
          accountId: "PRIVATE-ACCOUNT-VALUE",
          workerName: undefined,
        })
      );

      const error = yield* refused(file);

      threePart(error);
      expect(error.why).toContain("accountId");
      expect(error.why).toContain("workerName");
      expect(error.message.includes("PRIVATE-ACCOUNT-VALUE")).toBe(false);

      const leaked = yield* writeConfig(
        directory,
        JSON.stringify({
          ...baseSettings,
          callerDocuments: documents.map((document) => ({
            ...document,
            verificationMethod: document.verificationMethod.map((method) => ({
              ...method,
              publicKeyJwk: { ...method.publicKeyJwk, d: "PRIVATE-JWK-SCALAR" },
            })),
          })),
        })
      );

      const jwk = yield* refused(leaked);

      threePart(jwk);
      expect(jwk.why).toContain("callerDocuments.0.verificationMethod.0");
      expect(jwk.message.includes("PRIVATE-JWK-SCALAR")).toBe(false);

      const broken = yield* writeConfig(directory, "{");

      threePart(yield* refused(broken));
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect(
  "loads a 0600 file and takes its path from HOME or the override",
  () =>
    Effect.gen(function* valid() {
      const fs = yield* FileSystem.FileSystem;
      const directory = yield* fs.makeTempDirectoryScoped();
      const file = yield* writeConfig(directory, JSON.stringify(baseSettings));
      const loaded = yield* loadSettings(file);

      expect(loaded.workerName).toBe("secret-cell");
      expect(loaded.access).toBeUndefined();

      const fallback = yield* settingsPath.pipe(
        Effect.provide(
          ConfigProvider.layer(ConfigProvider.fromUnknown({ HOME: "/home/a" }))
        )
      );

      expect(fallback).toBe("/home/a/.config/secret-cell/cloudflare.json");

      const override = yield* settingsPath.pipe(
        Effect.provide(
          ConfigProvider.layer(
            ConfigProvider.fromUnknown({
              HOME: "/home/a",
              SECRET_CELL_CLOUDFLARE_CONFIG: file,
            })
          )
        )
      );

      expect(override).toBe(file);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);
