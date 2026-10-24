import {
  Config,
  Effect,
  FileSystem,
  Option,
  Path,
  Schema,
  SchemaIssue,
} from "effect";

import { Documents } from "../../packages/worker/src/caller-auth.ts";

export const CONFIG_ENV = "SECRET_CELL_CLOUDFLARE_CONFIG";

export const DEFAULT_CONFIG = ".config/secret-cell/cloudflare.json";

export class CloudflareRefusal extends Schema.TaggedError<CloudflareRefusal>()(
  "CloudflareRefusal",
  {
    next: Schema.String,
    what: Schema.String,
    why: Schema.String,
  }
) {
  override get message() {
    return `What: ${this.what} Why: ${this.why} Next: ${this.next}`;
  }
}

const Did = Schema.String.check(Schema.isPattern(/^did:[a-z0-9]+:\S+$/u));

const EnvironmentName = Schema.String.check(
  Schema.isPattern(/^[A-Z_][A-Z0-9_]{0,63}$/u)
);

const Reach = Schema.Union([
  Schema.Struct({ kind: Schema.Literal("workers.dev") }),
  Schema.Struct({
    kind: Schema.Literal("domain"),
    name: Schema.NonEmptyString,
  }),
  Schema.Struct({
    kind: Schema.Literal("route"),
    pattern: Schema.NonEmptyString,
    zoneName: Schema.NonEmptyString,
  }),
]);

const Access = Schema.Union([
  Schema.Struct({ enabled: Schema.Literal(false) }),
  Schema.Struct({
    enabled: Schema.Literal(true),
    serviceTokenId: Schema.String.check(
      Schema.isPattern(/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/u)
    ),
  }),
]);

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Settings = Schema.Struct({
  access: Schema.optionalKey(Access),
  accountId: Schema.String.check(Schema.isPattern(/^[0-9a-f]{32}$/u)),
  approverDid: Did,
  callerDocuments: Documents,
  cellDid: Did,
  reach: Reach,
  secrets: Schema.Struct({
    kek: EnvironmentName,
    kekNext: Schema.optionalKey(EnvironmentName),
  }),
  setters: Schema.Array(Did),
  workerName: Schema.String.check(
    Schema.isPattern(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)
  ),
});

export type Settings = typeof Settings.Type;

const refuse = (what: string, why: string, next: string) =>
  Effect.fail(new CloudflareRefusal({ next, what, why }));

const fieldPaths = (issue: SchemaIssue.Issue) =>
  [
    ...new Set(
      SchemaIssue.makeFormatterStandardSchemaV1()(issue).issues.map((entry) =>
        entry.path === undefined || entry.path.length === 0
          ? "(root)"
          : entry.path.map(String).join(".")
      )
    ),
  ].join(", ");

export const settingsPath = Effect.gen(function* settingsPath() {
  const path = yield* Path.Path;
  const home = yield* Config.String("HOME");

  return yield* Config.String(CONFIG_ENV).pipe(
    Config.withDefault(path.join(home, DEFAULT_CONFIG))
  );
});

export const loadSettings = Effect.fn("SecretCell.loadCloudflareSettings")(
  function* loadSettings(file: string) {
    const fs = yield* FileSystem.FileSystem;

    const info = yield* fs.stat(file).pipe(Effect.option);

    if (Option.isNone(info)) {
      return yield* refuse(
        `No Cloudflare config file at ${file}.`,
        "The stack takes the account, Worker name, caller documents and secret names only from a private file outside the repository. It has no defaults.",
        `Create it from the shape in deploy/cloudflare/README.md, run chmod 600 on it, or point ${CONFIG_ENV} at an existing file.`
      );
    }

    if (info.value.type !== "File") {
      return yield* refuse(
        `The Cloudflare config path ${file} is not a regular file.`,
        "A directory, socket or device can't hold the private settings.",
        `Replace it with a regular 0600 file, or point ${CONFIG_ENV} at one.`
      );
    }

    const mode = info.value.mode % 0o1000;

    if (mode % 0o100 !== 0) {
      return yield* refuse(
        `The Cloudflare config file ${file} has mode 0${mode.toString(8)}.`,
        "Group or other users can read it, and it names the account, the callers and the secret sources.",
        `Run chmod 600 ${file}, then rerun.`
      );
    }

    const text = yield* fs.readFileString(file);

    return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Settings))(
      text,
      { errors: "all" }
    ).pipe(
      Effect.catchTag("SchemaError", (error) =>
        refuse(
          `The Cloudflare config file ${file} does not match the documented shape.`,
          `These fields are missing or invalid: ${fieldPaths(error.issue)}.`,
          "Fix those fields against deploy/cloudflare/README.md, then rerun."
        )
      )
    );
  }
);

export const settings = settingsPath.pipe(Effect.flatMap(loadSettings));
