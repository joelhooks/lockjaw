import {
  InstanceNameSchema,
  PortBaseSchema,
  instanceLayout,
} from "@rat-king/alchemy-nest";
import { Config, Effect, FileSystem, Path, Schema, SchemaIssue } from "effect";

import { selectKek } from "../../packages/cell/src/keyring.ts";
import { Documents } from "../../packages/worker/src/caller-auth.ts";

export const CONFIG_ENV = "LOCKJAW_CELLD_CONFIG";

export class CelldRefusal extends Schema.TaggedError<CelldRefusal>()(
  "CelldRefusal",
  { next: Schema.String, what: Schema.String, why: Schema.String }
) {
  override get message() {
    return `What: ${this.what} Why: ${this.why} Next: ${this.next}`;
  }
}

const AbsolutePath = Schema.String.check(
  Schema.isPattern(
    /^\/(?!$)(?!\.{1,2}(?:\/|$))(?!.*\/\.{1,2}(?:\/|$))(?!.*\/\/)[^\r\n\0]*[^/\r\n\0]$/u
  )
);

const Did = Schema.String.check(Schema.isPattern(/^did:[a-z0-9]+:\S+$/u));

const EnvironmentName = Schema.String.check(
  Schema.isPattern(/^[A-Z_][A-Z0-9_]{0,63}$/u)
);

const IPv4 = Schema.String.check(
  Schema.isPattern(/^(?:\d{1,3}\.){3}\d{1,3}$/u),
  Schema.makeFilter((value) =>
    value.split(".").every((part) => Number(part) <= 255)
  )
);

const HttpUrl = Schema.String.check(
  Schema.makeFilter((value) => {
    if (!URL.canParse(value)) {
      return false;
    }

    const url = new URL(value);

    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      url.username === "" &&
      url.password === "" &&
      url.hash === ""
    );
  })
);

const Origin = HttpUrl.check(
  Schema.makeFilter(
    (value) => URL.canParse(value) && new URL(value).origin === value
  )
);

const Kek = Schema.Union([
  Schema.Struct({
    kek: EnvironmentName,
    kekNext: Schema.optionalKey(EnvironmentName),
    kind: Schema.Literal("binding"),
  }),
  Schema.Struct({
    access: EnvironmentName,
    kind: Schema.Literal("url"),
    url: Schema.String.check(
      Schema.makeFilter(
        (url) =>
          selectKek({ KEK_ACCESS: "config-validation", KEK_URL: url }).mode ===
          "url"
      )
    ),
  }),
]);

export const SettingsSchema = Schema.Struct({
  approverDid: Did,
  bucket: Schema.String.check(
    Schema.isPattern(/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u)
  ),
  callerDocuments: Documents,
  cellDid: Did,
  credentials: Schema.Struct({
    accessKey: EnvironmentName,
    secretKey: EnvironmentName,
  }),
  dataRoot: AbsolutePath,
  host: Schema.Struct({
    dataRoot: AbsolutePath,
    home: AbsolutePath,
    ssh: Schema.String.check(Schema.isPattern(/^(?!-)[A-Za-z0-9_.@:-]+$/u)),
    tailnetIPv4: IPv4,
  }),
  instance: InstanceNameSchema,
  kek: Kek,
  portBase: PortBaseSchema,
  setters: Schema.Array(Did),
  workerName: Schema.String.check(
    Schema.isPattern(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u)
  ),
  workerUrl: Origin,
});

export type Settings = typeof SettingsSchema.Type;

export const refusal = (what: string, why: string, next: string) =>
  new CelldRefusal({ next, what, why });

const invalid = (what: string) =>
  refusal(
    what,
    "Deployment inputs must match the operator config; values are withheld.",
    "Fix the private config against deploy/celld/README.md, then rerun."
  );

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

const overlap = (left: string, right: string) =>
  left === right ||
  left.startsWith(`${right}/`) ||
  right.startsWith(`${left}/`);

export const decodeSettings = Effect.fn("Lockjaw.decodeCelldSettings")(
  function* decodeSettings(text: string) {
    const chosen = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(SettingsSchema),
      {
        errors: "all",
        onExcessProperty: "error",
      }
    )(text).pipe(
      Effect.mapError((error) =>
        invalid(`Invalid celld config fields: ${fieldPaths(error.issue)}.`)
      )
    );

    const reserved = Object.values(instanceLayout(chosen.host, {}).ports);

    if (
      overlap(chosen.dataRoot, chosen.host.dataRoot) ||
      [`${chosen.host.home}/.config`, `${chosen.host.home}/.local/share`].some(
        (root) => overlap(chosen.dataRoot, root)
      ) ||
      reserved.some(
        (port) => port >= chosen.portBase && port < chosen.portBase + 10
      )
    ) {
      return yield* invalid(
        "The instance data root or ports overlap reserved storage or listeners."
      );
    }

    return chosen;
  }
);

export const settingsPath = Effect.gen(function* settingsPath() {
  const path = yield* Path.Path;
  const home = yield* Config.String("HOME");

  return yield* Config.String(CONFIG_ENV).pipe(
    Config.withDefault(path.join(home, ".config/lockjaw/celld.json"))
  );
});

export const loadSettings = Effect.fn("Lockjaw.loadCelldSettings")(
  function* loadSettings(file: string) {
    const fs = yield* FileSystem.FileSystem;

    const info = yield* fs
      .stat(file)
      .pipe(Effect.mapError(() => invalid("The celld config is unreadable.")));

    if (info.type !== "File" || info.mode % 0o1000 !== 0o600) {
      return yield* invalid("The celld config must be a regular 0600 file.");
    }

    const text = yield* fs
      .readFileString(file)
      .pipe(
        Effect.mapError(() => invalid("The celld config could not be read."))
      );

    return yield* decodeSettings(text);
  }
);

export const settings = settingsPath.pipe(Effect.flatMap(loadSettings));
