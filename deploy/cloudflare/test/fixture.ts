import { AlchemyContext } from "alchemy/AlchemyContext";
import { ConfigProvider, Effect, FileSystem, Path } from "effect";

import type { Settings } from "../config.ts";
import { compiled } from "./graph.ts";

export type SettingsDocument = typeof Settings.Encoded;

export const ACCOUNT = "0123456789abcdef0123456789abcdef";

export const CANARY = "c2VjcmV0LWNlbGwtY2FuYXJ5LWtlay12YWx1ZS0wMDE";

export const NEXT_CANARY = "c2VjcmV0LWNlbGwtY2FuYXJ5LWtlay12YWx1ZS0wMDI";

export const kekText = (kekId: string, key: string) =>
  JSON.stringify({ kekId, key });

export const documents = [
  {
    authentication: ["did:web:caller.example.com#key-1"],
    id: "did:web:caller.example.com",
    issuer: "example-host",
    name: "example-caller",
    verificationMethod: [
      {
        controller: "did:web:caller.example.com",
        id: "did:web:caller.example.com#key-1",
        publicKeyJwk: {
          crv: "Ed25519",
          kty: "OKP",
          x: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        },
      },
    ],
  },
];

export const baseSettings: SettingsDocument = {
  accountId: ACCOUNT,
  approverDid: "did:web:operator.example.com",
  callerDocuments: documents,
  cellDid: "did:web:cell.example.com",
  reach: { kind: "workers.dev" },
  secrets: { kek: "LOCKJAW_KEK" },
  setters: ["did:web:caller.example.com"],
  workerName: "secret-cell",
};

export const writeConfigFile = Effect.fn(function* writeConfigFile(
  directory: string,
  contents: string,
  mode: number
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const file = path.join(directory, "cloudflare.json");

  yield* fs.writeFileString(file, contents);
  yield* fs.chmod(file, mode);

  return file;
});

export const writeConfig = (directory: string, contents: string) =>
  writeConfigFile(directory, contents, 0o600);

export const environment = (
  file: string,
  home: string,
  extra: Readonly<Record<string, string>> = {}
) =>
  ConfigProvider.layer(
    ConfigProvider.fromUnknown({
      CLOUDFLARE_ACCOUNT_ID: ACCOUNT,
      HOME: home,
      LOCKJAW_KEK: kekText("kek-1", CANARY),
      SECRET_CELL_CLOUDFLARE_CONFIG: file,
      ...extra,
    })
  );

export const compile = Effect.fn(function* compile(
  document: SettingsDocument,
  extra: Readonly<Record<string, string>> = {}
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const directory = yield* fs.makeTempDirectoryScoped();
  const file = yield* writeConfig(directory, JSON.stringify(document));

  return yield* compiled.pipe(
    Effect.provideService(AlchemyContext, {
      adopt: false,
      dev: false,
      dotAlchemy: path.join(directory, "alchemy"),
    }),
    Effect.provide(environment(file, directory, extra))
  );
});
