import { NodeServices } from "@effect/platform-node";
import { HostShell } from "@rat-king/alchemy-nest";
import { AlchemyContext, AlchemyContextLive } from "alchemy/AlchemyContext";
import { AuthProviders } from "alchemy/Auth";
import * as Output from "alchemy/Output";
import { Stage } from "alchemy/Stage";
import { inMemoryState } from "alchemy/State/InMemoryState";
import { ConfigProvider, Effect, FileSystem, Layer, Schema } from "effect";

import { build } from "../alchemy.run.ts";
import example from "../config.example.json" with { type: "json" };
import { decodeSettings } from "../config.ts";
import type { Settings } from "../config.ts";
import { celldStack } from "../stack.ts";

export const CANARY = "A".repeat(43);

export const kekText = (kekId: string) =>
  JSON.stringify({ kekId, key: CANARY });

export const environment = (extra: Readonly<Record<string, string>> = {}) =>
  ConfigProvider.layer(
    ConfigProvider.fromUnknown({
      EXAMPLE_LOCKJAW_KEK: kekText("example-kek-1"),
      ...extra,
    })
  );

export const chosenSettings = decodeSettings(JSON.stringify(example));

const forbidden = () => Effect.die(new Error("OFFLINE_HOST_REFUSED"));

export const offlineHost = Layer.succeed(HostShell, {
  exec: forbidden,
  mkdir: forbidden,
  purgeRoots: [],
  read: forbidden,
  remove: forbidden,
  rmdir: forbidden,
  stat: forbidden,
  write: forbidden,
});

const Configuration = Schema.Struct({
  bundle: Schema.String,
  commit: Schema.String,
  configuration: Schema.String,
  secretNames: Schema.Array(Schema.String),
  version: Schema.String,
  workerUrl: Schema.String,
});

export const compile = Effect.fn("Test.compileCelld")(function* compile(
  chosen: Settings
) {
  const fs = yield* FileSystem.FileSystem;
  const directory = yield* fs.makeTempDirectoryScoped();

  const compiled = yield* celldStack(
    Effect.succeed(chosen),
    build,
    offlineHost
  ).pipe(
    Effect.provideService(AlchemyContext, {
      adopt: false,
      dev: false,
      dotAlchemy: directory,
    }),
    Effect.provideService(AuthProviders, {}),
    Effect.provide(
      Layer.mergeAll(AlchemyContextLive, Layer.succeed(Stage, "test")).pipe(
        Layer.provideMerge(NodeServices.layer)
      )
    )
  );

  const { deployment } = compiled.resources;

  const props: unknown = yield* Output.evaluate(deployment?.Props, {
    "celld/node": {
      internalUrl: "http://127.0.0.1:32001",
      sha256: "fixture-unit",
    },
    "worker-bindings": {
      path: "/home/example/.config/lockjaw/worker-bindings.json",
      sha256: "fixture-binding-revision",
    },
  }).pipe(Effect.provide(inMemoryState()));

  return {
    compiled,
    props: yield* Schema.decodeUnknownEffect(Configuration)(props),
    resources: Object.values(compiled.resources),
  };
});
