import {
  Celld,
  GeneratedConfiguration,
  ObjectStore,
  RemoteFile,
  sourceLayer,
} from "@rat-king/alchemy-nest";
import type { HostShell } from "@rat-king/alchemy-nest";
import { localState, Stack } from "alchemy";
import { dotAlchemyDirectory } from "alchemy/AlchemyContext";
import * as Output from "alchemy/Output";
import type { StackServices } from "alchemy/Stack";
import { Effect, Layer, Path, Schema } from "effect";
import { FetchHttpClient } from "effect/http";

import type { Settings } from "./config.ts";
import { bindingSource, environmentSecrets, secretNames } from "./inputs.ts";
import { prepareState, withheldState } from "./state.ts";

export interface Build {
  readonly bundle: string;
  readonly configuration: string;
  readonly version: string;
  readonly commit: string;
}

export const publicVars = (chosen: Settings) => {
  const vars = {
    APPROVER_DID: chosen.approverDid,
    CALLER_DOCUMENTS: JSON.stringify(chosen.callerDocuments),
    CELL_DID: chosen.cellDid,
    SETTERS: JSON.stringify(chosen.setters),
  };

  return chosen.kek.kind === "url"
    ? { ...vars, KEK_URL: chosen.kek.url }
    : vars;
};

export const declareStack = Effect.fn("Lockjaw.celldStack")(
  function* declareStack(chosen: Settings, build: Build) {
    const slice = yield* ObjectStore.Slice({
      home: chosen.host.home,
      instance: chosen.instance,
    });

    const bucket = yield* ObjectStore.Bucket("store", {
      credentials: chosen.credentials,
      dataRoot: chosen.dataRoot,
      host: chosen.host,
      instance: chosen.instance,
      name: chosen.bucket,
      portBase: chosen.portBase,
      purgeOnDelete: false,
      restartGate: false,
      slice: slice.sha256,
    });

    const binding = yield* RemoteFile("worker-bindings", {
      contentFrom: bindingSource(chosen.kek),
      mode: 0o600,
      path: Output.interpolate`${bucket.configuration}/worker-bindings.json`,
    });

    const node = yield* Celld.Node("celld", {
      bucket,
      host: chosen.host,
      instance: chosen.instance,
      portBase: chosen.portBase,
      prepared: [binding.sha256],
      purgeOnDelete: false,
      workerIPv4: chosen.host.tailnetIPv4,
    });

    const configuration = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(GeneratedConfiguration)
    )(build.configuration);

    const deployment = yield* Celld.Deployment("deployment", {
      ...build,
      binary: `${node.layout.bin}/celld`,
      bindingsFile: Output.all(node.unit.sha256, binding.path).pipe(
        Output.map(([, path]) => path)
      ),
      configuration: binding.sha256.pipe(
        Output.map((revision) =>
          JSON.stringify({
            ...configuration,
            vars: {
              ...configuration.vars,
              LOCKJAW_BINDINGS_REVISION: revision,
            },
          })
        )
      ),
      directory: `${node.layout.configuration}/deploy`,
      environmentFile: `${node.layout.configuration}/celld.env`,
      internalUrl: node.internalUrl,
      secretNames: secretNames(chosen.kek),
      workerUrl: chosen.workerUrl,
    });

    return {
      commit: deployment.commit,
      internalUrl: node.internalUrl,
      publicUrl: node.publicUrl,
      version: deployment.version,
    };
  }
);

export const celldStack = <
  E1,
  E2,
  E3,
  R1 extends StackServices,
  R2 extends StackServices,
  R3 extends StackServices,
>(
  load: Effect.Effect<Settings, E1, R1>,
  build: (chosen: Settings) => Effect.Effect<Build, E2, R2>,
  host: Layer.Layer<HostShell, E3, R3>
) =>
  Stack(
    "lockjaw-celld",
    {
      providers: Layer.mergeAll(
        ObjectStore.providers(),
        Celld.providers(),
        Celld.deploymentProvider()
      ).pipe(
        Layer.provide(host),
        Layer.provide(environmentSecrets),
        Layer.provide(sourceLayer.pipe(Layer.orDie)),
        Layer.provide(FetchHttpClient.layer),
        Layer.orDie
      ),
      state: withheldState(localState()),
    },
    Effect.gen(function* stack() {
      const path = yield* Path.Path;
      const root = path.resolve(import.meta.dirname, "../..");
      yield* prepareState(root, path.resolve(yield* dotAlchemyDirectory));
      const chosen = yield* load;

      return yield* declareStack(chosen, yield* build(chosen));
    }).pipe(Effect.orDie)
  );
