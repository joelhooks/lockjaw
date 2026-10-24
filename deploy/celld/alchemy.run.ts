import { prepareDeployment, Ssh } from "@rat-king/alchemy-nest";
import { Effect, Layer, Path } from "effect";
import { ChildProcess, ChildProcessSpawner } from "effect/process";

import wrangler from "../../packages/worker/wrangler.json" with { type: "json" };
import { refusal } from "./config.ts";
import type { Settings } from "./config.ts";
import { inputs } from "./inputs.ts";
import { celldStack, publicVars } from "./stack.ts";

export const build = Effect.fn("Lockjaw.celldBuild")(function* build(
  chosen: Settings
) {
  const path = yield* Path.Path;
  const spawner = yield* ChildProcessSpawner.ChildProcessSpawner;
  const root = path.resolve(import.meta.dirname, "../..");

  const commit = yield* spawner
    .string(ChildProcess.make("git", ["rev-parse", "HEAD"], { cwd: root }))
    .pipe(Effect.map((text) => text.trim()));

  if (!/^[a-f0-9]{40}$/u.test(commit)) {
    return yield* refusal(
      "Source commit is invalid.",
      "The bundle requires a Git identity.",
      "Run from a committed checkout."
    );
  }

  return yield* prepareDeployment(
    path.join(import.meta.dirname, "worker.ts"),
    {
      compatibility_date: wrangler.compatibility_date,
      compatibility_flags: [],
      durable_objects: wrangler.durable_objects,
      migrations: wrangler.migrations,
      name: chosen.workerName,
    },
    { commit, vars: publicVars(chosen), version: commit }
  );
});

const host = Layer.unwrap(
  inputs.pipe(
    Effect.map((chosen) =>
      Ssh.layer(chosen.host, {
        dataRoot: chosen.dataRoot,
        instance: chosen.instance,
        portBase: chosen.portBase,
      })
    )
  )
);

export default celldStack(inputs, build, host);
