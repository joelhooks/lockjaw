import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { AlchemyContext } from "alchemy/AlchemyContext";
import { localState, State } from "alchemy/State";
import { Effect, Exit, FileSystem, Redacted } from "effect";
import { expect } from "vitest";

import { prepareState, withheldState } from "../state.ts";

it.effect(
  "keeps state external and private, refusing repository and symlink paths",
  () =>
    Effect.gen(function* custody() {
      const fs = yield* FileSystem.FileSystem;
      const temporary = yield* fs.makeTempDirectoryScoped();
      const root = `${temporary}/repo`;
      const directory = `${temporary}/external/alchemy`;

      yield* fs.makeDirectory(root);
      yield* prepareState(root, directory);
      expect((yield* fs.stat(directory)).mode % 0o1000).toBe(0o700);
      expect(
        yield* prepareState(root, `${root}/nested`).pipe(Effect.exit)
      ).toSatisfy(Exit.isFailure);
      yield* fs.symlink(root, `${temporary}/alias`);
      expect(
        yield* prepareState(root, `${temporary}/alias/nested`).pipe(Effect.exit)
      ).toSatisfy(Exit.isFailure);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect("withholds accidental secret outputs in persisted state", () =>
  Effect.gen(function* secretOutput() {
    const fs = yield* FileSystem.FileSystem;
    const directory = yield* fs.makeTempDirectoryScoped();
    const canary = "celld-state-test-secret";

    yield* Effect.gen(function* persist() {
      const state = yield* yield* State;

      yield* state.setOutput({
        stack: "lockjaw-celld",
        stage: "test",
        value: { secret: Redacted.make(canary) },
      });
    }).pipe(
      Effect.provide(withheldState(localState())),
      Effect.provideService(AlchemyContext, {
        adopt: false,
        dev: false,
        dotAlchemy: directory,
      })
    );

    const paths = yield* fs.readDirectory(directory, { recursive: true });
    const texts: string[] = [];

    for (const path of paths) {
      const file = `${directory}/${path}`;

      if ((yield* fs.stat(file)).type === "File") {
        texts.push(yield* fs.readFileString(file));
      }
    }

    expect(texts.join("\n")).toContain("withheld-by-secret-cell");
    expect(texts.join("\n")).not.toContain(canary);
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);
