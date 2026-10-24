import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { AlchemyContext } from "alchemy/AlchemyContext";
import { localState, State } from "alchemy/State";
import type { CreatingResourceState, PersistedState } from "alchemy/State";
import { Effect, Exit, FileSystem, Path, Redacted, Schema } from "effect";
import type { Layer } from "effect";
import { expect } from "vitest";

import { prepareState, WITHHELD, withheldState } from "../state.ts";
import { baseSettings, CANARY, compile } from "./fixture.ts";

const persisted = Effect.fn(function* persisted(directory: string) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const files = yield* fs.readDirectory(directory, { recursive: true });
  const texts = [];

  for (const file of files) {
    const location = path.join(directory, file);

    if ((yield* fs.stat(location)).type === "File") {
      texts.push(yield* fs.readFileString(location));
    }
  }

  return texts.join("\n");
});

const write = Effect.fn(function* write(
  layer: Layer.Layer<State, never, FileSystem.FileSystem | Path.Path>,
  value: PersistedState
) {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const directory = yield* fs.makeTempDirectoryScoped();
  const dotAlchemy = path.join(directory, "alchemy");

  const exit = yield* Effect.gen(function* store() {
    const state = yield* yield* State;

    yield* state.set({
      fqn: "cell",
      stack: "secret-cell-cloudflare",
      stage: "test",
      value,
    });

    return yield* state.get({
      fqn: "cell",
      stack: "secret-cell-cloudflare",
      stage: "test",
    });
  }).pipe(
    Effect.provide(layer),
    Effect.provideService(AlchemyContext, {
      adopt: false,
      dev: false,
      dotAlchemy,
    }),
    Effect.exit
  );

  return { exit, text: yield* persisted(directory) };
});

const resourceRecord = (
  props: CreatingResourceState["props"],
  bindings: CreatingResourceState["bindings"] = []
): CreatingResourceState => ({
  bindings,
  downstream: [],
  fqn: "cell",
  instanceId: "test",
  kind: "resource",
  logicalId: "cell",
  namespace: undefined,
  props,
  providerVersion: 0,
  resourceType: "Cloudflare.Worker",
  status: "creating",
});

const workerRecord = Effect.fn(function* workerRecord() {
  const stack = yield* compile(baseSettings);

  const props = yield* Schema.decodeUnknownEffect(
    Schema.Record(Schema.String, Schema.Unknown)
  )(stack.resources.cell?.Props);

  return resourceRecord(props, stack.bindings.cell);
});

it.effect(
  "persists the compiled Worker without the KEK, where plain local state would leak it",
  () =>
    Effect.gen(function* custody() {
      const record = yield* workerRecord();
      const plain = yield* write(localState(), record);

      expect(Exit.isSuccess(plain.exit)).toBe(true);
      expect(plain.text.includes(CANARY)).toBe(true);

      const guarded = yield* write(withheldState(localState()), record);

      expect(Exit.isSuccess(guarded.exit)).toBe(true);
      expect(guarded.text.includes(CANARY)).toBe(false);
      expect(guarded.text).toMatch(
        new RegExp(`"__redacted__":\\s*"${WITHHELD}"`, "u")
      );
      expect(guarded.text).toMatch(
        new RegExp(
          `"type":\\s*"secret_text",\\s*"name":\\s*"LOCKJAW_KEK",\\s*"text":\\s*"${WITHHELD}"`,
          "u"
        )
      );

      const read = Exit.isSuccess(guarded.exit)
        ? guarded.exit.value
        : undefined;

      expect(JSON.stringify(read).includes(CANARY)).toBe(false);

      const env = yield* Schema.decodeUnknownEffect(
        Schema.Struct({
          props: Schema.Struct({
            env: Schema.Struct({ LOCKJAW_KEK: Schema.Unknown }),
          }),
        })
      )(read);

      expect(Redacted.isRedacted(env.props.env.LOCKJAW_KEK)).toBe(true);
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

class Opaque {
  readonly secret = Redacted.make(CANARY);
}

it.effect(
  "refuses to write a secret hidden inside a class instance and writes nothing",
  () =>
    Effect.gen(function* hidden() {
      const result = yield* write(
        withheldState(localState()),
        resourceRecord({ hidden: new Opaque() })
      );

      expect(Exit.isFailure(result.exit)).toBe(true);
      expect(String(Exit.isFailure(result.exit) && result.exit.cause)).toMatch(
        /What: .*Why: .*Next: /su
      );
      expect(result.text).toBe("");
    }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect(
  "creates private external state and rejects repo paths and symlink aliases",
  () =>
    Effect.gen(function* privateState() {
      const fs = yield* FileSystem.FileSystem;
      const path = yield* Path.Path;
      const temporary = yield* fs.makeTempDirectoryScoped();
      const root = path.join(temporary, "repo");
      const directory = path.join(temporary, "external", "alchemy");
      const alias = path.join(temporary, "alias");

      yield* fs.makeDirectory(root);

      expect(yield* prepareState(root, directory)).toBe(
        yield* fs.realPath(directory)
      );
      expect((yield* fs.stat(directory)).mode % 0o1000).toBe(0o700);

      for (const invalid of [root, path.join(root, "nested")]) {
        expect(
          Exit.isFailure(yield* prepareState(root, invalid).pipe(Effect.exit))
        ).toBe(true);
      }

      yield* fs.symlink(root, alias);

      expect(
        Exit.isFailure(
          yield* prepareState(root, path.join(alias, "nested")).pipe(
            Effect.exit
          )
        )
      ).toBe(true);
      expect(yield* fs.exists(path.join(root, "nested"))).toBe(false);
    }).pipe(Effect.provide(NodeServices.layer))
);
