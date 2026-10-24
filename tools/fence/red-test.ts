import { NodeRuntime, NodeServices } from "@effect/platform-node";
import { Console, Effect, FileSystem, Path } from "effect";

import { instanceLiterals } from "./rules.ts";
import { execute, FenceError, loadInstance } from "./scan.ts";

const proof = Effect.gen(function* proof() {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const inventory = yield* loadInstance({ generic: false });

  if (inventory === null) {
    return yield* new FenceError({
      reason: "Inventory required for red proof.",
    });
  }

  const literal = instanceLiterals(inventory)
    .flatMap(([, values]) => values)
    .find((value) => value.length >= 8);

  if (literal === undefined) {
    return yield* new FenceError({
      reason: "No suitable inventory literal for red proof.",
    });
  }

  const planted = yield* fs.makeTempFileScoped({
    directory: ".",
    prefix: "fence-red-proof-",
  });

  yield* fs.writeFileString(planted, `public canary\n${literal}\n`);

  const result = yield* execute({
    args: ["fence"],
    cwd: ".",
    executable: "pnpm",
  });

  const diagnostic = new TextDecoder().decode(
    Buffer.concat([result.bytes, result.stderrBytes])
  );

  if (
    result.code === 0 ||
    !diagnostic.includes(path.basename(planted)) ||
    !diagnostic.includes("rule=instance-") ||
    diagnostic.toLowerCase().includes(literal.toLowerCase())
  ) {
    return yield* new FenceError({
      reason: "Red proof failed or unsafe diagnostic; output suppressed.",
    });
  }

  yield* Console.log(diagnostic);
  yield* Console.log(
    "Red proof passed: planted inventory literal rejected; matched value absent from diagnostic."
  );

  return true;
}).pipe(Effect.scoped);

NodeRuntime.runMain(
  proof.pipe(
    Effect.matchEffect({
      onFailure: () =>
        Console.error(
          "path=<red-proof> line=0 rule=red-proof\nWhy: the inventory red proof failed; details suppressed.\nNext: check inventory access and the fence, then rerun node tools/fence/red-test.ts."
        ).pipe(
          Effect.andThen(
            Effect.sync(() => {
              process.exitCode = 1;
            })
          )
        ),
      onSuccess: () => Effect.void,
    }),
    Effect.provide(NodeServices.layer)
  )
);
