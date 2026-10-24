import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import path from "node:path";

import { Effect, Schema } from "effect";

import { executable } from "./harness.js";

export const ttyProcess = async (args: string[], env: NodeJS.ProcessEnv) => {
  const child = spawn(
    "python3",
    [
      path.resolve("packages/client/test/pty-runner.py"),
      process.execPath,
      executable,
      ...args,
    ],
    { env, stdio: ["ignore", "pipe", "pipe"] }
  );

  const chunks: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => {
    chunks.push(chunk);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    chunks.push(chunk);
  });
  await once(child, "close");

  return Buffer.concat(chunks).toString("utf-8");
};

const freePort = async () => {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();

  if (!Schema.is(Schema.Struct({ port: Schema.Int }))(address)) {
    throw new Error("missing port");
  }

  server.close();
  await once(server, "close");

  return address.port;
};

export const forwardProcess = Effect.fn("Test.forwardProcess")(
  function* forwardProcess(env: NodeJS.ProcessEnv) {
    const port = yield* Effect.promise(freePort);

    const child = yield* Effect.acquireRelease(
      Effect.sync(() =>
        spawn(
          process.execPath,
          [
            executable,
            "forward",
            "--listen",
            `127.0.0.1:${port}`,
            "--upstream-host",
            "api.example.com",
          ],
          { env, stdio: ["ignore", "pipe", "pipe"] }
        )
      ),
      (owned) =>
        Effect.promise(async () => {
          owned.kill("SIGTERM");
          await once(owned, "close");
        })
    );

    const output: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => {
      output.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      output.push(chunk);
    });

    yield* Effect.callback<null>((resume) => {
      let evidence = "";

      const onData = (chunk: Buffer) => {
        evidence += chunk.toString("utf-8");

        if (evidence.includes("sc forward listening")) {
          resume(Effect.succeed(null));
        }
      };

      const onExit = () => {
        resume(Effect.die("forward stopped before ready"));
      };

      child.stderr.on("data", onData);
      child.once("close", onExit);

      return Effect.sync(() => {
        child.stderr.off("data", onData);
        child.off("close", onExit);
      });
    });

    return {
      argv: child.spawnargs.join("\n"),
      text: () => Buffer.concat(output).toString("utf-8"),
      url: `http://127.0.0.1:${port}`,
    };
  }
);
