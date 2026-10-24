#!/usr/bin/env node
import { readFile } from "node:fs/promises";

import { CredentialName, Policy, RunHandle } from "@lockjaw/domain";
import { Effect, Fiber, Option, Schema } from "effect";

import {
  approvalCommand,
  execute,
  jsonRequest,
  Client,
  responseBytes,
} from "./client.js";
import type { ClientTransport } from "./client.js";
import { ClientFailure, renderFailure, usage } from "./failure.js";
import { forward } from "./forward.js";
import { maxPassSeconds, signPass, workerDid } from "./identity.js";
import { keygen } from "./keygen.js";
import { help, parseOptions } from "./options.js";
import type { Options } from "./options.js";

const Batch = Schema.Array(
  Schema.Struct({ name: CredentialName, ...Policy.fields })
).check(Schema.isMinLength(1));

const output = Effect.fn("Cli.output")(function* output(
  response: Response,
  options: Options
) {
  const bytes = yield* responseBytes(response);
  const body = bytes.toString("utf-8");

  if (response.status >= 400 && options.command !== "fetch") {
    yield* Effect.sync(() => {
      process.stderr.write(`${body}\n`);
      process.exitCode = 1;
    });

    return;
  }

  if (response.status >= 400) {
    const refusal = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(
        Schema.Struct({
          error: Schema.Struct({
            next: Schema.String,
            what: Schema.String,
            why: Schema.String,
          }),
        })
      )
    )(body).pipe(Effect.option);

    if (Option.isSome(refusal)) {
      yield* Effect.sync(() => {
        process.stderr.write(`${body}\n`);
        process.exitCode = 1;
      });

      return;
    }
  }

  yield* Effect.sync(() => {
    if (options.command === "fetch") {
      process.stderr.write(`HTTP ${response.status} ${response.statusText}\n`);
      process.stdout.write(
        options.flags.json === true
          ? `${JSON.stringify({ body, headers: Object.fromEntries(response.headers), status: response.status })}\n`
          : bytes
      );
    } else {
      process.stdout.write(`${body}\n`);

      if (options.command === "set") {
        process.stderr.write(`Next: ${approvalCommand(options)}\n`);
      }
    }
  });
});

const batchApprove = Effect.fn("Cli.batchApprove")(function* batchApprove(
  client: ClientTransport,
  options: Options
) {
  const source = yield* Effect.tryPromise({
    catch: () =>
      usage(
        "cannot read approval batch",
        "sc approve --batch <policies.json> --identity-stdin"
      ),
    try: async () => await readFile(options.flags.batch ?? "", "utf-8"),
  });

  const entries = yield* Schema.decodeUnknownEffect(
    Schema.fromJsonString(Batch)
  )(source).pipe(
    Effect.mapError(() =>
      usage(
        "invalid approval batch",
        "sc approve --batch <policies.json> --identity-stdin"
      )
    )
  );

  for (const entry of entries) {
    const { name, ...policy } = entry;

    const response = yield* client.send(
      "approve",
      "/v1/approve",
      jsonRequest({ name, policy })
    );

    yield* output(response, options);

    if (response.status >= 400) {
      return;
    }
  }
});

const runTicket = Effect.fn("Cli.runTicket")(function* runTicket(
  options: Options
) {
  const next =
    "sc pass --desk <desk-name> --handle <run> --worker-key <did:key|public-jwk.json> --scope sh.secretcell.fetch[:<pattern>] [--ttl 600] > <pass-file>";

  if (process.stdout.isTTY) {
    return yield* usage("pipe the pass to a file", next);
  }

  const { flags } = options;
  const seconds = Number(flags.ttl ?? String(maxPassSeconds));

  if (
    flags.desk === undefined ||
    flags.handle === undefined ||
    !Schema.is(RunHandle)(flags.handle) ||
    (flags.scope?.length ?? 0) === 0 ||
    !Number.isInteger(seconds) ||
    seconds < 1 ||
    seconds > maxPassSeconds
  ) {
    return yield* usage(
      "pass needs --desk, --handle, at least one --scope, and a --ttl of 1 to 600 seconds",
      next
    );
  }

  const pass = yield* signPass(
    flags["identity-file"],
    process.env.SC_IDENTITY_JSON,
    {
      desk: flags.desk,
      run: flags.handle,
      scope: flags.scope ?? [],
      seconds,
      worker: yield* workerDid(flags["worker-key"] ?? ""),
    }
  );

  return yield* Effect.sync(() => {
    process.stdout.write(`${pass}\n`);
  });
});

const main = Effect.gen(function* main() {
  const options = yield* Effect.try({
    catch: (error) =>
      Schema.is(ClientFailure)(error) ? error : usage("invalid arguments"),
    try: () => parseOptions(process.argv.slice(2)),
  });

  if (options.command === "help" || options.flags.help === true) {
    yield* Effect.sync(() => {
      process.stdout.write(help);
    });

    return;
  }

  if (options.command === "keygen") {
    const identity = yield* keygen(
      options.flags["public-out"],

      process.stdout.isTTY
    );

    yield* Effect.sync(() => {
      process.stdout.write(identity);
    });

    return;
  }

  if (
    options.command === "run-ticket" ||
    options.flags["run-ticket"] !== undefined
  ) {
    yield* Effect.sync(() => {
      process.stderr.write(
        "Deprecated: run-ticket and --run-ticket become pass and --pass; this alias is retained for one release.\n"
      );
    });
  }

  if (options.command === "pass" || options.command === "run-ticket") {
    yield* runTicket(options);

    return;
  }

  yield* Effect.gen(function* authenticatedCommand() {
    const client = yield* Client;

    if (options.command === "forward") {
      const address = yield* forward(
        client,
        options.flags.listen,
        options.flags["upstream-host"]
      );

      yield* Effect.sync(() => {
        process.stderr.write(
          `sc forward listening on ${address.host}:${address.port}\n`
        );
      });

      return yield* Effect.never;
    }

    if (options.command === "approve" && options.flags.batch !== undefined) {
      return yield* batchApprove(client, options);
    }

    const response = yield* execute(client, options, process.stdin);

    return yield* output(response, options);
  }).pipe(Effect.provide(Client.layer(options, process.env)));
}).pipe(
  Effect.scoped,
  // oxlint-disable-next-line promise/prefer-await-to-then, promise/prefer-await-to-callbacks -- Effect.catch handles typed failures, not Promise callbacks.
  Effect.catch((error) =>
    Effect.sync(() => {
      const commands = new Set([
        "set",
        "approve",
        "fetch",
        "list",
        "describe",
        "revoke",
        "forward",
        "keygen",
        "rotate",
        "grant",
        "grants",
        "pass",
        "run-ticket",
      ]);

      const command =
        process.argv.slice(2).find((argument) => commands.has(argument)) ??
        "command";

      process.stderr.write(renderFailure(command, error));
      process.exitCode = error.code;
    })
  )
);

const fiber = Effect.runFork(main);

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    Effect.runFork(Fiber.interrupt(fiber));
  });
}
