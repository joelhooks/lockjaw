import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";

import { EchoRedactor, Fill, Policy } from "@lockjaw/gateway-rules";
import { Effect, Layer, Schema, Stream } from "effect";

import { CallerAuth, ClaimsSchema } from "../../worker/src/caller-auth.js";
import { handle } from "../../worker/src/gateway.js";
import type { Bindings, CellId } from "../../worker/src/gateway.js";
import { Upstream } from "../../worker/src/upstream.js";
import { canary, name, setup } from "../../worker/test/fixtures.js";

export const executable = path.resolve("packages/client/dist/sc.js");

export const audience = "did:web:cell.invalid";

export const temporary = Effect.acquireRelease(
  Effect.promise(async () => await mkdtemp(path.join(tmpdir(), "sc-client-"))),
  (dir) =>
    Effect.promise(async () => {
      await rm(dir, { recursive: true });
    })
);

export const identity = Effect.fn("Test.identity")(function* identity(
  did: string,
  displayName?: string
) {
  const pair = yield* Effect.promise(
    async () =>
      await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      )
  );

  const signing = yield* Effect.promise(
    async () => await crypto.subtle.exportKey("jwk", pair.privateKey)
  );

  const publicKeyJwk = yield* Effect.promise(
    async () => await crypto.subtle.exportKey("jwk", pair.publicKey)
  );

  return {
    d: signing.d ?? "",
    document: {
      authentication: [`${did}#atproto`],
      id: did,
      issuer: "test-host",
      name: displayName ?? "test/agent",
      verificationMethod: [
        { controller: did, id: `${did}#atproto`, publicKeyJwk },
      ],
    },
    json: JSON.stringify({ did, signing }),
    publicJwk: publicKeyJwk,
    signing,
  };
});

export const runProcess = async (
  args: string[],
  input: string,
  env: NodeJS.ProcessEnv
) => {
  const child = spawn(process.execPath, [executable, ...args], {
    env,
    stdio: ["pipe", "pipe", "pipe"],
  });

  const stdout: Buffer[] = [];
  const stderr: Buffer[] = [];
  child.stdout.on("data", (chunk: Buffer) => {
    stdout.push(chunk);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr.push(chunk);
  });
  // oxlint-disable-next-line eslint/no-empty-function -- A CLI may refuse before consuming its piped stdin.
  child.stdin.on("error", () => {});
  child.stdin.end(input);
  await once(child, "close");
  const code = child.exitCode;

  return {
    argv: child.spawnargs.join("\n"),
    code,
    stderr: Buffer.concat(stderr).toString("utf-8"),
    stdout: Buffer.concat(stdout).toString("utf-8"),
  };
};

export const decodeClaims = (token: string) =>
  Schema.decodeUnknownSync(Schema.fromJsonString(ClaimsSchema))(
    Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf-8")
  );

const bridge = async (
  incoming: IncomingMessage,
  outgoing: ServerResponse,
  dispatch: (request: Request) => Promise<Response>
) => {
  try {
    const chunks: Buffer[] = [];

    for await (const chunk of incoming) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    }

    const init: RequestInit = {
      headers: new Headers(
        Object.entries(incoming.headers).flatMap(([headerName, value]) =>
          value === undefined
            ? []
            : [[headerName, Array.isArray(value) ? value.join(", ") : value]]
        )
      ),
      method: incoming.method ?? "GET",
    };

    if (!["GET", "HEAD"].includes(init.method ?? "GET")) {
      init.body = Buffer.concat(chunks);
    }

    const response = await dispatch(
      new Request(`http://127.0.0.1${incoming.url ?? "/"}`, init)
    );

    outgoing.writeHead(response.status, Object.fromEntries(response.headers));
    outgoing.end(Buffer.from(await response.arrayBuffer()));
  } catch {
    outgoing.writeHead(500);
    outgoing.end("test bridge failed");
  }
};

const invokeWorker = async (
  request: Request,
  env: Bindings,
  layers: Layer.Layer<CallerAuth | Fill | EchoRedactor | Policy | Upstream>
) => await Effect.runPromise(handle(request, env).pipe(Effect.provide(layers)));

export const startWorker = Effect.fn("Test.startWorker")(function* startWorker(
  documents: string,
  approverDid: string
) {
  const fixture = yield* setup;
  const tokens: string[] = [];
  const claims: (typeof ClaimsSchema.Type)[] = [];

  const env = {
    ...fixture.env,
    APPROVER_DID: approverDid,
    CREDENTIAL: {
      ...fixture.env.CREDENTIAL,
      get: (id: CellId) => {
        const stub = fixture.env.CREDENTIAL.get(id);

        return {
          ...stub,
          describe: async () =>
            id.toString() === name
              ? await stub.describe()
              : {
                  ok: true as const,
                  value: {
                    lifecycle: undefined,
                    meta: undefined,
                    policy: undefined,
                    version: 0,
                  },
                },
        };
      },
    },
  };

  const layers = Layer.mergeAll(
    CallerAuth.layer(documents, audience),
    Fill.layer,
    EchoRedactor.layer,
    Policy.layer,
    Upstream.testLayer({
      send: (request) =>
        Effect.sync(() => {
          fixture.received.push(request);

          return {
            body: Stream.fromIterable([
              canary.slice(0, 11),
              canary.slice(11),
            ]).pipe(Stream.map((text) => new TextEncoder().encode(text))),
            headers: [{ name: "x-echo", value: canary }],
            status: 200,
            statusText: "OK",
            url: request.url,
          };
        }),
    })
  );

  const dispatch = async (request: Request) => {
    const token = request.headers.get("x-sc-auth") ?? "";
    tokens.push(token);
    claims.push(decodeClaims(token));

    return await invokeWorker(request, env, layers);
  };

  return { claims, dispatch, env, fixture, layers, tokens };
});

export const serve = Effect.fn("Test.serve")(function* serve(
  dispatch: (request: Request) => Promise<Response>
) {
  const server = createServer((request, response) => {
    void bridge(request, response, dispatch);
  });

  yield* Effect.acquireRelease(
    Effect.promise(async () => {
      server.listen(0, "127.0.0.1");
      await once(server, "listening");

      return server;
    }),
    (owned) =>
      Effect.promise(async () => {
        owned.closeAllConnections();
        await owned[Symbol.asyncDispose]();
      })
  );
  const address = server.address();

  if (!Schema.is(Schema.Struct({ port: Schema.Int }))(address)) {
    return yield* Effect.die("no loopback address");
  }

  return `http://127.0.0.1:${address.port}`;
});

export const loopbackFetch = async (url: string, init: RequestInit) =>
  await fetch(url, init);
