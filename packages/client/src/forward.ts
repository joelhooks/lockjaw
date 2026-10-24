import { once } from "node:events";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";

import { Effect } from "effect";

import type { ClientTransport } from "./client.js";
import { renderFailure, transport, usage } from "./failure.js";
import { listenAddress } from "./options.js";

const hopHeaders = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "expect",
]);

const forwardedHeaders = (request: IncomingMessage) => {
  const headers = new Headers();

  const connectionHeaders = new Set(
    (request.headers.connection ?? "")
      .toLowerCase()
      .split(",")
      .map((name) => name.trim())
  );

  for (const [name, value] of Object.entries(request.headers)) {
    if (
      hopHeaders.has(name) ||
      connectionHeaders.has(name) ||
      name.startsWith("x-sc-") ||
      value === undefined
    ) {
      continue;
    }

    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }

  return headers;
};

const proxy = async (
  client: ClientTransport,
  host: string,
  request: IncomingMessage,
  response: ServerResponse
) => {
  const method = request.method ?? "GET";
  const chunks: Buffer[] = [];

  try {
    for await (const chunk of request) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk)));
    }

    const body = Buffer.concat(chunks);

    try {
      const path = request.url ?? "/";

      if (
        !path.startsWith("/") ||
        path.startsWith("//") ||
        /[\r\n\0#]/u.test(path)
      ) {
        throw usage("forward requires an origin-form path");
      }

      const init: RequestInit = { headers: forwardedHeaders(request), method };

      if (method !== "GET" && method !== "HEAD") {
        init.body = body;
      }

      const upstream = await Effect.runPromise(
        client.send("fetch", `/v1/u/${host}${path}`, init)
      );

      const headers = new Headers(upstream.headers);

      for (const name of hopHeaders) {
        headers.delete(name);
      }

      response.writeHead(upstream.status, Object.fromEntries(headers));

      if (upstream.body !== null && method !== "HEAD") {
        for await (const chunk of upstream.body) {
          if (!response.write(chunk)) {
            await once(response, "drain");
          }
        }
      }

      response.end();
    } finally {
      body.fill(0);
    }
  } catch {
    if (response.headersSent) {
      response.destroy();
    } else {
      response.writeHead(502, { "content-type": "text/plain" });
      response.end(renderFailure("forward", transport()));
    }
  } finally {
    for (const chunk of chunks) {
      chunk.fill(0);
    }
  }
};

export const forward = Effect.fn("Client.forward")(function* forward(
  client: ClientTransport,
  listen: string | undefined,
  upstreamHost: string | undefined
) {
  const address = yield* Effect.try({
    catch: () =>
      usage(
        "forward requires a loopback bind",
        "sc forward --listen 127.0.0.1:8080 --upstream-host <approved-host>"
      ),
    try: () => listenAddress(listen),
  });

  if (
    upstreamHost === undefined ||
    !/^[a-z0-9.-]+(?::[0-9]+)?$/u.test(upstreamHost)
  ) {
    return yield* usage("invalid upstream host");
  }

  const server = createServer((request, response) => {
    void proxy(client, upstreamHost, request, response);
  });

  server.requestTimeout = 60_000;
  server.headersTimeout = 30_000;
  yield* Effect.acquireRelease(
    Effect.tryPromise({
      catch: transport,
      try: async () => {
        server.listen(address.port, address.host);
        await once(server, "listening");

        return server;
      },
    }),
    (owned) =>
      Effect.promise(async () => {
        owned.closeAllConnections();
        await owned[Symbol.asyncDispose]();
      })
  );

  return address;
});
