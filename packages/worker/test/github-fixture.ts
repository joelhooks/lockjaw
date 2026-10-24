// oxlint-disable typescript/promise-function-async -- Node HTTPS callbacks implement the injected transport.
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, verify, randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer, request as httpsRequest } from "node:https";
import { tmpdir } from "node:os";
import path from "node:path";

import { CredentialName, Host } from "@lockjaw/domain";
import {
  Clock,
  DateTime,
  Effect,
  Logger,
  Option,
  Schema,
  Stream,
} from "effect";

import type { GatewayFault } from "../src/fault.js";
import { boundaryFault } from "../src/fault.js";
import type { UpstreamResponse } from "../src/upstream.js";
import { Upstream } from "../src/upstream.js";
import { setupWith } from "./fixtures.js";

export const githubName = CredentialName.make("shitrat-github");

export const githubMetadata = {
  appId: "12345",
  installations: { "example-org": 9876, other: 5432 },
};

export const githubGrants = {
  callers: ["test/*"],
  hosts: [Host.make("api.github.com"), Host.make("github.com")],
  inject: {
    basicUser: "x-access-token",
    header: "authorization",
    template: "Bearer {value}",
  },
  placements: ["test-host"],
};

export const githubSetup = Effect.gen(function* githubSetup() {
  const directory = mkdtempSync(path.join(tmpdir(), "sc-github-https-"));
  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      rmSync(directory, { recursive: true });
    })
  );
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      path.join(directory, "tls-key.pem"),
      "-out",
      path.join(directory, "tls-cert.pem"),
      "-subj",
      "/CN=localhost",
      "-days",
      "1",
    ],
    { stdio: "ignore" }
  );
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });

  const pem = pair.privateKey
    .export({ format: "pem", type: "pkcs8" })
    .toString();

  const pkcs1 = pair.privateKey
    .export({ format: "pem", type: "pkcs1" })
    .toString();

  const tokens: string[] = [];
  const installationPaths: string[] = [];
  const claims: { exp: number; iat: number; iss: string }[] = [];
  const received: { host: string; authorization: string; path: string }[] = [];
  let mints = 0;
  let status = 201;
  let failNext = 0;
  let signaturesValid = true;

  const Claims = Schema.Struct({
    exp: Schema.Int,
    iat: Schema.Int,
    iss: Schema.String,
  });

  const verifyJwt = (jwt: string) => {
    const [header, payload, signature] = jwt.split(".");

    if (
      header === undefined ||
      payload === undefined ||
      signature === undefined
    ) {
      return false;
    }

    const decoded = Schema.decodeUnknownOption(Schema.fromJsonString(Claims))(
      Buffer.from(payload, "base64url").toString()
    );

    if (Option.isNone(decoded)) {
      return false;
    }

    const decodedHeader = Schema.decodeOption(
      Schema.fromJsonString(
        Schema.Struct({
          alg: Schema.Literal("RS256"),
          typ: Schema.Literal("JWT"),
        })
      )
    )(Buffer.from(header, "base64url").toString());

    if (Option.isNone(decodedHeader)) {
      return false;
    }

    claims.push(decoded.value);

    return verify(
      "RSA-SHA256",
      Buffer.from(`${header}.${payload}`),
      pair.publicKey,
      Buffer.from(signature, "base64url")
    );
  };

  const server = createServer(
    {
      cert: readFileSync(path.join(directory, "tls-cert.pem")),
      key: readFileSync(path.join(directory, "tls-key.pem")),
    },
    (req, res) => {
      const authorization = req.headers.authorization ?? "";

      if (req.url?.endsWith("/access_tokens") === true) {
        installationPaths.push(`${req.method ?? ""} ${req.url ?? ""}`);
        mints += 1;
        const jwt = authorization.slice(7);
        signaturesValid &&= verifyJwt(jwt);
        const code = failNext > 0 ? 503 : status;
        failNext = Math.max(0, failNext - 1);
        res.writeHead(code, { "content-type": "application/json" });

        if (code !== 201) {
          res.end(
            JSON.stringify({ message: `${pem}${jwt}${tokens.join("")}` })
          );

          return;
        }

        const token = `SC_INSTALLATION_CANARY_${randomUUID()}`;
        tokens.push(token);
        const last = claims.at(-1);
        res.end(
          JSON.stringify({
            expires_at: DateTime.formatIso(
              DateTime.makeUnsafe(((last?.iat ?? 0) + 60 + 3600) * 1000)
            ),
            token,
          })
        );

        return;
      }

      received.push({
        authorization,
        host: req.headers.host ?? "",
        path: req.url ?? "",
      });
      res.writeHead(200, { "x-echo": authorization });
      res.write(authorization.slice(0, 19));
      res.end(authorization.slice(19));
    }
  );

  yield* Effect.addFinalizer(() =>
    Effect.callback<true>((resume) => {
      server.close(() => {
        resume(Effect.succeed(true));
      });
    })
  );
  yield* Effect.callback<true, GatewayFault>((resume) => {
    server.once("error", () => {
      resume(Effect.fail(boundaryFault()));
    });
    server.listen(0, "127.0.0.1", () => {
      resume(Effect.succeed(true));
    });
  });
  const address = server.address();

  if (!Schema.is(Schema.Struct({ port: Schema.Int }))(address)) {
    return yield* boundaryFault();
  }

  const upstream = Upstream.testLayer({
    send: (outgoing) =>
      Effect.callback<UpstreamResponse, GatewayFault>((resume) => {
        const url = new URL(outgoing.url);

        const headers = Object.fromEntries(
          outgoing.headers.map((entry) => [entry.name, entry.value])
        );

        headers.host = url.host;

        const fail = () => {
          resume(Effect.fail(boundaryFault()));
        };

        const request = httpsRequest(
          {
            headers,
            hostname: "127.0.0.1",
            method: outgoing.method,
            path: `${url.pathname}${url.search}`,
            port: address.port,
            rejectUnauthorized: false,
          },
          (response) => {
            const chunks: Buffer[] = [];
            response.on("data", (chunk: Buffer) => {
              chunks.push(chunk);
            });
            response.on("error", fail);
            response.on("end", () => {
              resume(
                Effect.succeed({
                  body: Stream.make(new Uint8Array(Buffer.concat(chunks))),
                  headers: Object.entries(response.headers).flatMap(
                    ([name, value]) =>
                      value === undefined
                        ? []
                        : [
                            {
                              name,
                              value: Array.isArray(value)
                                ? value.join(",")
                                : value,
                            },
                          ]
                  ),
                  status: response.statusCode ?? 500,
                  statusText: response.statusMessage ?? "",
                  url: outgoing.url,
                })
              );
            });
          }
        );

        request.on("error", fail);
        request.end(outgoing.body);

        return Effect.sync(() => {
          request.destroy();
        });
      }),
  });

  const logs: string[] = [];

  const logger = Logger.make<unknown, number>((entry) =>
    logs.push(JSON.stringify({ cause: entry.cause, message: entry.message }))
  );

  const fixture = yield* setupWith({
    clock: yield* Clock.clockWith(Effect.succeed),
    credentialName: githubName,
    logger,
    upstream,
  });

  const set = (value = pem, metadata = githubMetadata) =>
    Effect.gen(function* setGithub() {
      const response = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ githubApp: metadata, name: githubName, value }),
        yield* fixture.token("sh.secretcell.set")
      );

      return {
        status: response.status,
        text: yield* Effect.promise(() => response.text()),
      };
    });

  const approve = (metadata?: typeof githubMetadata) =>
    Effect.gen(function* approveGithub() {
      return yield* fixture.call(
        "/v1/approve",
        JSON.stringify({
          githubApp: metadata,
          name: githubName,
          policy: githubGrants,
        }),
        yield* fixture.token("sh.secretcell.approve")
      );
    });

  const fetch = (basic = false, owner = "example-org") =>
    Effect.gen(function* fetchGithub() {
      const placeholder = basic
        ? `{{secret-basic:user=x-access-token,password=shitrat-github/${owner}}}`
        : `Bearer {{secret:shitrat-github/${owner}}}`;

      const signed = yield* fixture.token();

      const response = basic
        ? yield* fixture.call(
            "/v1/u/github.com/example-org/repo.git/info/refs?service=git-upload-pack",
            undefined,
            signed,
            "GET",
            { authorization: placeholder }
          )
        : yield* fixture.call(
            "/v1/fetch",
            JSON.stringify({
              headers: [{ name: "authorization", value: placeholder }],
              method: "GET",
              url: "https://api.github.com/user",
            }),
            signed
          );

      return {
        headers: JSON.stringify([...response.headers]),
        status: response.status,
        text: yield* Effect.promise(() => response.text()),
      };
    });

  return {
    ...fixture,
    approve,
    claims,
    failOnce: () => {
      failNext = 1;
    },
    fetch,
    installationPaths,
    logs,
    mints: () => mints,
    pem,
    pkcs1,
    received,
    set,
    setStatus: (code: number) => {
      status = code;
    },
    signaturesValid: () => signaturesValid,
    tokens,
    upstream,
  };
});
