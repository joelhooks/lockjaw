import { readFile } from "node:fs/promises";

import {
  CredentialName,
  GitHubAppMetadata,
  GrantId,
  Grantee,
  Policy,
  Scope,
} from "@lockjaw/domain";
import { Context, Effect, Layer, Schema } from "effect";

import type { ClientError } from "./failure.js";
import { transport, usage } from "./failure.js";
import {
  directPassLive,
  identityKeyDid,
  loadSigner,
  passRun,
  readProtectedFile,
} from "./identity.js";
import { splitHeader, workerUrl } from "./options.js";
import type { Options } from "./options.js";
import { bothPassSources, readPassFile } from "./pass-file.js";
import type { CurrentPass } from "./pass-file.js";

interface PolicyInput {
  callers: string[] | undefined;
  hosts: string[] | undefined;
  placements: string[] | undefined;
  inject?: { header: string; template: string; basicUser?: string };
  ports?: number[];
}

interface SetBody {
  expiresAt: number | null;
  name: string;
  value: string;
  githubApp?: typeof GitHubAppMetadata.Type;
  policy?: typeof Policy.Type;
}

interface ScopeInput {
  credentials: string[];
  exp: number;
  grantees: string[];
  hosts: string[];
  ops: string[];
  routes?: { method: string; pathPrefix: string }[];
}

interface GrantInput {
  grantee: { desk: string; runHandle?: string };
  scope: ScopeInput;
}

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
const GrantBody = Schema.Struct({ grantee: Grantee, scope: Scope });

type GrantBody = typeof GrantBody.Type;

interface FetchBody {
  headers: { name: string; value: string }[];
  method: string;
  url: string;
  body?: string;
}

interface ApproveBody {
  name: string;
  policy: typeof Policy.Type;
  githubApp?: typeof GitHubAppMetadata.Type;
}

const requestHttp = async (
  url: string,
  path: string,
  init: RequestInit,
  token: string,
  pass: CurrentPass | null
) => {
  const headers = new Headers(init.headers);
  headers.set("x-sc-auth", token);

  if (pass !== null) {
    headers.set("x-sc-pass", pass.pass);
  }

  if (pass?.ticket !== undefined) {
    headers.set("x-sc-ticket", pass.ticket);
  }

  return await fetch(`${url}${path}`, {
    ...init,
    headers,
    redirect: "manual",
    signal: AbortSignal.timeout(60_000),
  });
};

export const readStdin = (stdin: NodeJS.ReadStream) =>
  Effect.tryPromise({
    catch: () =>
      usage("cannot read stdin", "sc set <name> --kind key < <value-file>"),
    try: async () => {
      const chunks: Buffer[] = [];

      try {
        for await (const chunk of stdin) {
          chunks.push(
            Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk))
          );
        }

        return Buffer.concat(chunks);
      } finally {
        for (const chunk of chunks) {
          chunk.fill(0);
        }
      }
    },
  });

export interface ClientTransport {
  readonly send: (
    operation: string,
    path: string,
    init?: RequestInit
  ) => Effect.Effect<Response, ClientError>;
}

export class Client extends Context.Service<Client, ClientTransport>()(
  "secret-cell/Client"
) {
  static readonly layer = (options: Options, env: NodeJS.ProcessEnv) =>
    Layer.effect(
      Client,
      Effect.gen(function* configure() {
        const url = yield* Effect.try({
          catch: () =>
            usage(
              "unsafe or missing Worker URL",
              "sc --url https://<cell-host> list"
            ),
          try: () => workerUrl(options.flags.url ?? env.SC_URL),
        });

        const audience = options.flags.audience ?? env.SC_AUDIENCE;

        if (audience === undefined || !audience.startsWith("did:")) {
          return yield* usage(
            "SC_AUDIENCE is missing or invalid",
            "sc --audience <worker-did> list"
          );
        }

        const sources =
          Number(options.flags["identity-file"] !== undefined) +
          Number(env.SC_IDENTITY_JSON !== undefined) +
          Number(options.flags["identity-stdin"] === true);

        if (sources !== 1) {
          return yield* usage(
            "exactly one identity source is required",
            "sc --identity-file <identity.json> list"
          );
        }

        let identityText = env.SC_IDENTITY_JSON;

        if (options.flags["identity-stdin"] === true) {
          const bytes = yield* readStdin(process.stdin);
          identityText = bytes.toString("utf-8");
          bytes.fill(0);
        }

        const passFlag = options.flags.pass ?? options.flags["run-ticket"];
        const passFile = env.SC_PASS_FILE;

        if (passFile !== undefined && passFlag !== undefined) {
          return yield* bothPassSources();
        }

        const keyDid =
          passFile === undefined
            ? undefined
            : yield* identityKeyDid(
                options.flags["identity-file"],
                identityText
              );

        const direct =
          passFlag === undefined
            ? undefined
            : (yield* readProtectedFile(passFlag, true)).trim();

        let runHandle: string | undefined;

        if (passFile !== undefined && keyDid !== undefined) {
          runHandle = (yield* readPassFile(passFile, keyDid)).run;
        } else if (direct !== undefined) {
          runHandle = yield* passRun(direct);
        }

        const sign = yield* loadSigner(
          options.flags["identity-file"],
          identityText,
          audience,
          runHandle
        );

        const currentPass = Effect.fn("Client.currentPass")(
          function* currentPass() {
            if (passFile !== undefined && keyDid !== undefined) {
              return yield* readPassFile(passFile, keyDid, runHandle);
            }

            if (direct === undefined) {
              return null;
            }

            yield* directPassLive(direct);

            return { pass: direct, run: runHandle ?? "", ticket: undefined };
          }
        );

        return Client.of({
          send: Effect.fn("Client.send")(function* send(
            operation: string,
            path: string,
            init: RequestInit = {}
          ) {
            const pass = yield* currentPass();
            const token = yield* sign(operation);

            return yield* Effect.tryPromise({
              catch: transport,
              try: async () => await requestHttp(url, path, init, token, pass),
            });
          }),
        });
      })
    );
}

const validName = (name: string) =>
  Schema.decodeUnknownEffect(CredentialName)(name).pipe(
    Effect.mapError(() => usage("invalid credential name"))
  );

const githubMetadata = Effect.fn("Client.githubMetadata")(
  function* githubMetadata(path: string | undefined) {
    if (path === undefined) {
      return null;
    }

    const text = yield* readProtectedFile(path, true);

    return yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(GitHubAppMetadata)
    )(text).pipe(
      Effect.mapError(() =>
        usage(
          "invalid GitHub App metadata",
          "sc set <name> --kind github-app --github-app-file <metadata.json> < <key.pem>"
        )
      )
    );
  }
);

export const policy = Effect.fn("Client.policy")(function* policy(
  options: Options,
  delegated: boolean
) {
  const { flags } = options;
  const template = flags.inject?.[0];

  if (
    (flags.host?.length ?? 0) === 0 ||
    (!delegated && (flags.caller?.length ?? 0) === 0) ||
    (flags.placement?.length ?? 0) === 0
  ) {
    return yield* usage(
      "approval requires hosts, callers and trusted issuing placements",
      "sc approve <name> --host <host> --caller <pattern> --placement <issuer> --inject 'Authorization: Bearer {value}'"
    );
  }

  const input: PolicyInput = {
    callers: flags.caller ?? [],
    hosts: flags.host,
    placements: flags.placement,
  };

  if (template !== undefined) {
    const header = yield* Effect.try({
      catch: () => usage("invalid injection template"),
      try: () => splitHeader(template),
    });

    input.inject = { header: header.name, template: header.value };

    if (flags["basic-user"] !== undefined) {
      input.inject.basicUser = flags["basic-user"];
    }
  } else if (flags["basic-user"] !== undefined) {
    return yield* usage("basic-user requires an inject template");
  }

  if (flags.ports !== undefined) {
    input.ports = flags.ports.flatMap((entry) => entry.split(",").map(Number));
  }

  return yield* Schema.decodeUnknownEffect(Policy)(input).pipe(
    Effect.mapError(() => usage("invalid approval policy"))
  );
});

const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

const repeat = (
  flag: string,
  values: readonly string[] | undefined,
  fallback: string
) =>
  (values ?? [fallback]).map((value) => ` --${flag} ${quote(value)}`).join("");

export const approvalCommand = (options: Options) =>
  `sc approve ${quote(options.operand)}${repeat("host", options.flags.host, "<approved-host>")}${repeat("caller", options.flags.caller, "<caller-pattern>")}${repeat("placement", options.flags.placement, "<trusted-issuer>")} --inject ${quote(options.flags.inject?.[0] ?? "Authorization: Bearer {value}")}`;

export const jsonRequest = (
  body:
    | SetBody
    | FetchBody
    | ApproveBody
    | GrantBody
    | { readonly name: string }
    | { readonly name: string; readonly value: string }
    | { readonly id: string }
): RequestInit => ({
  body: JSON.stringify(body),
  headers: { "content-type": "application/json" },
  method: "POST",
});

const setValue = Effect.fn("Client.setValue")(function* setValue(
  client: ClientTransport,
  options: Options,
  stdin: NodeJS.ReadStream
) {
  const { operand, flags } = options;
  yield* validName(operand);

  if (stdin.isTTY) {
    return yield* usage(
      "pipe the value in",
      "sc set <name> --kind key < <value-file>"
    );
  }

  if (flags.kind !== "key" && flags.kind !== "github-app") {
    return yield* usage("set requires --kind key or github-app");
  }

  if (flags.kind === "key" && flags["github-app-file"] !== undefined) {
    return yield* usage("key credentials do not take GitHub App metadata");
  }

  const githubApp = yield* githubMetadata(flags["github-app-file"]);

  if (flags.kind === "github-app" && githubApp === null) {
    return yield* usage(
      "github-app requires metadata",
      "sc set <name> --kind github-app --github-app-file <metadata.json> < <key.pem>"
    );
  }

  const expiresAt =
    flags["expires-at"] === undefined ? null : Date.parse(flags["expires-at"]);

  if (
    expiresAt !== null &&
    (!Number.isFinite(expiresAt) ||
      !/^\d{4}-\d\d-\d\dT/u.test(flags["expires-at"] ?? ""))
  ) {
    return yield* usage("expires-at must be an ISO timestamp");
  }

  const bytes = yield* readStdin(stdin);

  const body: SetBody = {
    expiresAt,
    name: operand,
    value: bytes.toString("utf-8"),
  };

  if (githubApp !== null) {
    body.githubApp = githubApp;
  }

  if (flags.placement !== undefined) {
    body.policy = yield* policy(options, true);
  }

  return yield* client.send("set", "/v1/set", jsonRequest(body)).pipe(
    Effect.ensuring(
      Effect.sync(() => {
        bytes.fill(0);
        body.value = "";
      })
    )
  );
});

const rotateValue = Effect.fn("Client.rotateValue")(function* rotateValue(
  client: ClientTransport,
  options: Options,
  stdin: NodeJS.ReadStream
) {
  yield* validName(options.operand);

  if (stdin.isTTY) {
    return yield* usage(
      "pipe the new value in",
      "sc rotate <name> < <new-value-file>"
    );
  }

  const bytes = yield* readStdin(stdin);
  const body = { name: options.operand, value: bytes.toString("utf-8") };

  return yield* client.send("rotate", "/v1/rotate", jsonRequest(body)).pipe(
    Effect.ensuring(
      Effect.sync(() => {
        bytes.fill(0);
        body.value = "";
      })
    )
  );
});

const grantNext =
  "sc grant <desk-name> [--run <handle>] --credential <pattern> --host <host> --op use --exp 2026-10-20T00:00:00Z";

export const grantBody = Effect.fn("Client.grantBody")(function* grantBody(
  options: Options
) {
  const { flags, operand } = options;
  const exp = Date.parse(flags.exp ?? "");

  if (!Number.isFinite(exp) || !/^\d{4}-\d\d-\d\dT/u.test(flags.exp ?? "")) {
    return yield* usage("grant requires --exp as an ISO timestamp", grantNext);
  }

  const input: GrantInput = {
    grantee: { desk: operand },
    scope: {
      credentials: flags.credential ?? [],
      exp,
      grantees: flags.grantee ?? [],
      hosts: flags.host ?? [],
      ops: flags.op ?? [],
    },
  };

  if (flags.run !== undefined) {
    input.grantee.runHandle = flags.run;
  }

  if (flags.route !== undefined) {
    input.scope.routes = flags.route.map((text) => {
      const [method = "", pathPrefix = ""] = text.trim().split(/\s+/u);

      return { method: method.toUpperCase(), pathPrefix };
    });
  }

  return yield* Schema.decodeUnknownEffect(GrantBody)(input).pipe(
    Effect.mapError(() =>
      usage(
        "grant needs at least one --credential and --op, valid hosts, and routes as 'METHOD /prefix'",
        grantNext
      )
    )
  );
});

const fetchTarget = Effect.fn("Client.fetchTarget")(function* fetchTarget(
  client: ClientTransport,
  options: Options,
  stdin: NodeJS.ReadStream
) {
  const { operand, flags } = options;

  if (!URL.canParse(operand) || new URL(operand).protocol !== "https:") {
    return yield* usage("fetch requires an HTTPS target URL");
  }

  const headers = yield* Effect.try({
    catch: () => usage("invalid request headers"),
    try: () => (flags.header ?? []).map(splitHeader),
  });

  const body: FetchBody = {
    headers,
    method: flags.method ?? (flags.data === undefined ? "GET" : "POST"),
    url: operand,
  };

  if (flags.data === "-") {
    const bytes = yield* readStdin(stdin);
    body.body = bytes.toString("utf-8");
    bytes.fill(0);
  } else if (flags.data !== undefined) {
    if (!flags.data.startsWith("@")) {
      return yield* usage("data must be @file or -");
    }

    body.body = yield* Effect.tryPromise({
      catch: () =>
        usage(
          "cannot read request body",
          "sc fetch <https-url> --data @<body-file>"
        ),
      try: async () => await readFile(flags.data?.slice(1) ?? "", "utf-8"),
    });
  }

  return yield* client.send("fetch", "/v1/fetch", jsonRequest(body));
});

export const execute = Effect.fn("Client.execute")(function* execute(
  client: ClientTransport,
  options: Options,
  stdin: NodeJS.ReadStream
) {
  const { command, operand, flags } = options;

  switch (command) {
    case "set": {
      return yield* setValue(client, options, stdin);
    }

    case "fetch": {
      return yield* fetchTarget(client, options, stdin);
    }

    case "approve": {
      yield* validName(operand);
      const grants = yield* policy(options, false);
      const githubApp = yield* githubMetadata(flags["github-app-file"]);
      const body: ApproveBody = { name: operand, policy: grants };

      if (githubApp !== null) {
        body.githubApp = githubApp;
      }

      return yield* client.send("approve", "/v1/approve", jsonRequest(body));
    }

    case "list": {
      return yield* client.send("list", "/v1/list", { method: "GET" });
    }

    case "describe": {
      yield* validName(operand);

      return yield* client.send(
        "describe",
        `/v1/describe?name=${encodeURIComponent(operand)}`,
        { method: "GET" }
      );
    }

    case "revoke": {
      yield* validName(operand);

      return yield* client.send(
        "revoke",
        "/v1/revoke",
        jsonRequest({ name: operand })
      );
    }

    case "rotate": {
      return yield* rotateValue(client, options, stdin);
    }

    case "grant": {
      return yield* client.send(
        "grant",
        "/v1/grant",
        jsonRequest(yield* grantBody(options))
      );
    }

    case "grant-revoke": {
      const id = yield* Schema.decodeUnknownEffect(GrantId)(operand).pipe(
        Effect.mapError(() =>
          usage("invalid grant id", "sc grants, then sc grant revoke <g_...>")
        )
      );

      return yield* client.send(
        "grant.revoke",
        "/v1/grant/revoke",
        jsonRequest({ id })
      );
    }

    case "grants": {
      return yield* client.send("grant.list", "/v1/grants", { method: "GET" });
    }

    default: {
      return yield* usage("unsupported command");
    }
  }
});

export const responseBytes = (response: Response) =>
  Effect.tryPromise({
    catch: transport,
    try: async () => Buffer.from(await response.arrayBuffer()),
  });
