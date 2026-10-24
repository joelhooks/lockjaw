import { isIP } from "node:net";
import { parseArgs } from "node:util";

import { Schema } from "effect";

import { ClientFailure, usage } from "./failure.js";

export const help = `sc set <name> --kind key|github-app [--expires-at ISO] [--host HOST --caller PATTERN --placement ISSUER --inject 'Header: template']
sc approve <name> --host HOST --caller PATTERN --placement ISSUER [--ports 8443,9443] [--inject 'Header: Bearer {value}']
sc fetch <https-url> [-X METHOD] [-H 'Name: value'] [--data @file|-] [--json]
sc approve --batch <policies.json> --identity-stdin\nsc keygen --public-out <document.json> (stdout must be piped)\nsc list | describe <name> | revoke <name>
sc forward --listen 127.0.0.1:<port> --upstream-host <host>
sc rotate <name> < <new-value-file>
sc grant <desk-name> [--run <handle>] --credential PATTERN --host HOST --op use|describe|set|rotate|revoke|grant --exp ISO [--grantee PATTERN] [--route 'GET /prefix']
sc grant revoke <grant-id> | sc grants
sc pass --desk <desk-name> --handle <run> --worker-key <did:key|public-jwk.json> --scope <lxm[:pattern]> [--ttl <=600]   (desk side; prints a worker pass)
Workers: SC_PASS_FILE=<runtime pass file> sc ... (or sc --pass <desk-minted pass>, never both) with SC_IDENTITY_JSON holding {did: <desk DID>, signing: <ephemeral P-256 JWK>} in memory, never on disk
Delegated set: sc set <name> --kind key --host HOST --placement ISSUER [--caller PATTERN] sends a policy clipped to your grant.
Global: --url URL --audience DID --identity-file PATH (or SC_URL, SC_AUDIENCE, SC_IDENTITY_JSON)
GitHub App metadata only: --github-app-file PATH. Pipe keys and values through stdin.
Repeat --host, --caller, --placement and -H for multiple entries. Placements are trusted issuer names from the Worker's callers file.
`;

const optionSpec = {
  audience: { type: "string" },
  "basic-user": { type: "string" },
  batch: { type: "string" },
  caller: { multiple: true, type: "string" },
  credential: { multiple: true, type: "string" },
  data: { type: "string" },
  desk: { type: "string" },
  exp: { type: "string" },
  "expires-at": { type: "string" },
  "github-app-file": { type: "string" },
  grantee: { multiple: true, type: "string" },
  handle: { type: "string" },
  header: { multiple: true, short: "H", type: "string" },
  help: { type: "boolean" },
  host: { multiple: true, type: "string" },
  "identity-file": { type: "string" },
  "identity-stdin": { type: "boolean" },
  inject: { multiple: true, type: "string" },
  json: { type: "boolean" },
  kind: { type: "string" },
  listen: { type: "string" },
  method: { short: "X", type: "string" },
  op: { multiple: true, type: "string" },
  pass: { type: "string" },
  placement: { multiple: true, type: "string" },
  ports: { multiple: true, type: "string" },
  "public-out": { type: "string" },
  route: { multiple: true, type: "string" },
  run: { type: "string" },
  "run-ticket": { type: "string" },
  scope: { multiple: true, type: "string" },
  ttl: { type: "string" },
  "upstream-host": { type: "string" },
  url: { type: "string" },
  "worker-key": { type: "string" },
} as const;

const commands = new Set([
  "help",
  "keygen",
  "set",
  "approve",
  "fetch",
  "list",
  "describe",
  "revoke",
  "forward",
  "rotate",
  "grant",
  "grants",
  "pass",
  "run-ticket",
]);

const stdinIdentityCommands = new Set(["approve", "grant"]);

const namedCommands = new Set([
  "set",
  "fetch",
  "describe",
  "revoke",
  "rotate",
  "grant",
]);

const checkOperands = (
  values: {
    readonly "identity-stdin"?: boolean | undefined;
    readonly batch?: string | undefined;
    readonly help?: boolean | undefined;
  },
  command: string,
  operand: string | undefined
) => {
  if (
    values["identity-stdin"] === true &&
    !stdinIdentityCommands.has(command)
  ) {
    throw usage("identity-stdin is allowed only for approve and grant");
  }

  const named =
    namedCommands.has(command) ||
    (command === "approve" && values.batch === undefined);

  if (
    values.help !== true &&
    command !== "help" &&
    (named ? operand === undefined || operand === "" : operand !== undefined)
  ) {
    throw usage("wrong number of arguments");
  }
};

export const parseOptions = (args: string[]) => {
  try {
    const parsed = parseArgs({
      allowPositionals: true,
      args,
      options: optionSpec,
      strict: true,
    });

    const [command = "help", operand, ...extra] = parsed.positionals;
    const revokingGrant = command === "grant" && operand === "revoke";

    if (extra.length !== (revokingGrant ? 1 : 0) || !commands.has(command)) {
      throw usage("unknown command or extra arguments");
    }

    if ((parsed.values.inject?.length ?? 0) > 1) {
      throw new ClientFailure({
        code: 2,
        next: "sc approve <name>-alt --host <host> --caller <pattern> --placement <issuer> --inject 'Header: {value}'",
        what: "two inject templates for one credential",
        why: "A policy holds one header template.",
      });
    }

    if (
      parsed.values.pass !== undefined &&
      parsed.values["run-ticket"] !== undefined
    ) {
      throw usage("use --pass, not both pass flags");
    }

    checkOperands(parsed.values, command, operand);

    return {
      command: revokingGrant ? "grant-revoke" : command,
      flags: parsed.values,
      operand: revokingGrant ? (extra[0] ?? "") : (operand ?? ""),
    };
  } catch (error) {
    if (Schema.is(ClientFailure)(error)) {
      throw error;
    }

    throw usage("invalid command or flags");
  }
};

export type Options = ReturnType<typeof parseOptions>;

export const workerUrl = (value: string | undefined) => {
  if (value === undefined || !URL.canParse(value)) {
    throw usage(
      "SC_URL is missing or invalid",
      "sc --url https://<cell-host> --audience <worker-did> list"
    );
  }

  const url = new URL(value);
  const host = url.hostname;
  const [a = 0, b = 0] = host.split(".").map(Number);

  const privateHttp =
    host === "[::1]" ||
    host === "localhost" ||
    (isIP(host) === 4 && (a === 127 || (a === 100 && b >= 64 && b <= 127)));

  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    url.pathname !== "/" ||
    (url.protocol !== "https:" && !(url.protocol === "http:" && privateHttp))
  ) {
    throw usage("unsafe Worker URL", "sc --url https://<cell-host> list");
  }

  return url.origin;
};

export const listenAddress = (value: string | undefined) => {
  const match = /^(?<host>127(?:\.\d{1,3}){3}|\[::1\]):(?<port>\d+)$/u.exec(
    value ?? ""
  );

  const host = match?.groups?.host?.replaceAll(/[[\]]/gu, "");
  const port = Number(match?.groups?.port);

  if (
    host === undefined ||
    isIP(host) === 0 ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535
  ) {
    throw usage(
      "forward must bind a literal loopback address and valid port",
      "sc forward --listen 127.0.0.1:8080 --upstream-host <approved-host>"
    );
  }

  return { host, port };
};

export const splitHeader = (text: string) => {
  const colon = text.indexOf(":");

  if (colon < 1 || /[\r\n\0]/u.test(text)) {
    throw usage("invalid header or injection template");
  }

  return {
    name: text.slice(0, colon).trim(),
    value: text.slice(colon + 1).trim(),
  };
};
