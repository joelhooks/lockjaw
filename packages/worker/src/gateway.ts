// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
import {
  CredentialName,
  GitHubAppMetadata,
  GrantId,
  Policy as PolicySchema,
  placeholderNames,
  placeholdersIn,
} from "@lockjaw/domain";
import type { Caller, GrantRecord, Operation, Policy } from "@lockjaw/domain";
import { KeyUnavailable, ValueNotWellFormed } from "@lockjaw/domain/errors";
import {
  EchoRedactor,
  Fill,
  GatewayRequest,
  Placement,
  Policy as PolicyService,
  clipRefusal,
  listable,
  parsePassScope,
} from "@lockjaw/gateway-rules";
import {
  Clock,
  Effect,
  Predicate,
  Redacted,
  Result,
  Schema,
  SchemaIssue,
  Stream,
} from "effect";

import { named } from "./bindings.js";
import type { Bindings } from "./bindings.js";
import { boundary, jsonBody, parse, rpc } from "./boundary.js";
import { CallerAuth } from "./caller-auth.js";
import type { Authenticated } from "./caller-auth.js";
import type { ResolvedForFill } from "./credential-do.js";
import {
  clipRefused,
  delegatedUse,
  direct,
  grantListOperation,
  grantOperation,
  grantRevokeOperation,
  grantRecords,
  grantsStub,
  holdsGrant,
  isApprover,
  isSetter,
  ownerActive,
} from "./delegation.js";
import { GatewayFault, boundaryFault, fault } from "./fault.js";
import { ticketRefused } from "./name-ticket.js";
import { Upstream } from "./upstream.js";

export { named } from "./bindings.js";

export type {
  Bindings,
  CellId,
  CredentialMethods,
  GrantMethods,
  Namespace,
  RpcStub,
} from "./bindings.js";

const decodeResolved = (input: ResolvedForFill) => Redacted.make(input.value);

const routeFor = (path: string) => {
  if (path.startsWith("/v1/u/") || path === "/v1/fetch") {
    return "fetch";
  }

  switch (path) {
    case "/v1/list": {
      return "list";
    }

    case "/v1/describe": {
      return "describe";
    }

    case "/v1/revoke": {
      return "revoke";
    }

    case "/v1/set": {
      return "set";
    }

    case "/v1/approve": {
      return "approve";
    }

    case "/v1/rotate": {
      return "rotate";
    }

    case "/v1/grant": {
      return "grant";
    }

    case "/v1/grant/revoke": {
      return "grant.revoke";
    }

    case "/v1/grants": {
      return "grant.list";
    }

    default: {
      return "unknown";
    }
  }
};

const directory = (env: Bindings) => named(env.REGISTRY, "registry");

const WellFormedValue = Schema.NonEmptyString.check(
  Schema.makeFilter((value) => value.isWellFormed(), {
    message: "ValueNotWellFormed",
  })
);

const SetRequest = Schema.Struct({
  expiresAt: Schema.optionalKey(Schema.NullOr(Schema.Finite)),
  githubApp: Schema.optionalKey(GitHubAppMetadata),
  name: CredentialName,
  policy: Schema.optionalKey(PolicySchema),
  value: WellFormedValue,
});

const RotateRequest = Schema.Struct({
  name: CredentialName,
  value: WellFormedValue,
});

const ApproveRequest = Schema.Struct({
  githubApp: Schema.optionalKey(GitHubAppMetadata),
  name: CredentialName,
  policy: PolicySchema,
});

const NameRequest = Schema.Struct({ name: CredentialName });

const metadata = (env: Bindings) =>
  boundary(async () => await directory(env).list());

const describe = (env: Bindings, name: CredentialName) =>
  rpc(async () => await named(env.CREDENTIAL, name).describe());

const operation = (
  name: CredentialName,
  target: GatewayRequest,
  reference: CredentialName = name
): Operation => {
  const url = new URL(target.url);

  const base: Operation = {
    credential: name,
    host: url.hostname.toLowerCase().replace(/\.$/u, ""),
    method: target.method.toUpperCase(),
    path: url.pathname,
  };

  return reference === name
    ? base
    : { ...base, subkey: reference.slice(name.length + 1) };
};

const active = Effect.fn("Gateway.preflight")(function* preflight(
  env: Bindings,
  name: CredentialName,
  caller: Caller,
  target: GatewayRequest,
  root: CredentialName = name
) {
  const info = yield* describe(env, root);

  if (!info.meta || !info.policy || !info.lifecycle) {
    return yield* fault(
      "missing",
      "Set this credential, then ask approver to approve its hosts and callers.",
      404,
      name
    );
  }

  const credentialPolicy = info.policy;
  const op = operation(root, target, name);

  const policyRefusal = (error: { readonly rule: string }) =>
    fault(
      error.rule,
      "Ask approver to approve this credential's caller, issuing host, target host and route.",
      403,
      name
    );

  const own =
    direct(caller) && (yield* ownerActive(env, root))
      ? yield* PolicyService.use((policy) =>
          policy.authorize(caller, credentialPolicy, op)
        ).pipe(Effect.result)
      : undefined;

  let chain: readonly string[] = [];

  if (own === undefined || Result.isFailure(own)) {
    if (caller.ticketOnly === true) {
      return yield* ticketRefused(
        "Ticket-only desks can match only an exact fleet-wide * policy entry with an allowed placement, host and route."
      );
    }

    if (
      own !== undefined &&
      Result.isFailure(own) &&
      !holdsGrant(yield* grantRecords(env), caller)
    ) {
      return yield* policyRefusal(own.failure);
    }

    ({ chain } = yield* delegatedUse(env, caller, {
      credential: root,
      host: op.host,
      method: op.method,
      op: "use",
      path: op.path,
    }));

    yield* PolicyService.use((policy) =>
      policy.authorizeDelegated(caller, credentialPolicy, op)
    ).pipe(Effect.mapError(policyRefusal));
  }

  if (
    info.lifecycle.state !== "active" &&
    info.lifecycle.state !== "rotating" &&
    info.lifecycle.state !== "refreshing"
  ) {
    return yield* fault(
      info.lifecycle.state,
      "Ask the cell operator to replace or reauthorize this credential.",
      403,
      name
    );
  }

  if (
    info.meta.expiresAt !== null &&
    info.meta.expiresAt <= (yield* Clock.currentTimeMillis)
  ) {
    return yield* fault(
      "expired",
      "Ask the cell operator to refresh or replace this credential.",
      403,
      name
    );
  }

  return chain;
});

const hopByHop = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
]);

const edgeOnly = new Set([
  "cookie",
  "forwarded",
  "host",
  "true-client-ip",
  "x-real-ip",
]);

const edgePrefixes = ["cf-", "x-forwarded-"];

const forwardable = (headers: GatewayRequest["headers"]) => {
  const listed = new Set(
    headers
      .filter((header) => header.name.toLowerCase() === "connection")
      .flatMap((header) =>
        header.value.split(",").map((token) => token.trim().toLowerCase())
      )
  );

  return headers.filter((header) => {
    const lower = header.name.toLowerCase();

    return (
      !hopByHop.has(lower) &&
      !edgeOnly.has(lower) &&
      !listed.has(lower) &&
      !edgePrefixes.some((prefix) => lower.startsWith(prefix))
    );
  });
};

const fetchFlow = Effect.fn("Gateway.fetch")(function* fetchFlow(
  env: Bindings,
  request: GatewayRequest,
  caller: Caller,
  transport: "fetch" | "swap",
  used: string[]
) {
  if (!request.url.startsWith("https://")) {
    return yield* fault("https", "Use an HTTPS target URL.");
  }

  const policies = new Map<CredentialName, Policy>();

  for (const entry of yield* metadata(env)) {
    const info = yield* describe(env, entry.name);

    if (info.policy) {
      policies.set(entry.name, info.policy);
    }
  }

  const registered = new Set(policies.keys());

  const rootFor = (name: CredentialName) =>
    registered.has(name)
      ? name
      : CredentialName.make(name.split("/")[0] ?? name);

  const roots = new Map<CredentialName, CredentialName>();

  for (const header of request.headers) {
    for (const entry of placeholdersIn(header.value)) {
      for (const name of placeholderNames(entry.placeholder)) {
        const root = rootFor(name);
        roots.set(name, root);
        const policy = policies.get(root);

        if (policy && !policies.has(name)) {
          policies.set(name, policy);
        }
      }
    }
  }

  const fills = yield* Placement.use((placement) =>
    placement.check(request)
  ).pipe(
    Effect.provide(Placement.layer(policies)),
    Effect.mapError((error) =>
      Predicate.isTagged(error, "NothingToFill")
        ? new GatewayFault({
            credential: error.credential,
            next: error.next,
            rule: error.rule,
            status: 403,
            what: error.what,
            why: error.why,
          })
        : fault(
            error.rule,
            "Use an approved HTTPS host and put each placeholder only in its declared header.",
            403,
            error.credential
          )
    )
  );

  const names = new Set(
    fills.flatMap((fill) => placeholderNames(fill.placeholder))
  );

  const chains = new Map<CredentialName, readonly string[]>();

  for (const name of names) {
    const chain = yield* active(
      env,
      name,
      caller,
      request,
      roots.get(name) ?? name
    );

    chains.set(name, chain);

    for (const id of chain) {
      if (!used.includes(id)) {
        used.push(id);
      }
    }
  }

  let resolveFault: GatewayFault | undefined;

  const filled = yield* Fill.use((fill) =>
    fill.apply(request, fills, (name) =>
      rpc(
        async () =>
          await named(env.CREDENTIAL, roots.get(name) ?? name).resolve(
            caller,
            operation(roots.get(name) ?? name, request, name),
            chains.get(name) ?? []
          )
      ).pipe(
        Effect.map(decodeResolved),
        Effect.tapError((error) =>
          Effect.sync(() => {
            resolveFault = error;
          })
        ),
        Effect.mapError(
          () => new KeyUnavailable({ credential: name, rule: "key" })
        )
      )
    )
  ).pipe(
    Effect.mapError(
      (error) =>
        resolveFault ??
        fault(
          error.rule,
          "Ask the cell operator to check this credential and its encryption bindings.",
          503,
          error.credential
        )
    )
  );

  const outgoing = {
    ...filled.request,
    headers: (transport === "swap"
      ? forwardable(filled.request.headers)
      : filled.request.headers
    ).filter((header) => !header.name.toLowerCase().startsWith("x-sc-")),
    redirect: "manual" as const,
  };

  const upstream = yield* Upstream.use((service) => service.send(outgoing));

  const response = yield* EchoRedactor.use((redactor) =>
    Effect.succeed(redactor.response(filled.redaction, upstream))
  );

  const body = yield* Stream.toReadableStreamEffect(response.body);

  return new Response(
    request.method.toUpperCase() === "HEAD" ||
      [204, 205, 304].includes(response.status)
      ? null
      : body,
    {
      headers: response.headers.map((header): [string, string] => [
        header.name,
        header.value,
      ]),
      status: response.status,
      statusText: response.statusText,
    }
  );
});

const swapTarget = Effect.fn("Gateway.swapTarget")(function* swapTarget(
  request: Request
) {
  const url = new URL(request.url);
  const rest = url.pathname.slice(6);
  const slash = rest.indexOf("/");
  const host = slash === -1 ? rest : rest.slice(0, slash);

  if (!/^[a-z0-9.-]+(?::[0-9]+)?$/u.test(host)) {
    return yield* fault(
      "host",
      "Use a literal approved hostname in /v1/u/<host>/<path>."
    );
  }

  const target: GatewayRequest = {
    headers: [...request.headers].map(([name, value]) => ({ name, value })),
    method: request.method,
    url: `https://${host}${slash === -1 ? "/" : rest.slice(slash)}${url.search}`,
  };

  return request.method === "GET" || request.method === "HEAD"
    ? target
    : { ...target, body: yield* jsonBody(request) };
});

const recordAttempt = Effect.fn("Gateway.recordAttempt")(
  function* recordAttempt(
    env: Bindings,
    op: string,
    caller: Caller | undefined,
    decision: "allowed" | "refused",
    reason: string,
    target: GatewayRequest | undefined,
    credential: string,
    grants: readonly string[]
  ) {
    const at = yield* Clock.currentTimeMillis;
    yield* Effect.tryPromise({
      catch: boundaryFault,
      try: async () => {
        await directory(env).record({
          at,
          callerDid: caller?.did ?? "",
          callerName: caller?.name ?? "",
          credential,
          decision,
          grants: [...grants],
          host:
            target && URL.canParse(target.url)
              ? new URL(target.url).hostname
              : "",
          method: target?.method ?? "",
          operation: op,
          pathPrefix: "",
          reason,
          runHandle: caller?.run?.handle ?? "",
          sessionId: caller?.sid ?? "",
        });
      },
    });
  }
);

const credentialAccess = Effect.fn("Gateway.credentialAccess")(
  function* credentialAccess(
    env: Bindings,
    caller: Caller,
    op: "describe" | "revoke" | "rotate" | "set",
    name: CredentialName,
    privileged: boolean
  ) {
    if (privileged) {
      return [];
    }

    const records = yield* grantRecords(env);

    if (direct(caller) && !holdsGrant(records, caller) && op !== "describe") {
      return yield* fault(
        "setter",
        `Ask approver to run sc ${op} with a setter identity, or to grant you the ${op} op on this credential.`,
        403,
        name
      );
    }

    const { chain } = yield* delegatedUse(env, caller, {
      credential: name,
      op,
    });

    return chain;
  }
);

const ticketMetadata = (caller: Caller, policy: Policy | undefined) =>
  caller.ticketOnly === true &&
  (policy === undefined ||
    !policy.callers.includes("*") ||
    !policy.placements.includes(caller.issuer))
    ? Effect.fail(
        ticketRefused(
          "Ticket-only desks may describe only fleet-wide * credentials on their pinned issuer placement."
        )
      )
    : Effect.void;

const metadataOperation = Effect.fn("Gateway.metadataOperation")(
  function* metadataOperation(
    env: Bindings,
    route: "describe" | "revoke",
    name: CredentialName,
    caller: Caller,
    used: string[]
  ) {
    const privileged =
      route === "describe"
        ? direct(caller)
        : isApprover(env, caller) || (yield* isSetter(env, caller));

    used.push(
      ...(yield* credentialAccess(env, caller, route, name, privileged))
    );

    const info = yield* describe(env, name);

    if (!info.meta) {
      return yield* new GatewayFault({
        credential: name,
        next: "sc list",
        rule: "missing",
        status: 404,
        what: "Lockjaw refused the operation",
        why: "The named credential has not been saved in this cell.",
      });
    }

    yield* ticketMetadata(caller, info.policy);

    if (route === "revoke") {
      if (info.lifecycle?.state !== "revoked") {
        yield* rpc(async () => await named(env.CREDENTIAL, name).revoke());
      }

      return Response.json({ name, state: "revoked" });
    }

    return Response.json({
      callers: info.policy?.callers ?? [],
      expiresAt: info.meta.expiresAt,
      hosts: info.policy?.hosts ?? [],
      inject: info.policy?.inject ?? null,
      kind: info.meta.kind,
      name,
      placements: info.policy?.placements ?? [],
      state: info.lifecycle?.state ?? "empty",
      version: info.version,
    });
  }
);

const delegatedSet = Effect.fn("Gateway.delegatedSet")(function* delegatedSet(
  env: Bindings,
  caller: Caller,
  body: typeof SetRequest.Type,
  records: readonly GrantRecord[],
  existed: boolean
) {
  if (direct(caller) && !holdsGrant(records, caller)) {
    return yield* fault(
      "setter",
      "Ask approver to add your DID to the setters binding, or to grant you the set op on this credential pattern."
    );
  }

  const { chain } = yield* delegatedUse(env, caller, {
    credential: body.name,
    op: "set",
  });

  const leaf = records.find((record) => record.grant.id === chain.at(-1));

  if (body.githubApp !== undefined) {
    return yield* new GatewayFault({
      credential: body.name,
      next: "Ask approver to set and approve GitHub App credentials directly.",
      rule: "clip",
      status: 403,
      what: "Lockjaw refused the delegated credential",
      why: "GitHub App metadata needs approver's approval, so a grant cannot set it.",
    });
  }

  if (body.policy === undefined && !existed) {
    return yield* new GatewayFault({
      credential: body.name,
      next: "Retry sc set with --host, --placement and optional --caller inside your grant, so the new credential has a clipped policy.",
      rule: "clip",
      status: 400,
      what: "Lockjaw refused the delegated credential",
      why: "A credential created under a grant needs a policy inside that grant.",
    });
  }

  if (body.policy !== undefined && leaf !== undefined) {
    const field = clipRefusal(body.policy, leaf.grant);

    if (field !== undefined) {
      return yield* clipRefused(body.name, field);
    }
  }

  if (existed && body.policy !== undefined) {
    const existing = yield* boundary(
      async () => await grantsStub(env).owner(body.name)
    );

    if (existing === null || !chain.includes(existing)) {
      return yield* new GatewayFault({
        credential: body.name,
        next: "Set the value without a policy, or ask approver to change this credential's policy with sc approve.",
        rule: "clip",
        status: 403,
        what: "Lockjaw refused the delegated policy change",
        why: "Only credentials created under your own grant chain take a policy from a grant.",
      });
    }
  }

  return {
    chain,
    owner: existed ? undefined : leaf?.grant.id,
    policy: body.policy,
  };
});

const setOperation = Effect.fn("Gateway.setOperation")(function* setOperation(
  env: Bindings,
  caller: Caller,
  body: typeof SetRequest.Type,
  used: string[]
) {
  const records = yield* grantRecords(env);

  const setter =
    (yield* isSetter(env, caller)) &&
    (body.policy === undefined || !holdsGrant(records, caller));

  const before = yield* describe(env, body.name);

  const delegation = setter
    ? undefined
    : yield* delegatedSet(
        env,
        caller,
        body,
        records,
        before.meta !== undefined
      );

  used.push(...(delegation?.chain ?? []));
  const owner = delegation?.owner;
  const policy = delegation?.policy;

  yield* rpc(
    async () =>
      await named(env.CREDENTIAL, body.name).set(
        body.value,
        body.expiresAt ?? null,
        body.githubApp
      )
  );

  if (policy !== undefined) {
    yield* rpc(
      async () => await named(env.CREDENTIAL, body.name).approve(policy)
    );
  }

  if (owner !== undefined) {
    const grant = GrantId.make(owner);
    yield* boundary(async () => {
      await grantsStub(env).own(body.name, grant);
    });
  }

  const saved = yield* describe(env, body.name);

  if (!saved.meta) {
    return yield* boundaryFault();
  }

  const savedMeta = saved.meta;
  yield* boundary(async () => {
    await directory(env).register(savedMeta);
  });

  return Response.json({ saved: true });
});

const listOperation = Effect.fn("Gateway.listOperation")(
  function* listOperation(request: Request, env: Bindings, caller: Caller) {
    if (request.method !== "GET") {
      return yield* fault("method", "Use GET /v1/list.", 405);
    }

    const entries = [];
    const all = yield* metadata(env);

    const visible = direct(caller)
      ? new Set(all.map((entry) => entry.name))
      : new Set(
          listable(
            yield* grantRecords(env),
            caller,
            all.map((entry) => entry.name),
            yield* Clock.currentTimeMillis
          )
        );

    for (const entry of all.filter((item) => visible.has(item.name))) {
      const info = yield* describe(env, entry.name);
      entries.push({
        kind: info.meta?.kind ?? "key",
        lifecycle: info.lifecycle?.state ?? "empty",
        name: entry.name,
      });
    }

    return Response.json({ credentials: entries });
  }
);

const postBody = <A, I>(
  request: Request,
  schema: Schema.Codec<A, I>,
  path: string
) =>
  Effect.gen(function* readPostBody() {
    if (request.method !== "POST") {
      return yield* fault("method", `Use POST ${path}.`, 405);
    }

    const text = yield* jsonBody(request);

    if (path === "/v1/set" || path === "/v1/rotate") {
      return yield* Schema.decodeEffect(Schema.fromJsonString(schema))(
        text
      ).pipe(
        Effect.mapError((error) => {
          const malformed = SchemaIssue.makeFormatterStandardSchemaV1()(
            error.issue
          ).issues.some((issue) => issue.message === "ValueNotWellFormed");

          if (malformed) {
            const { credential, next, rule, what, why } =
              ValueNotWellFormed.refusal("request");

            return new GatewayFault({
              credential,
              next,
              rule,
              status: 400,
              what,
              why,
            });
          }

          return fault(
            "request",
            "Send a JSON body matching this route's contract.",
            400
          );
        })
      );
    }

    return yield* parse(schema, text);
  });

const passCeiling = Effect.fn("Gateway.passCeiling")(function* passCeiling(
  auth: Authenticated,
  route: string
) {
  const { pass, caller } = auth;

  if (pass === undefined || caller.run === undefined) {
    return yield* Effect.void;
  }

  const lxm = `sh.secretcell.${route}`;

  if (
    !(parsePassScope(caller.run.scope) ?? []).some((entry) => entry.lxm === lxm)
  ) {
    return yield* new GatewayFault({
      credential: "request",
      next: "Ask your desk for a pass whose scope carries this lxm, or have the desk run the operation itself. Passes carry only fetch, describe, list and broker lxms.",
      rule: "pass",
      status: 403,
      what: `Lockjaw refused ${lxm} for this worker pass`,
      why: "The worker pass scope does not carry this operation's lxm.",
    });
  }

  return yield* Effect.void;
});

const rotateOperation = Effect.fn("Gateway.rotateOperation")(
  function* rotateOperation(
    env: Bindings,
    caller: Caller,
    body: typeof RotateRequest.Type,
    used: string[]
  ) {
    used.push(
      ...(yield* credentialAccess(
        env,
        caller,
        "rotate",
        body.name,
        isApprover(env, caller) || (yield* isSetter(env, caller))
      ))
    );

    const info = yield* describe(env, body.name);

    if (!info.meta) {
      return yield* fault(
        "missing",
        "Set this credential before rotating it.",
        404,
        body.name
      );
    }

    yield* rpc(
      async () => await named(env.CREDENTIAL, body.name).rotate(body.value)
    );

    const rotated = yield* describe(env, body.name);

    return Response.json({
      name: body.name,
      rotated: true,
      version: rotated.version,
    });
  }
);

const delegationRoute = Effect.fn("Gateway.delegationRoute")(
  function* delegationRoute(
    route: "list" | "grant" | "grant.revoke" | "grant.list",
    request: Request,
    env: Bindings,
    caller: Caller,
    used: string[]
  ) {
    if (route === "grant") {
      const result = yield* grantOperation(request, env, caller);
      used.push(...result.chain);

      return Response.json({ grant: result.created });
    }

    if (route === "grant.revoke") {
      const result = yield* grantRevokeOperation(request, env, caller);
      used.push(...result.chain);

      return Response.json({ revoked: result.revoked });
    }

    if (route === "grant.list") {
      return Response.json({
        grants: yield* grantListOperation(request, env, caller),
      });
    }

    return yield* listOperation(request, env, caller);
  }
);

export const handle = Effect.fn("Gateway.handle")(function* handle(
  request: Request,
  env: Bindings
) {
  const path = new URL(request.url).pathname;

  const route = routeFor(path);

  let caller: Caller | undefined;
  let target: GatewayRequest | undefined;
  let attemptCredential = "request";
  const used: string[] = [];

  const run = Effect.gen(function* routeOperation() {
    if (route === "unknown") {
      return yield* fault(
        "route",
        "Use /v1/fetch, /v1/u/<host>/<path>, /v1/list, /v1/set, /v1/rotate, /v1/grant or /v1/grants.",
        404
      );
    }

    const auth = yield* CallerAuth.use((service) =>
      service.authenticate({
        bindings: env,
        lxm: `sh.secretcell.${route}`,
        pass: request.headers.get("x-sc-pass"),
        ticket: request.headers.get("x-sc-ticket"),
        token:
          request.headers.get("x-sc-auth") ??
          (path.startsWith("/v1/u/")
            ? null
            : request.headers.get("authorization")),
      })
    );

    ({ caller } = auth);

    const now = yield* Clock.currentTimeMillis;

    const hash = yield* Effect.tryPromise({
      catch: boundaryFault,
      try: async () =>
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(auth.keyId)
        ),
    });

    const shard = Array.from(new Uint8Array(hash).slice(0, 2), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");

    const consumed = yield* Effect.tryPromise({
      catch: boundaryFault,
      try: async () =>
        await named(env.REPLAY, shard).consume(
          auth.keyId,
          auth.claims.jti,
          auth.claims.exp * 1000,
          now
        ),
    });

    if (!consumed) {
      return yield* fault(
        "replay",
        "Mint a new caller token with a unique jti.",
        401
      );
    }

    yield* passCeiling(auth, route);

    if (
      route === "list" ||
      route === "grant" ||
      route === "grant.revoke" ||
      route === "grant.list"
    ) {
      return yield* delegationRoute(route, request, env, caller, used);
    }

    if (route === "describe" || route === "revoke") {
      const expectedMethod = route === "describe" ? "GET" : "POST";

      if (request.method !== expectedMethod) {
        return yield* fault(
          "method",
          `Use ${expectedMethod} /v1/${route}.`,
          405
        );
      }

      const body = yield* parse(
        NameRequest,
        route === "describe"
          ? JSON.stringify({
              name: new URL(request.url).searchParams.get("name"),
            })
          : yield* jsonBody(request)
      );

      attemptCredential = body.name;

      return yield* metadataOperation(env, route, body.name, caller, used);
    }

    if (route === "set") {
      const body = yield* postBody(request, SetRequest, "/v1/set");
      attemptCredential = body.name;

      return yield* setOperation(env, caller, body, used);
    }

    if (route === "rotate") {
      const body = yield* postBody(request, RotateRequest, "/v1/rotate");

      attemptCredential = body.name;

      return yield* rotateOperation(env, caller, body, used);
    }

    if (route === "approve") {
      if (!isApprover(env, caller)) {
        return yield* fault(
          "approver",
          "Ask approver to approve the host and caller policy."
        );
      }

      const body = yield* postBody(request, ApproveRequest, "/v1/approve");
      attemptCredential = body.name;
      yield* rpc(
        async () =>
          await named(env.CREDENTIAL, body.name).approve(
            body.policy,
            body.githubApp
          )
      );

      return Response.json({ approved: true });
    }

    const transport = path.startsWith("/v1/u/") ? "swap" : "fetch";

    if (transport === "swap") {
      target = yield* swapTarget(request);
    } else {
      if (request.method !== "POST") {
        return yield* fault("method", "Use POST /v1/fetch.", 405);
      }

      target = yield* parse(GatewayRequest, yield* jsonBody(request));
    }

    attemptCredential =
      target.headers
        .flatMap((header) =>
          placeholdersIn(header.value).flatMap((entry) =>
            placeholderNames(entry.placeholder)
          )
        )
        .join(",") || "request";

    return yield* fetchFlow(env, target, caller, transport, used);
  });

  return yield* run.pipe(
    Effect.matchEffect({
      onFailure: (error) =>
        recordAttempt(
          env,
          route,
          caller,
          "refused",
          error.rule,
          target,
          error.credential === "request" ? attemptCredential : error.credential,
          used
        ).pipe(
          Effect.as(
            Response.json(
              {
                error: {
                  credential: error.credential,
                  next: error.next,
                  rule: error.rule,
                  what: error.what,
                  why: error.why,
                },
              },
              { status: error.status }
            )
          )
        ),
      onSuccess: (response) =>
        recordAttempt(
          env,
          route,
          caller,
          "allowed",
          "authorized",
          target,
          attemptCredential,
          used
        ).pipe(Effect.as(response)),
    })
  );
});
