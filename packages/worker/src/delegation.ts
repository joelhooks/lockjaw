// oxlint-disable typescript/promise-function-async -- RPC callbacks are lazy Promise boundaries; Effect owns the workflow.
import { Grant, GrantId, Grantee, Scope } from "@lockjaw/domain";
import type { Caller, GrantRecord } from "@lockjaw/domain";
import {
  activeChain,
  admitDelegated,
  authorizeUse,
  descendants,
  granteeMatches,
  lxmFor,
  visibleTo,
} from "@lockjaw/gateway-rules";
import type {
  GrantField,
  PolicyField,
  Use,
  UseRefusal,
} from "@lockjaw/gateway-rules";
import { Clock, Effect, Schema } from "effect";

import { named } from "./bindings.js";
import type { Bindings } from "./bindings.js";
import { boundary, jsonBody, parse } from "./boundary.js";
import { GatewayFault, fault } from "./fault.js";

const settersSchema = Schema.Array(Schema.String);

export const grantsStub = (env: Bindings) => named(env.GRANTS, "grants");

export const grantRecords = (env: Bindings) =>
  boundary(async () => await grantsStub(env).list());

export const direct = (caller: Caller) => caller.run === undefined;

export const isApprover = (env: Bindings, caller: Caller) =>
  direct(caller) &&
  caller.ticketOnly !== true &&
  caller.did === env.APPROVER_DID;

export const isSetter = Effect.fn("Delegation.isSetter")(function* isSetter(
  env: Bindings,
  caller: Caller
) {
  const setters = yield* parse(settersSchema, env.SETTERS);

  return (
    direct(caller) && caller.ticketOnly !== true && setters.includes(caller.did)
  );
});

const grantNext = new Map<GrantField, string>([
  [
    "credentials",
    "Name only credential patterns inside your own grant's credentials, then retry sc grant.",
  ],
  ["hosts", "Name only hosts your own grant allows, then retry sc grant."],
  [
    "routes",
    "Name only routes inside your own grant's routes, and keep routes when your grant has them, then retry sc grant.",
  ],
  ["ops", "Pass only ops your own grant holds, then retry sc grant."],
  [
    "grantees",
    "Name only grantee patterns inside your own grant's grantees; a bare * is approver-only. Retry sc grant.",
  ],
  [
    "grantee",
    "Grant only to a desk your own grant's grantees cover, then retry sc grant.",
  ],
  [
    "exp",
    "Set --exp in the future and no later than your own grant's expiry, then retry sc grant.",
  ],
  [
    "depth",
    "Grant chains stop at three links. Ask the desk above you, or approver, to grant this scope directly.",
  ],
  [
    "parent",
    "Ask approver or your desk for an active grant that includes the grant op, then retry sc grant.",
  ],
]);

export const grantRefused = (field: GrantField) =>
  new GatewayFault({
    credential: "request",
    next: grantNext.get(field) ?? "Run sc grants to see your active grants.",
    rule: "grant",
    status: 403,
    what: "Lockjaw refused the grant",
    why:
      field === "depth" || field === "parent"
        ? `The grant has no valid parent (${field}): you hold no active grant with the grant op that can carry one more link.`
        : `The requested ${field} is wider than your own grant allows.`,
  });

const useWhy = (use: Use, reason: UseRefusal) => {
  if (reason === "pass-expiry") {
    return "The worker pass outlives a grant in the matched chain.";
  }

  if (reason === "pass") {
    return `The worker pass scope does not carry ${lxmFor(use.op)} for this credential. Passes never carry set, rotate, revoke or grant ops.`;
  }

  return `No active grant chain covers this caller, credential and ${use.op} op${use.op === "use" ? " on this host and route" : ""}.`;
};

const useNext = (use: Use, reason: UseRefusal) => {
  if (reason === "pass-expiry") {
    return "Ask your desk for a pass that expires no later than every grant in your chain, then retry.";
  }

  if (reason === "pass") {
    return "Ask your desk for a pass whose scope includes this lxm and credential, or have the desk run the operation itself.";
  }

  return `Ask your desk or approver for an active grant with the ${use.op} op on this credential${use.op === "use" ? ", host and route" : ""}, then retry. Run sc grants to see yours.`;
};

export const useRefused = (use: Use, reason: UseRefusal) =>
  new GatewayFault({
    credential: use.credential,
    next: useNext(use, reason),
    rule: reason,
    status: 403,
    what: `Lockjaw refused the ${use.op} operation`,
    why: useWhy(use, reason),
  });

export const clipRefused = (credential: string, field: PolicyField) =>
  new GatewayFault({
    credential,
    next:
      field === "ports"
        ? "Remove ports from the policy; delegated credentials use implicit HTTPS only. Ask approver to approve explicit ports."
        : `Name only ${field} that your set grant covers, then retry sc set.`,
    rule: "clip",
    status: 403,
    what: "Lockjaw refused the delegated credential policy",
    why: `The policy's ${field} reach outside the grant that allows this set.`,
  });

export const delegatedUse = Effect.fn("Delegation.use")(function* delegatedUse(
  env: Bindings,
  caller: Caller,
  use: Use
) {
  const records = yield* grantRecords(env);
  const now = yield* Clock.currentTimeMillis;
  const decision = authorizeUse(records, caller, use, now);

  if (!decision.allowed) {
    return yield* useRefused(use, decision.reason);
  }

  return { chain: decision.chain, records };
});

export const holdsGrant = (records: readonly GrantRecord[], caller: Caller) =>
  records.some((record) => granteeMatches(record.grant, caller));

export const ownerActive = Effect.fn("Delegation.ownerActive")(
  function* ownerActive(env: Bindings, credential: string) {
    const owner = yield* boundary(
      async () => await grantsStub(env).owner(credential)
    );

    if (owner === null) {
      return true;
    }

    return (
      activeChain(
        yield* grantRecords(env),
        owner,
        yield* Clock.currentTimeMillis
      ) !== undefined
    );
  }
);

const GrantBody = Schema.Struct({ grantee: Grantee, scope: Scope });

const RevokeBody = Schema.Struct({ id: GrantId });

const newId = () =>
  GrantId.make(
    `g_${Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("")}`
  );

const state = (record: GrantRecord, now: number) => {
  if (record.revokedAt !== null) {
    return "revoked";
  }

  return record.grant.scope.exp <= now ? "expired" : "active";
};

const summary = (record: GrantRecord, now: number) => ({
  ...record.grant,
  revokedAt: record.revokedAt,
  state: state(record, now),
});

export const grantOperation = Effect.fn("Delegation.grant")(function* grant(
  request: Request,
  env: Bindings,
  caller: Caller
) {
  if (request.method !== "POST") {
    return yield* fault("method", "Use POST /v1/grant.", 405);
  }

  const body = yield* parse(GrantBody, yield* jsonBody(request));
  const now = yield* Clock.currentTimeMillis;

  if (body.scope.exp <= now) {
    return yield* grantRefused("exp");
  }

  const records = yield* grantRecords(env);
  let parent: GrantId | undefined;

  if (!isApprover(env, caller)) {
    const admission = admitDelegated(records, caller, body, now);

    if (!admission.admitted) {
      return yield* grantRefused(admission.field);
    }

    ({ parent } = admission);
  }

  const root = Grant.make({
    createdAt: now,
    grantee: body.grantee,
    grantor: caller.name,
    id: newId(),
    scope: body.scope,
  });

  const created = parent === undefined ? root : Grant.make({ ...root, parent });

  const inserted = yield* boundary(
    async () => await grantsStub(env).insert(created)
  );

  if (!inserted.inserted) {
    return yield* grantRefused(inserted.reason);
  }

  return { chain: parent === undefined ? [] : [parent], created };
});

export const grantRevokeOperation = Effect.fn("Delegation.revoke")(
  function* grantRevoke(request: Request, env: Bindings, caller: Caller) {
    if (request.method !== "POST") {
      return yield* fault("method", "Use POST /v1/grant/revoke.", 405);
    }

    const body = yield* parse(RevokeBody, yield* jsonBody(request));
    const now = yield* Clock.currentTimeMillis;
    const records = yield* grantRecords(env);

    const holder = records.find(
      (record) =>
        granteeMatches(record.grant, caller) &&
        activeChain(records, record.grant.id, now) !== undefined &&
        descendants(records, record.grant.id).includes(body.id)
    );

    if (!isApprover(env, caller) && holder === undefined) {
      return yield* new GatewayFault({
        credential: "request",
        next: "Run sc grants to list the grants you hold and their descendants, then revoke one of those.",
        rule: "grant",
        status: 403,
        what: "Lockjaw refused the grant revocation",
        why: "The grant is not yours or a descendant of an active grant you hold.",
      });
    }

    const revoked = yield* boundary(
      async () => await grantsStub(env).revoke(body.id, now)
    );

    return {
      chain: holder === undefined ? [] : [holder.grant.id],
      revoked,
    };
  }
);

export const grantListOperation = Effect.fn("Delegation.list")(
  function* grantList(request: Request, env: Bindings, caller: Caller) {
    if (request.method !== "GET") {
      return yield* fault("method", "Use GET /v1/grants.", 405);
    }

    const now = yield* Clock.currentTimeMillis;
    const records = yield* grantRecords(env);

    return (isApprover(env, caller) ? records : visibleTo(records, caller)).map(
      (record) => summary(record, now)
    );
  }
);
