import type {
  Caller,
  Grant,
  GrantId,
  GrantRecord,
  Grantee,
  Host,
  Op,
  Policy,
  Route,
  Scope,
} from "@lockjaw/domain";

import { lxmFor, passAllows } from "./pass.js";
import { nameMatches, patternCovers } from "./patterns.js";
import { hostMatches } from "./policy.js";

export const maxDepth = 3;

export type ScopeField =
  | "credentials"
  | "hosts"
  | "routes"
  | "ops"
  | "grantees"
  | "exp";

export type GrantField = ScopeField | "grantee" | "depth" | "parent";

export type PolicyField = "callers" | "hosts" | "routes" | "ports";

export interface Use {
  readonly credential: string;
  readonly op: Op;
  readonly host?: string;
  readonly method?: string;
  readonly path?: string;
}

export const granteeMatches = (grant: Grant, caller: Caller): boolean =>
  caller.ticketOnly !== true &&
  grant.grantee.desk === caller.name &&
  grant.grantee.runHandle === caller.run?.handle;

const hostCovers = (parent: Host, child: Host): boolean =>
  parent === child || (!child.startsWith("*.") && hostMatches(child, parent));

const routeCovers = (parent: Route, child: Route): boolean =>
  parent.method === child.method &&
  child.pathPrefix.startsWith(parent.pathPrefix);

const routesCovered = (
  parent: readonly Route[] | undefined,
  child: readonly Route[] | undefined
): boolean =>
  parent === undefined ||
  (child !== undefined &&
    child.every((route) => parent.some((outer) => routeCovers(outer, route))));

const allCovered = (
  parent: readonly string[],
  child: readonly string[]
): boolean =>
  child.every((pattern) =>
    parent.some((outer) => patternCovers(outer, pattern))
  );

export const widened = (
  child: Scope,
  parent: Scope
): ScopeField | undefined => {
  if (!allCovered(parent.credentials, child.credentials)) {
    return "credentials";
  }

  if (
    !child.hosts.every((host) =>
      parent.hosts.some((outer) => hostCovers(outer, host))
    )
  ) {
    return "hosts";
  }

  if (!routesCovered(parent.routes, child.routes)) {
    return "routes";
  }

  if (!child.ops.every((op) => parent.ops.includes(op))) {
    return "ops";
  }

  if (!allCovered(parent.grantees, child.grantees)) {
    return "grantees";
  }

  if (child.exp > parent.exp) {
    return "exp";
  }

  return undefined;
};

export const isSubScope = (child: Scope, parent: Scope): boolean =>
  widened(child, parent) === undefined;

export const unbounded = (scope: Scope): ScopeField | undefined => {
  if (scope.credentials.some((pattern) => pattern === "*")) {
    return "credentials";
  }

  if (scope.grantees.some((pattern) => pattern === "*")) {
    return "grantees";
  }

  return undefined;
};

const routeAllows = (
  routes: readonly Route[] | undefined,
  method: string,
  path: string
): boolean => {
  if (routes === undefined) {
    return true;
  }

  if (/%(?:2f|5c|25)/iu.test(path)) {
    return false;
  }

  let decoded = path;

  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false;
  }

  return [path, decoded].every((candidate) =>
    routes.some(
      (route) =>
        route.method === method && candidate.startsWith(route.pathPrefix)
    )
  );
};

export const scopeAllows = (scope: Scope, use: Use, now: number): boolean => {
  if (
    scope.exp <= now ||
    !scope.ops.includes(use.op) ||
    !scope.credentials.some((pattern) => nameMatches(pattern, use.credential))
  ) {
    return false;
  }

  if (use.op !== "use") {
    return true;
  }

  return (
    use.host !== undefined &&
    scope.hosts.some((host) => hostMatches(use.host ?? "", host)) &&
    routeAllows(scope.routes, use.method ?? "", use.path ?? "")
  );
};

const index = (records: readonly GrantRecord[]) =>
  new Map(records.map((record) => [record.grant.id, record]));

export const chainOf = (
  records: readonly GrantRecord[],
  id: GrantId
): readonly GrantRecord[] | undefined => {
  const byId = index(records);
  const chain: GrantRecord[] = [];
  let current = byId.get(id);

  while (current !== undefined) {
    if (chain.length >= maxDepth) {
      return undefined;
    }

    chain.unshift(current);
    const { parent } = current.grant;

    if (parent === undefined) {
      return chain;
    }

    current = byId.get(parent);
  }

  return undefined;
};

const linked = (parent: Grant | undefined, child: Grant): boolean =>
  parent === undefined
    ? child.parent === undefined
    : child.parent === parent.id &&
      isSubScope(child.scope, parent.scope) &&
      unbounded(child.scope) === undefined &&
      parent.scope.grantees.some((pattern) =>
        nameMatches(pattern, child.grantee.desk)
      );

export const effective = (
  chain: readonly GrantRecord[],
  now: number
): boolean => {
  let parent: Grant | undefined;

  for (const record of chain) {
    if (
      record.revokedAt !== null ||
      record.grant.scope.exp <= now ||
      !linked(parent, record.grant)
    ) {
      return false;
    }

    parent = record.grant;
  }

  return chain.length > 0;
};

export const activeChain = (
  records: readonly GrantRecord[],
  id: GrantId,
  now: number
): readonly GrantRecord[] | undefined => {
  const chain = chainOf(records, id);

  return chain !== undefined && effective(chain, now) ? chain : undefined;
};

export type UseRefusal = "grant" | "pass" | "pass-expiry";

export type UseDecision =
  | { readonly allowed: true; readonly chain: readonly GrantId[] }
  | { readonly allowed: false; readonly reason: UseRefusal };

export const authorizeUse = (
  records: readonly GrantRecord[],
  caller: Caller,
  use: Use,
  now: number
): UseDecision => {
  if (
    caller.run !== undefined &&
    !passAllows(caller.run.scope, lxmFor(use.op), use.credential)
  ) {
    return { allowed: false, reason: "pass" };
  }

  let reason: UseRefusal = "grant";

  for (const record of records) {
    if (
      !granteeMatches(record.grant, caller) ||
      !scopeAllows(record.grant.scope, use, now)
    ) {
      continue;
    }

    const chain = activeChain(records, record.grant.id, now);

    if (
      chain === undefined ||
      !chain.every((link) => scopeAllows(link.grant.scope, use, now))
    ) {
      continue;
    }

    const passExpiry = caller.run?.expiresAt ?? 0;

    if (chain.some((link) => passExpiry > link.grant.scope.exp)) {
      reason = "pass-expiry";
      continue;
    }

    return { allowed: true, chain: chain.map((link) => link.grant.id) };
  }

  return { allowed: false, reason };
};

export interface GrantRequest {
  readonly grantee: Grantee;
  readonly scope: Scope;
}

export type Admission =
  | { readonly admitted: true; readonly parent: GrantId }
  | { readonly admitted: false; readonly field: GrantField };

export const admitDelegated = (
  records: readonly GrantRecord[],
  caller: Caller,
  request: GrantRequest,
  now: number
): Admission => {
  const unboundedField = unbounded(request.scope);

  if (unboundedField !== undefined) {
    return { admitted: false, field: unboundedField };
  }

  let refusal: GrantField = "parent";

  for (const record of records) {
    if (
      !granteeMatches(record.grant, caller) ||
      !record.grant.scope.ops.includes("grant")
    ) {
      continue;
    }

    const chain = activeChain(records, record.grant.id, now);

    if (chain === undefined) {
      continue;
    }

    if (chain.length >= maxDepth) {
      refusal = "depth";
      continue;
    }

    if (
      !record.grant.scope.grantees.some((pattern) =>
        nameMatches(pattern, request.grantee.desk)
      )
    ) {
      refusal = "grantee";
      continue;
    }

    const field = widened(request.scope, record.grant.scope);

    if (field !== undefined) {
      refusal = field;
      continue;
    }

    return { admitted: true, parent: record.grant.id };
  }

  return { admitted: false, field: refusal };
};

export const descendants = (
  records: readonly GrantRecord[],
  id: GrantId
): readonly GrantId[] => {
  const found: GrantId[] = [id];

  for (const current of found) {
    for (const record of records) {
      if (record.grant.parent === current) {
        found.push(record.grant.id);
      }
    }
  }

  return found;
};

export const visibleTo = (
  records: readonly GrantRecord[],
  caller: Caller
): readonly GrantRecord[] => {
  const ids = new Set(
    records
      .filter((record) => granteeMatches(record.grant, caller))
      .flatMap((record) => descendants(records, record.grant.id))
  );

  return records.filter((record) => ids.has(record.grant.id));
};

export const clipRefusal = (
  policy: Policy,
  grant: Grant
): PolicyField | undefined => {
  const { scope } = grant;

  if (
    !policy.callers.every(
      (pattern) =>
        pattern !== "*" &&
        scope.grantees.some((outer) => patternCovers(outer, pattern))
    )
  ) {
    return "callers";
  }

  if (
    !policy.hosts.every((host) =>
      scope.hosts.some((outer) => hostCovers(outer, host))
    )
  ) {
    return "hosts";
  }

  if (!routesCovered(scope.routes, policy.routes)) {
    return "routes";
  }

  if (policy.ports !== undefined && policy.ports.length > 0) {
    return "ports";
  }

  return undefined;
};

export const listable = (
  records: readonly GrantRecord[],
  caller: Caller,
  names: readonly string[],
  now: number
): readonly string[] =>
  names.filter(
    (name) =>
      caller.run !== undefined &&
      passAllows(caller.run.scope, "sh.secretcell.list", name) &&
      records.some(
        (record) =>
          granteeMatches(record.grant, caller) &&
          record.grant.scope.credentials.some((pattern) =>
            nameMatches(pattern, name)
          ) &&
          activeChain(records, record.grant.id, now) !== undefined
      )
  );
