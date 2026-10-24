import { isPublicHost } from "@lockjaw/domain";
import type {
  Caller,
  Host,
  Operation,
  Policy as CredentialPolicy,
} from "@lockjaw/domain";
import {
  CallerNotAllowed,
  HostNotAllowed,
  PlacementNotAllowed,
  RouteNotAllowed,
} from "@lockjaw/domain/errors";
import { Context, Effect, Layer } from "effect";

export const hostMatches = (actual: string, allowed: Host): boolean => {
  if (!allowed.startsWith("*.")) {
    return actual === allowed;
  }

  const base = allowed.slice(2);

  return (
    actual.endsWith(`.${base}`) &&
    actual.slice(0, -(base.length + 1)).split(".").length === 1 &&
    actual.length > base.length + 1
  );
};

const callerMatches = (actual: string, pattern: string): boolean =>
  pattern === "*" ||
  pattern === actual ||
  (pattern.endsWith("/*") && actual.startsWith(pattern.slice(0, -1)));

export const checkPublicTarget = Effect.fn("Policy.checkPublicTarget")(
  function* checkPublicTarget(op: Operation) {
    if (!isPublicHost(op.host)) {
      return yield* new HostNotAllowed({
        credential: op.credential,
        rule: "host-not-public",
      });
    }

    return yield* Effect.void;
  }
);

export const checkTarget = Effect.fn("Policy.checkTarget")(function* operation(
  policy: CredentialPolicy,
  op: Operation
) {
  yield* checkPublicTarget(op);

  if (!policy.hosts.some((host) => hostMatches(op.host, host))) {
    return yield* new HostNotAllowed({
      credential: op.credential,
      rule: "host",
    });
  }

  if (
    policy.routes &&
    !policy.routes.some(
      (route) =>
        route.method === op.method && op.path.startsWith(route.pathPrefix)
    )
  ) {
    return yield* new RouteNotAllowed({
      credential: op.credential,
      rule: "route",
    });
  }

  return yield* Effect.void;
});

export const authorize = Effect.fn("Policy.authorize")(function* operation(
  caller: Caller,
  policy: CredentialPolicy,
  op: Operation
) {
  if (
    !policy.callers.some((pattern) =>
      caller.ticketOnly === true
        ? pattern === "*"
        : callerMatches(caller.name, pattern)
    )
  ) {
    return yield* new CallerNotAllowed({
      credential: op.credential,
      rule: "caller",
    });
  }

  if (!policy.placements.includes(caller.issuer)) {
    return yield* new PlacementNotAllowed({
      credential: op.credential,
      rule: "placement",
    });
  }

  return yield* checkTarget(policy, op);
});

export const authorizeDelegated = Effect.fn("Policy.authorizeDelegated")(
  function* operation(caller: Caller, policy: CredentialPolicy, op: Operation) {
    if (!policy.placements.includes(caller.issuer)) {
      return yield* new PlacementNotAllowed({
        credential: op.credential,
        rule: "placement",
      });
    }

    return yield* checkTarget(policy, op);
  }
);

export class Policy extends Context.Service<
  Policy,
  {
    readonly authorize: typeof authorize;
    readonly authorizeDelegated: typeof authorizeDelegated;
  }
>()("secret-cell/Policy") {
  static readonly layer = Layer.succeed(
    Policy,
    Policy.of({ authorize, authorizeDelegated })
  );
  static readonly testLayer = Policy.layer;
}
