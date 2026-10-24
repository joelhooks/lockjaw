export {
  Policy,
  authorize,
  authorizeDelegated,
  checkTarget,
  hostMatches,
} from "./policy.js";

export {
  activeChain,
  admitDelegated,
  authorizeUse,
  chainOf,
  clipRefusal,
  descendants,
  effective,
  granteeMatches,
  isSubScope,
  listable,
  maxDepth,
  scopeAllows,
  unbounded,
  visibleTo,
  widened,
} from "./delegation.js";

export type {
  Admission,
  GrantField,
  GrantRequest,
  PolicyField,
  ScopeField,
  Use,
  UseDecision,
  UseRefusal,
} from "./delegation.js";

export { nameMatches, patternCovers } from "./patterns.js";

export {
  lxmFor,
  parsePassScope,
  passAllows,
  passLifetimeSeconds,
  passSkewSeconds,
  passableLxm,
} from "./pass.js";

export type { PassEntry } from "./pass.js";

export { Placement, GatewayRequest, makeCheck } from "./placement.js";

export type { HeaderFill } from "./placement.js";

export { NothingToFill, nothingToFill } from "./nothing-to-fill.js";

export { Fill, apply } from "./fill.js";

export type { FilledRequest, RedactionPlan, Resolve } from "./fill.js";

export {
  EchoRedactor,
  redactText,
  redactStream,
  redactResponse,
  redactError,
} from "./echo-redactor.js";

export type { EchoResponse } from "./echo-redactor.js";
