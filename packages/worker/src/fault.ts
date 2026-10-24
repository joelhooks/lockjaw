import { Schema } from "effect";

export class GatewayFault extends Schema.TaggedError<GatewayFault>()(
  "GatewayFault",
  {
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.String,
    status: Schema.Int,
    what: Schema.String,
    why: Schema.String,
  }
) {}

const reasons = new Map([
  [
    "caller-auth",
    "The signature or signed iss, aud, iat, exp, jti, lxm or sid claim did not satisfy the caller-auth contract.",
  ],
  [
    "replay",
    "This caller key has already consumed the signed jti, or the token expired.",
  ],
  ["host", "The credential policy does not approve the target hostname."],
  [
    "host-not-public",
    "IP literals and internal or special-use hostnames cannot be approved upstreams.",
  ],
  ["https", "Generic secret filling is allowed only over HTTPS."],
  [
    "caller",
    "The authenticated Rat King name is outside the credential caller policy.",
  ],
  [
    "placement",
    "The authenticated issuing host is outside the credential placement policy.",
  ],
  [
    "authority",
    "URL user information is forbidden, or this explicit port is not approved for every credential.",
  ],
  ["missing", "The named credential has not been saved in this cell."],
  ["empty", "The named credential has no saved value."],
  [
    "revoked",
    "The credential was revoked and its encrypted value was deleted.",
  ],
  ["expired", "The credential lifetime ended before this use."],
  [
    "needsAuth",
    "A refresh failed with invalid_grant or the one activation recovery retry failed.",
  ],
  ["needs-auth", "The credential requires fresh upstream authorization."],
  [
    "header-only",
    "A secret placeholder occurred in a body or URL rather than its declared header.",
  ],
  [
    "encoding",
    "An encoded secret placeholder occurred outside a permitted raw header placement.",
  ],
  [
    "header",
    "The header placement or injection template does not match the credential policy.",
  ],
  [
    "setter",
    "The authenticated caller DID is absent from the setters binding.",
  ],
  [
    "approver",
    "Only the configured approver DID may change credential host or caller policy.",
  ],
  [
    "storage",
    "A Durable Object or required storage binding could not complete the operation.",
  ],
  [
    "upstream",
    "The upstream transport failed or the overall request deadline elapsed.",
  ],
]);

const actions = new Map([
  [
    "host-not-public",
    "Use the service's public DNS hostname in the policy and the request, not an IP literal or internal name, then retry /v1/fetch.",
  ],
  [
    "needs-auth",
    "Reauthorize the upstream credential or replace its value with POST /v1/set using sh.secretcell.set. Retry /v1/fetch with a fresh sh.secretcell.fetch caller token.",
  ],
  [
    "upstream",
    "Retry /v1/fetch with a fresh sh.secretcell.fetch caller token. If it fails again, ask the cell operator to check the approved upstream's availability.",
  ],
  [
    "missing",
    "POST /v1/set with this name and a replacement value using sh.secretcell.set from an allowed setter. Then ask approver to POST /v1/approve using sh.secretcell.approve before retrying /v1/fetch.",
  ],
  [
    "empty",
    "POST /v1/set with this name and a replacement value using sh.secretcell.set from an allowed setter. Then ask approver to POST /v1/approve before retrying /v1/fetch.",
  ],
  [
    "revoked",
    "POST /v1/set under a new credential name using sh.secretcell.set. Ask approver to POST /v1/approve for that name, update the placeholder, and retry /v1/fetch.",
  ],
  [
    "expired",
    "An allowed setter must POST /v1/set with a fresh value for this name using sh.secretcell.set. Retry /v1/fetch with a fresh sh.secretcell.fetch token.",
  ],
  [
    "needsAuth",
    "Reauthorize the upstream credential, then POST /v1/set with the replacement using sh.secretcell.set. Retry /v1/fetch with a fresh sh.secretcell.fetch token.",
  ],
  [
    "host",
    "Ask approver to POST /v1/approve for this name with the intended hosts policy using sh.secretcell.approve. Then retry /v1/fetch with a fresh sh.secretcell.fetch token.",
  ],
  [
    "caller",
    "Ask approver to POST /v1/approve for this name with the intended callers policy using sh.secretcell.approve. Then retry /v1/fetch with a fresh sh.secretcell.fetch token.",
  ],
  [
    "placement",
    "Ask approver to POST /v1/approve for this name with the intended placements policy using sh.secretcell.approve. Then retry /v1/fetch with a fresh sh.secretcell.fetch token.",
  ],
  [
    "authority",
    "Remove URL user information. Use implicit HTTPS, or ask approver to POST /v1/approve with this name and the explicit ports policy using sh.secretcell.approve. Retry /v1/fetch with a fresh token.",
  ],
  [
    "key",
    "The cell operator must check LOCKJAW_KEK and optional LOCKJAW_KEK_NEXT against the stored kekId. Restore the matching binding and retry /v1/fetch with a fresh token.",
  ],
]);

export const fault = (
  rule: string,
  next: string,
  status = 403,
  credential = "request"
) =>
  new GatewayFault({
    credential,
    next: actions.get(rule) ?? next,
    rule,
    status,
    what: "Lockjaw refused the operation",
    why: reasons.get(rule) ?? `The ${rule} rule did not pass.`,
  });

export const boundaryFault = () =>
  fault(
    "storage",
    "Retry once; if it fails again, ask the cell operator to check storage and bindings.",
    503
  );
