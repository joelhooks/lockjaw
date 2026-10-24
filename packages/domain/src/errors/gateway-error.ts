import { Schema } from "effect";

import { BrokerRefused } from "./broker-refused.js";
import { CallerNotAllowed } from "./caller-not-allowed.js";
import { CallerUnauthenticated } from "./caller-unauthenticated.js";
import { CredentialExpired } from "./credential-expired.js";
import { CredentialNeedsAuth } from "./credential-needs-auth.js";
import { CredentialNotFound } from "./credential-not-found.js";
import { CredentialRevoked } from "./credential-revoked.js";
import { EncodedPlaceholderRefused } from "./encoded-placeholder-refused.js";
import { GatewayUnavailable } from "./gateway-unavailable.js";
import { HostNotAllowed } from "./host-not-allowed.js";
import { KeyUnavailable } from "./key-unavailable.js";
import { PlaceholderInAuthority } from "./placeholder-in-authority.js";
import { PlaceholderOutsideHeader } from "./placeholder-outside-header.js";
import { PlacementNotAllowed } from "./placement-not-allowed.js";
import { RefreshFailed } from "./refresh-failed.js";
import { RouteNotAllowed } from "./route-not-allowed.js";
import { SchemeNotHttps } from "./scheme-not-https.js";
import { UpstreamFailed } from "./upstream-failed.js";

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const GatewayError = Schema.Union([
  BrokerRefused,
  CallerNotAllowed,
  CallerUnauthenticated,
  CredentialExpired,
  CredentialNeedsAuth,
  CredentialNotFound,
  CredentialRevoked,
  EncodedPlaceholderRefused,
  GatewayUnavailable,
  HostNotAllowed,
  KeyUnavailable,
  PlaceholderInAuthority,
  PlaceholderOutsideHeader,
  PlacementNotAllowed,
  RefreshFailed,
  RouteNotAllowed,
  SchemeNotHttps,
  UpstreamFailed,
]);

export type GatewayError = typeof GatewayError.Type;
