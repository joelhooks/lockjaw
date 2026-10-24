import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class GatewayUnavailable extends Schema.TaggedError<GatewayUnavailable>()(
  "GatewayUnavailable",
  { credential: CredentialName, rule: Rule }
) {}
