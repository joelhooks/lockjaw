import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class UpstreamFailed extends Schema.TaggedError<UpstreamFailed>()(
  "UpstreamFailed",
  { credential: CredentialName, rule: Rule }
) {}
