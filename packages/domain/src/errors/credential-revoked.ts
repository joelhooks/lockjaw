import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CredentialRevoked extends Schema.TaggedError<CredentialRevoked>()(
  "CredentialRevoked",
  { credential: CredentialName, rule: Rule }
) {}
