import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CredentialNeedsAuth extends Schema.TaggedError<CredentialNeedsAuth>()(
  "CredentialNeedsAuth",
  { credential: CredentialName, rule: Rule }
) {}
