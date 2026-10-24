import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class KeyUnavailable extends Schema.TaggedError<KeyUnavailable>()(
  "KeyUnavailable",
  { credential: CredentialName, rule: Rule }
) {}
