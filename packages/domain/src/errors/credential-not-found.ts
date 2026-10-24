import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CredentialNotFound extends Schema.TaggedError<CredentialNotFound>()(
  "CredentialNotFound",
  { credential: CredentialName, rule: Rule }
) {}
