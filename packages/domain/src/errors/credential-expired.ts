import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CredentialExpired extends Schema.TaggedError<CredentialExpired>()(
  "CredentialExpired",
  { credential: CredentialName, rule: Rule }
) {}
