import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class RefreshFailed extends Schema.TaggedError<RefreshFailed>()(
  "RefreshFailed",
  { credential: CredentialName, rule: Rule }
) {}
