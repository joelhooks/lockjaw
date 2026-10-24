import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class PlaceholderInAuthority extends Schema.TaggedError<PlaceholderInAuthority>()(
  "PlaceholderInAuthority",
  { credential: CredentialName, rule: Rule }
) {}
