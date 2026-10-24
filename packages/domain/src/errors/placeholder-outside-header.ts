import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class PlaceholderOutsideHeader extends Schema.TaggedError<PlaceholderOutsideHeader>()(
  "PlaceholderOutsideHeader",
  { credential: CredentialName, rule: Rule }
) {}
