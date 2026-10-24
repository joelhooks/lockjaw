import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class EncodedPlaceholderRefused extends Schema.TaggedError<EncodedPlaceholderRefused>()(
  "EncodedPlaceholderRefused",
  { credential: CredentialName, rule: Rule }
) {}
