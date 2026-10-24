import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CallerUnauthenticated extends Schema.TaggedError<CallerUnauthenticated>()(
  "CallerUnauthenticated",
  { credential: CredentialName, rule: Rule }
) {}
