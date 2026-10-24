import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class CallerNotAllowed extends Schema.TaggedError<CallerNotAllowed>()(
  "CallerNotAllowed",
  { credential: CredentialName, rule: Rule }
) {}
