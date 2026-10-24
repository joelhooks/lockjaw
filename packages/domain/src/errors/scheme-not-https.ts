import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class SchemeNotHttps extends Schema.TaggedError<SchemeNotHttps>()(
  "SchemeNotHttps",
  { credential: CredentialName, rule: Rule }
) {}
