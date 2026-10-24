import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class HostNotAllowed extends Schema.TaggedError<HostNotAllowed>()(
  "HostNotAllowed",
  { credential: CredentialName, rule: Rule }
) {}
