import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class BrokerRefused extends Schema.TaggedError<BrokerRefused>()(
  "BrokerRefused",
  { credential: CredentialName, rule: Rule }
) {}
