import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class RouteNotAllowed extends Schema.TaggedError<RouteNotAllowed>()(
  "RouteNotAllowed",
  { credential: CredentialName, rule: Rule }
) {}
