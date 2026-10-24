import { Schema } from "effect";

import { CredentialName, Rule } from "../index.js";

export class PlacementNotAllowed extends Schema.TaggedError<PlacementNotAllowed>()(
  "PlacementNotAllowed",
  { credential: CredentialName, rule: Rule }
) {}
