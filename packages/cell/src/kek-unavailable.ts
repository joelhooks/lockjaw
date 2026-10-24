import { Schema } from "effect";

export class KekUnavailable extends Schema.TaggedError<KekUnavailable>()(
  "KekUnavailable",
  {
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.Literal("kek"),
    what: Schema.String,
    why: Schema.String,
  }
) {}
