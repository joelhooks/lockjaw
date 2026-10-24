import { Schema } from "effect";

export class SigningKeyInvalid extends Schema.TaggedError<SigningKeyInvalid>()(
  "SigningKeyInvalid",
  {
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.Literal("signing-key"),
    what: Schema.String,
    why: Schema.String,
  }
) {}
