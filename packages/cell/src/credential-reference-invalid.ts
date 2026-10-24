import { Schema } from "effect";

export class CredentialReferenceInvalid extends Schema.TaggedError<CredentialReferenceInvalid>()(
  "CredentialReferenceInvalid",
  {
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.Literals(["subkey", "approval"]),
    what: Schema.String,
    why: Schema.String,
  }
) {}
