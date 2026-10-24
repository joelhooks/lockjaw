// oxlint-disable-next-line typescript/triple-slash-reference -- Node 24 and Workers support the Unicode validation used at credential boundaries.
/// <reference lib="es2024.string" />
import { Schema } from "effect";

export class ValueNotWellFormed extends Schema.TaggedError<ValueNotWellFormed>()(
  "ValueNotWellFormed",
  {
    credential: Schema.String,
    next: Schema.String,
    rule: Schema.Literal("value"),
    what: Schema.String,
    why: Schema.String,
  }
) {
  static readonly refusal = (credential: string) =>
    new ValueNotWellFormed({
      credential,
      next: "Send the value as valid UTF-8; `sc set` reads stdin bytes, so pipe the exact value",
      rule: "value",
      what: "The value is not well-formed Unicode text",
      why: "It has a lone UTF-16 surrogate, which UTF-8 cannot store without changing it.",
    });
}
