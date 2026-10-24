import { Schema } from "effect";

export class PassStale extends Schema.TaggedError<PassStale>()("PassStale", {
  code: Schema.Literal(1),
  next: Schema.String,
  what: Schema.Literal("PassStale"),
  why: Schema.String,
}) {}

export const passStale = (subject: "worker pass" | "name ticket") =>
  new PassStale({
    code: 1,
    next: "Check the worker's blocked item in its desk queue. Do not renew from sc.",
    what: "PassStale",
    why: `The ${subject} in SC_PASS_FILE expires in under 30 s. The worker runtime renews 120 s before expiry and has not. No gateway request was sent.`,
  });
