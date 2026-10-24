import { Schema } from "effect";

export class RefreshFailure extends Schema.TaggedError<RefreshFailure>()(
  "RefreshFailure",
  { reason: Schema.Literals(["invalid_grant", "retryable"]) }
) {}
