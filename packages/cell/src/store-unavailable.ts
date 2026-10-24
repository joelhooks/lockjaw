import { Schema } from "effect";

export class StoreUnavailable extends Schema.TaggedError<StoreUnavailable>()(
  "StoreUnavailable",
  { operation: Schema.String }
) {}
