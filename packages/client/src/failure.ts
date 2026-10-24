import { Schema } from "effect";

import type { PassStale } from "./pass-stale.js";

export class ClientFailure extends Schema.TaggedError<ClientFailure>()(
  "ClientFailure",
  {
    code: Schema.Literals([1, 2, 3]),
    next: Schema.String,
    what: Schema.String,
    why: Schema.String,
  }
) {}

export type ClientError = ClientFailure | PassStale;

export const usage = (what: string, next = "sc --help") =>
  new ClientFailure({
    code: 2,
    next,
    what,
    why: "The client refused this input before sending a request.",
  });

export const transport = () =>
  new ClientFailure({
    code: 3,
    next: "sc list",
    what: "gateway unavailable",
    why: "The gateway request or response stream failed. No retry was made.",
  });

export const renderFailure = (command: string, failure: ClientError) =>
  `sc ${command} failed: ${failure.what}\nWhy: ${failure.why}\nNext: ${failure.next}\n`;
