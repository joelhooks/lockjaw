import { SignedTicket, verifyTicket } from "@rat-king/lexicon/passes";
import { PublicKey } from "@rat-king/lexicon/trust";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Effect, Schema } from "effect";

import { GatewayFault } from "./fault.js";
import { trustFault } from "./pass.js";

const Issuers = Schema.Array(
  Schema.Struct({
    issuer: Schema.NonEmptyString,
    key: PublicKey,
    namespaces: Schema.Array(Schema.NonEmptyString).check(
      Schema.isMinLength(1)
    ),
  })
).check(Schema.isMinLength(3), Schema.isMaxLength(3));

export const ticketRefused = (why: string) =>
  new GatewayFault({
    credential: "request",
    next: "Ask the desk queue for a fresh name ticket from a pinned host issuer; ask the cell operator to configure TICKET_ISSUERS with three public issuer keys.",
    rule: "name-ticket",
    status: 401,
    what: "Lockjaw refused the name ticket",
    why,
  });

export const nameTicket = Effect.fn("NameTicket.verify")(function* nameTicket(
  text: string,
  binding: string | undefined,
  now: number
) {
  if (binding === undefined) {
    return yield* ticketRefused(
      "TICKET_ISSUERS is not configured; an unverified name cannot use fleet-wide policy."
    );
  }

  const issuers = yield* Schema.decodeUnknownEffect(
    Schema.fromJsonString(Issuers),
    { onExcessProperty: "error" }
  )(binding).pipe(
    Effect.mapError(() =>
      ticketRefused(
        "TICKET_ISSUERS must contain three pinned public keys and their namespaces."
      )
    )
  );

  if (new Set(issuers.map((issuer) => issuer.issuer)).size !== 3) {
    return yield* ticketRefused("Pinned issuer identifiers must be distinct.");
  }

  const signed = yield* Schema.decodeUnknownEffect(
    Schema.fromJsonString(SignedTicket)
  )(text).pipe(
    Effect.mapError(() =>
      ticketRefused("The header is not a signed name ticket envelope.")
    )
  );

  return yield* verifyTicket(
    new Map(issuers.map(({ issuer, ...value }) => [issuer, value])),
    signed,
    now
  ).pipe(
    Effect.provide(signatures),
    Effect.mapError((error) => {
      const { credential, next, status, what, why } = trustFault(error);

      return new GatewayFault({
        credential,
        next,
        rule: "name-ticket",
        status,
        what,
        why,
      });
    })
  );
});
