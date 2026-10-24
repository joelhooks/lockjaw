import type { Caller } from "@lockjaw/domain";
import { passSkewSeconds } from "@lockjaw/gateway-rules";
// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
import { verifyRequest } from "@rat-king/lexicon/passes";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Clock, Context, Effect, Layer, Schema } from "effect";

import type { Bindings } from "./bindings.js";
import type { GatewayFault } from "./fault.js";
import { Jwk, denied, parse, splitCompact, validKey, verify } from "./jws.js";
import { nameTicket, ticketRefused } from "./name-ticket.js";
import { passRefused, passVerifier, trustFault } from "./pass.js";

export { base64url, unbase64 } from "./jws.js";

export const ClaimsSchema = Schema.Struct({
  aud: Schema.NonEmptyString,
  exp: Schema.Int,
  iat: Schema.Int,
  iss: Schema.NonEmptyString,
  jti: Schema.String.check(Schema.isMinLength(16)),
  lxm: Schema.NonEmptyString,
  sid: Schema.NonEmptyString,
});

export type Claims = typeof ClaimsSchema.Type;

export const Documents = Schema.Array(
  Schema.Struct({
    authentication: Schema.Array(Schema.String),
    id: Schema.NonEmptyString,
    issuer: Schema.NonEmptyString,
    name: Schema.NonEmptyString,
    verificationMethod: Schema.Array(
      Schema.Struct({
        controller: Schema.String,
        id: Schema.String,
        publicKeyJwk: Jwk,
      })
    ),
  })
);

const Header = Schema.Struct({
  alg: Schema.Literals(["EdDSA", "ES256"]),
  kid: Schema.NonEmptyString,
  typ: Schema.optionalKey(Schema.Literal("JWT")),
});

export interface PassBinding {
  readonly binding: string;
  readonly deskDid: string;
  readonly expires: number;
  readonly nonce: string;
}

export interface Authenticated {
  readonly caller: Caller;
  readonly claims: Claims;
  readonly keyId: string;
  readonly pass?: PassBinding;
}

export interface AuthRequest {
  readonly token: string | null;
  readonly lxm: string;
  readonly pass?: string | null;
  readonly bindings?: Bindings;
  readonly ticket?: string | null;
}

const validClaims = (
  claims: Claims,
  audience: string,
  lxm: string,
  now: number
) =>
  claims.aud === audience &&
  claims.lxm === lxm &&
  claims.iat <= now &&
  claims.exp > now &&
  claims.exp > claims.iat &&
  claims.exp - claims.iat <= 60 &&
  now - claims.iat <= 60;

interface SignedToken {
  readonly claims: Claims;
  readonly header: typeof Header.Type;
  readonly headerText: string;
  readonly payload: string;
  readonly signature: string;
}

const authenticatePass = Effect.fn("CallerAuth.authenticatePass")(
  function* authenticatePass(
    documents: typeof Documents.Type,
    text: string,
    token: SignedToken,
    now: number,
    bindings: Bindings
  ) {
    const { issuer, pass, verified } = yield* passVerifier(documents)(
      text,
      now,
      bindings
    );

    if (token.header.alg !== "ES256") {
      return yield* passRefused(
        "The request token is not signed by the worker key named in the pass.",
        "Sign each request with the ephemeral key whose did:key the desk put in this pass, or ask the desk for a pass naming your key."
      );
    }

    yield* verifyRequest(
      verified,
      new TextEncoder().encode(`${token.headerText}.${token.payload}`),
      token.signature
    ).pipe(Effect.provide(signatures), Effect.mapError(trustFault));

    if (token.claims.iss !== pass.deskDid) {
      return yield* passRefused(
        "The request token's iss is not the desk DID that signed the pass.",
        "Set iss to the pass's deskDid, then retry."
      );
    }

    if (token.claims.sid !== pass.run) {
      return yield* passRefused(
        "The request token's sid does not equal the pass's run handle.",
        "Sign the request with sid set to the run in the pass, then retry."
      );
    }

    const authenticated: Authenticated = {
      caller: {
        did: pass.deskDid,
        issuer,
        name: pass.desk,
        run: {
          expiresAt: pass.exp * 1000,
          handle: pass.run,
          scope: [...pass.scope],
        },
        sid: token.claims.sid,
      },
      claims: token.claims,
      keyId: `${pass.deskDid}#pass:${pass.worker}`,
      pass: {
        binding: `${pass.worker} ${pass.run}`,
        deskDid: pass.deskDid,
        expires: (pass.exp + passSkewSeconds) * 1000,
        nonce: pass.nonce,
      },
    };

    return authenticated;
  }
);

type VerifiedTicket = Effect.Success<ReturnType<typeof nameTicket>>;

const authenticateTicket = Effect.fn("CallerAuth.authenticateTicket")(
  function* authenticateTicket(
    request: AuthRequest,
    token: SignedToken,
    ticket: VerifiedTicket | undefined
  ): Effect.fn.Return<Authenticated, GatewayFault> {
    if (ticket === undefined) {
      return yield* denied();
    }

    if (
      request.lxm !== "sh.secretcell.fetch" &&
      request.lxm !== "sh.secretcell.describe"
    ) {
      return yield* ticketRefused(
        "Ticket-only desks can only fetch and describe fleet-wide credentials, never mutate or use grants."
      );
    }

    if (request.pass !== undefined && request.pass !== null) {
      return yield* ticketRefused(
        "A ticket-only desk has no stored desk grant ceiling for a worker pass."
      );
    }

    if (
      token.header.alg !== "ES256" ||
      !(yield* verify(
        "ES256",
        ticket.key,
        token.signature,
        `${token.headerText}.${token.payload}`
      ))
    ) {
      return yield* ticketRefused(
        "The request signature does not match the ticket's desk key."
      );
    }

    return {
      caller: {
        did: ticket.record.did,
        issuer: ticket.record.issuer,
        name: ticket.record.name,
        sid: token.claims.sid,
        ticketOnly: true,
      },
      claims: token.claims,
      keyId: `${ticket.record.did}#ticket:${ticket.key.x}:${ticket.key.y}`,
    };
  }
);

const checkTicketIdentity = Effect.fn("CallerAuth.checkTicketIdentity")(
  function* checkTicketIdentity(
    ticket: VerifiedTicket | undefined,
    document: (typeof Documents.Type)[number] | undefined,
    issuer: string
  ) {
    if (ticket === undefined) {
      return yield* Effect.void;
    }

    if (ticket.record.did !== issuer) {
      return yield* ticketRefused(
        "The ticket DID does not match the request issuer."
      );
    }

    if (document === undefined) {
      return yield* Effect.void;
    }

    const matches = document.verificationMethod.some(
      (method) =>
        method.controller === document.id &&
        document.authentication.includes(method.id) &&
        method.publicKeyJwk.kty === ticket.key.kty &&
        method.publicKeyJwk.crv === ticket.key.crv &&
        method.publicKeyJwk.x === ticket.key.x &&
        method.publicKeyJwk.y === ticket.key.y
    );

    if (ticket.record.name !== document.name || !matches) {
      return yield* ticketRefused(
        "The ticket name or key does not match the known callers document."
      );
    }

    return yield* Effect.void;
  }
);

export class CallerAuth extends Context.Service<
  CallerAuth,
  {
    readonly authenticate: (
      request: AuthRequest
    ) => Effect.Effect<Authenticated, GatewayFault>;
  }
>()("secret-cell/CallerAuth") {
  static readonly testLayer = (service: CallerAuth["Service"]) =>
    Layer.succeed(CallerAuth, service);
  static readonly layer = (documentsFile: string, audience: string) =>
    Layer.succeed(
      CallerAuth,
      CallerAuth.of({
        authenticate: Effect.fn("CallerAuth.authenticate")(
          function* authenticate(request) {
            const documents = yield* Schema.decodeEffect(
              Schema.fromJsonString(Documents)
            )(documentsFile).pipe(Effect.mapError(denied));

            const parts = splitCompact(request.token);

            if (parts === undefined) {
              return yield* denied();
            }

            const {
              header: headerText,
              payload: claimsText,
              signature: signatureText,
            } = parts;

            const header = yield* Schema.decodeUnknownEffect(
              Schema.fromJsonString(Header)
            )(yield* parse(headerText)).pipe(Effect.mapError(denied));

            const claims = yield* Schema.decodeUnknownEffect(
              Schema.fromJsonString(ClaimsSchema)
            )(yield* parse(claimsText)).pipe(Effect.mapError(denied));

            const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

            if (!validClaims(claims, audience, request.lxm, now)) {
              return yield* denied();
            }

            const document = documents.find((doc) => doc.id === claims.iss);

            const ticket =
              request.ticket === undefined || request.ticket === null
                ? undefined
                : yield* nameTicket(
                    request.ticket,
                    request.bindings?.TICKET_ISSUERS,
                    now
                  );

            yield* checkTicketIdentity(ticket, document, claims.iss);

            if (document === undefined) {
              return yield* authenticateTicket(
                request,
                {
                  claims,
                  header,
                  headerText,
                  payload: claimsText,
                  signature: signatureText,
                },
                ticket
              );
            }

            if (request.pass !== undefined && request.pass !== null) {
              if (request.bindings === undefined) {
                return yield* passRefused(
                  "The pass verifier has no durable bindings.",
                  "Ask the cell operator to configure Replay and Grants."
                );
              }

              return yield* authenticatePass(
                documents,
                request.pass,
                {
                  claims,
                  header,
                  headerText,
                  payload: claimsText,
                  signature: signatureText,
                },
                now,
                request.bindings
              );
            }

            const keyId = header.kid.startsWith("#")
              ? `${claims.iss}${header.kid}`
              : header.kid;

            const method = document.verificationMethod.find(
              (m) => m.id === keyId && m.controller === claims.iss
            );

            if (
              method === undefined ||
              !document.authentication.includes(keyId)
            ) {
              return yield* denied();
            }

            const jwk = method.publicKeyJwk;

            if (
              ticket !== undefined &&
              (jwk.x !== ticket.key.x || jwk.y !== ticket.key.y)
            ) {
              return yield* ticketRefused(
                "The request key does not match the ticket key."
              );
            }

            if (!validKey(header.alg, jwk)) {
              return yield* denied();
            }

            const valid = yield* verify(
              header.alg,
              jwk,
              signatureText,
              `${headerText}.${claimsText}`
            );

            if (!valid) {
              return yield* denied();
            }

            return {
              caller: {
                did: claims.iss,
                issuer: document.issuer,
                name: document.name,
                sid: claims.sid,
              },
              claims,
              keyId,
            };
          }
        ),
      })
    );
}
