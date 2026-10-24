import { expect, it } from "@effect/vitest";
import { signingKey } from "@rat-king/lexicon/pass-webcrypto";
import { signTicket } from "@rat-king/lexicon/passes";
import {
  PublicKey,
  Signatures,
  fingerprintBytes,
} from "@rat-king/lexicon/trust";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Clock, Effect, Schema } from "effect";
import { TestClock } from "effect/testing";

import type { Bindings } from "../src/bindings.js";
import {
  canary,
  grants,
  name,
  p256,
  publicJwk,
  setupWith,
  target,
} from "./fixtures.js";

const key = Effect.gen(function* key() {
  const pair = yield* p256();

  const publicKey = yield* Schema.decodeUnknownEffect(PublicKey)(
    yield* publicJwk(pair)
  );

  return { pair, publicKey, signer: signingKey(publicKey, pair.privateKey) };
});

const scenario = Effect.gen(function* scenario() {
  yield* TestClock.setTime(1_000_000);

  const fixture = yield* setupWith({
    identities: [{ did: "did:web:known.invalid", name: "acme/known" }],
  });

  const desk = yield* key;
  const host = yield* key;
  const second = yield* key;
  const third = yield* key;
  const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

  const fingerprint = yield* Signatures.use((crypto) =>
    crypto.digest(fingerprintBytes(desk.publicKey))
  ).pipe(Effect.provide(signatures));

  const record = {
    $type: "sh.ratking.ticket",
    did: "did:web:unknown.invalid",
    exp: now + 300,
    fingerprint,
    iat: now,
    issuer: "test-host",
    name: "acme/desk",
    namespace: "acme",
  };

  const binding = JSON.stringify(
    [host, second, third].map((issuer, index) => ({
      issuer: index === 0 ? "test-host" : `test-host-${index}`,
      key: issuer.publicKey,
      namespaces: ["acme"],
    }))
  );

  const env = { ...fixture.env, TICKET_ISSUERS: binding };
  const ticket = yield* signTicket(host.signer, record, desk.publicKey);

  const call = (
    signed = ticket,
    lxm: "fetch" | "describe" | "set" = "fetch",
    bindings: Bindings = env
  ) =>
    Effect.gen(function* ticketCall() {
      const routes = {
        describe: { body: undefined, path: `/v1/describe?name=${name}` },
        fetch: {
          body: JSON.stringify({
            ...target,
            headers: [
              ...target.headers,
              { name: "x-sc-ticket", value: "must-not-forward" },
            ],
          }),
          path: "/v1/fetch",
        },
        set: { body: JSON.stringify({ name, value: canary }), path: "/v1/set" },
      };

      const response = yield* fixture.call(
        routes[lxm].path,
        routes[lxm].body,
        yield* fixture.tokenAs(
          signed.record.did,
          `sh.secretcell.${lxm}`,
          {},
          desk.pair
        ),
        lxm === "describe" ? "GET" : "POST",
        { "x-sc-ticket": JSON.stringify(signed) },
        bindings
      );

      const text = yield* Effect.promise(async () => await response.text());
      expect(text).not.toContain(canary);

      if (response.status >= 400) {
        const refusal = yield* Schema.decodeUnknownEffect(
          Schema.fromJsonString(
            Schema.Struct({
              error: Schema.Struct({
                next: Schema.NonEmptyString,
                what: Schema.NonEmptyString,
                why: Schema.NonEmptyString,
              }),
            })
          )
        )(text);

        expect(refusal.error.next.length).toBeGreaterThan(0);
      }

      return response.status;
    });

  const seed = (callers: string[]) =>
    Effect.gen(function* seedCredential() {
      const saved = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.set")
      );

      expect(saved.status).toBe(200);

      const approved = yield* fixture.call(
        "/v1/approve",
        JSON.stringify({ name, policy: { ...grants, callers } }),
        yield* fixture.token("sh.secretcell.approve")
      );

      expect(approved.status).toBe(200);
    });

  return { call, desk, env, fixture, host, now, record, seed, ticket };
});

it.effect(
  "ticket-only desks fetch and describe only an exact * policy; prefixes, exact names and grants never confer authority",
  () =>
    Effect.gen(function* policy() {
      const { call, fixture, now, seed } = yield* scenario;
      yield* seed(["*"]);
      expect(yield* call()).toBe(302);
      expect(yield* call(undefined, "describe")).toBe(200);
      expect(
        fixture.received[0]?.headers.some(
          (header) => header.name.toLowerCase() === "x-sc-ticket"
        )
      ).toBe(false);
      expect(yield* call(undefined, "set")).toBe(401);

      const granted = yield* fixture.call(
        "/v1/grant",
        JSON.stringify({
          grantee: { desk: "acme/desk" },
          scope: {
            credentials: [name],
            exp: (now + 600) * 1000,
            grantees: [],
            hosts: ["api.example.com"],
            ops: ["use", "describe"],
          },
        }),
        yield* fixture.token("sh.secretcell.grant")
      );

      expect(granted.status).toBe(200);

      for (const callers of [["acme/*"], ["acme/desk"], []]) {
        yield* seed(callers);
        expect(yield* call()).toBe(401);
        expect(yield* call(undefined, "describe")).toBe(401);
      }

      expect(fixture.resolves()).toBe(1);
    }).pipe(Effect.scoped)
);

it.effect(
  "name tickets refuse forged, expired, unpinned and mismatched-known-desk proofs before resolve, including absent public-key bindings",
  () =>
    Effect.gen(function* refusals() {
      const { call, desk, env, fixture, host, now, record, seed, ticket } =
        yield* scenario;

      yield* seed(["*"]);

      const expired = yield* signTicket(
        host.signer,
        { ...record, exp: now - 100, iat: now - 500 },
        desk.publicKey
      );

      const unpinned = yield* signTicket(
        host.signer,
        { ...record, issuer: "untrusted-host" },
        desk.publicKey
      );

      const knownMismatch = yield* signTicket(
        host.signer,
        { ...record, did: "did:web:known.invalid", name: "acme/known" },
        desk.publicKey
      );

      for (const planted of [
        expired,
        unpinned,
        knownMismatch,
        { ...ticket, signature: "A".repeat(86) },
      ]) {
        expect(yield* call(planted)).toBe(401);
      }

      expect(
        yield* call(ticket, "fetch", { ...env, TICKET_ISSUERS: "[]" })
      ).toBe(401);
      expect(yield* call(ticket, "fetch", { ...env, TICKET_ISSUERS: "" })).toBe(
        401
      );
      expect(yield* call(ticket, "fetch", fixture.env)).toBe(401);
      expect(
        yield* call(ticket, "fetch", {
          ...env,
          TICKET_ISSUERS: env.TICKET_ISSUERS.replace(
            '"crv"',
            '"d":"not-private","crv"'
          ),
        })
      ).toBe(401);
      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);
