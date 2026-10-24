// oxlint-disable typescript/promise-function-async -- Response body readers are native Promise adapters.
import { expect, it } from "@effect/vitest";
import { CredentialName, encodeDidKeyP256 } from "@lockjaw/domain";
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

import type { Bindings } from "../src/gateway.js";
import { canary, p256, publicJwk, setupWith } from "./fixtures.js";
import type { PassOptions } from "./fixtures.js";

const approver = "did:web:approver.invalid";

const desk = "did:web:acme-desk.invalid";

const beta = "did:web:beta-desk.invalid";

const key = CredentialName.make("acme/key");

const minute = 60_000;

const Refusal = Schema.Struct({
  error: Schema.Struct({
    next: Schema.NonEmptyString,
    rule: Schema.String,
    what: Schema.NonEmptyString,
    why: Schema.NonEmptyString,
  }),
});

const GrantCreated = Schema.Struct({
  grant: Schema.Struct({ id: Schema.String }),
});

const GrantList = Schema.Struct({
  grants: Schema.Array(Schema.Struct({ id: Schema.String })),
});

const Revoked = Schema.Struct({ revoked: Schema.Array(Schema.String) });

const Listed = Schema.Struct({
  credentials: Schema.Array(Schema.Struct({ name: Schema.String })),
});

const Row = Schema.Struct({ json: Schema.String });

const AttemptRow = Schema.Struct({
  decision: Schema.String,
  grants: Schema.optionalKey(Schema.Array(Schema.String)),
  runHandle: Schema.optionalKey(Schema.String),
});

const fetchBody = (host: string) =>
  JSON.stringify({
    headers: [{ name: "authorization", value: "Bearer {{secret:acme/key}}" }],
    method: "GET",
    url: `https://${host}/resource`,
  });

const policy = {
  callers: [],
  hosts: ["api.example.com", "other.example.com"],
  inject: { header: "authorization", template: "Bearer {value}" },
  placements: ["test-host"],
};

interface PassCall extends PassOptions {
  readonly method?: string;
  readonly sid?: string;
  readonly token?: CryptoKeyPair;
  readonly bindings?: Bindings;
}

const delegated = Effect.gen(function* delegated() {
  yield* TestClock.setTime(Date.parse("2026-10-19T12:00:00Z"));

  const fixture = yield* setupWith({
    approver,
    clock: yield* Clock.clockWith(Effect.succeed),
    credentialName: key,
    identities: [
      { did: approver, name: "approver" },
      { did: desk, name: "acme/desk" },
      { did: beta, name: "beta/desk" },
    ],
  });

  const now = yield* Clock.currentTimeMillis;
  const texts: string[] = [];

  const read = (response: Response) =>
    Effect.promise(() => response.text()).pipe(
      Effect.tap((text) =>
        Effect.sync(() => {
          texts.push(text);
        })
      )
    );

  const decoded =
    <A, I>(schema: Schema.Codec<A, I>) =>
    (response: Response) =>
      read(response).pipe(
        Effect.flatMap(
          Schema.decodeUnknownEffect(Schema.fromJsonString(schema))
        ),
        Effect.orDie
      );

  const refusal = decoded(Refusal);

  const as = (
    who: string,
    path: string,
    lxm: string,
    body: string | undefined,
    method = "POST",
    bindings = fixture.env
  ) =>
    Effect.gen(function* call() {
      return yield* fixture.call(
        path,
        body,
        yield* fixture.tokenAs(who, lxm),
        method,
        {},
        bindings
      );
    });

  const root = yield* as(
    approver,
    "/v1/grant",
    "sh.secretcell.grant",
    JSON.stringify({
      grantee: { desk: "acme/desk" },
      scope: {
        credentials: ["acme/*"],
        exp: now + 60 * minute,
        grantees: ["acme/*"],
        hosts: ["api.example.com", "other.example.com"],
        ops: ["use", "describe", "set", "rotate", "revoke", "grant"],
      },
    })
  );

  expect(root.status).toBe(200);

  const rootId = (yield* decoded(GrantCreated)(root)).grant.id;
  const worker = yield* p256();
  const workerKey = yield* publicJwk(worker);

  const viaPass = (
    run: string,
    lxm: string,
    path: string,
    body: string | undefined,
    options: PassCall = {}
  ) =>
    Effect.gen(function* passCall() {
      const pass = yield* fixture.pass(
        desk,
        "acme/desk",
        run,
        workerKey,
        options
      );

      return yield* fixture.call(
        path,
        body,
        yield* fixture.tokenAs(
          desk,
          lxm,
          { sid: options.sid ?? run },
          options.token ?? worker
        ),
        options.method ?? "POST",
        { "x-sc-pass": pass },
        options.bindings ?? fixture.env
      );
    });

  const use = (run: string, options: PassCall = {}, host = "api.example.com") =>
    viaPass(run, "sh.secretcell.fetch", "/v1/fetch", fetchBody(host), options);

  const setKey = (callers: readonly string[] = []) =>
    as(
      desk,
      "/v1/set",
      "sh.secretcell.set",
      JSON.stringify({
        name: key,
        policy: { ...policy, callers },
        value: canary,
      })
    );

  const grantRun = (
    run: string,
    exp: number,
    ops: readonly string[] = ["use"],
    hosts: readonly string[] = ["api.example.com"]
  ) =>
    as(
      desk,
      "/v1/grant",
      "sh.secretcell.grant",
      JSON.stringify({
        grantee: { desk: "acme/desk", runHandle: run },
        scope: { credentials: ["acme/key"], exp, grantees: [], hosts, ops },
      })
    );

  return {
    as,
    decoded,
    fixture,
    grantRun,
    now,
    refusal,
    rootId,
    setKey,
    texts,
    use,
    viaPass,
    worker,
    workerKey,
  };
});

const publicKey = (pair: CryptoKeyPair) =>
  publicJwk(pair).pipe(Effect.flatMap(Schema.decodeUnknownEffect(PublicKey)));

const rows = (
  fixture: Effect.Success<typeof delegated>["fixture"],
  context: string,
  query: string
) =>
  [...(fixture.contexts.get(context)?.storage.sql.exec(query) ?? [])].map(
    (row) => Schema.decodeUnknownSync(Row)(row).json
  );

it.effect(
  "approver roots a desk; the desk sets, clips and delegates; its run uses, is fenced, revoked and expires",
  () =>
    Effect.gen(function* endToEnd() {
      const {
        as,
        decoded,
        fixture,
        grantRun,
        now,
        refusal,
        rootId,
        texts,
        use,
        viaPass,
      } = yield* delegated;

      const clipped = yield* as(
        desk,
        "/v1/set",
        "sh.secretcell.set",
        JSON.stringify({
          name: key,
          policy: { ...policy, hosts: ["api.example.org"] },
          value: canary,
        })
      );

      expect(clipped.status).toBe(403);
      expect((yield* refusal(clipped)).error.why).toContain("hosts");

      const saved = yield* as(
        desk,
        "/v1/set",
        "sh.secretcell.set",
        JSON.stringify({ name: key, policy, value: canary })
      );

      expect(saved.status).toBe(200);
      expect(fixture.grantStore.owner(key)).toBe(rootId);

      const widened = yield* grantRun(
        "run-1",
        now + 30 * minute,
        ["use"],
        ["api.example.com", "evil.example.net"]
      );

      expect(widened.status).toBe(403);

      const widenedError = (yield* refusal(widened)).error;

      expect(widenedError.rule).toBe("grant");
      expect(widenedError.why).toContain("hosts");

      const later = yield* grantRun("run-1", now + 61 * minute);

      expect((yield* refusal(later)).error.why).toContain("exp");

      const granted = yield* grantRun("run-1", now + 30 * minute);

      expect(granted.status).toBe(200);

      const runId = (yield* decoded(GrantCreated)(granted)).grant.id;
      const used = yield* use("run-1");

      expect(used.status).toBe(302);
      yield* Effect.promise(() => used.text());
      expect(fixture.received.at(-1)?.headers[0]?.value).toBe(
        `Bearer ${canary}`
      );
      expect(fixture.resolves()).toBe(1);

      const otherHost = yield* use("run-1", {}, "other.example.com");

      expect(otherHost.status).toBe(403);
      expect((yield* refusal(otherHost)).error.rule).toBe("grant");

      const setRefused = yield* viaPass(
        "run-1",
        "sh.secretcell.set",
        "/v1/set",
        JSON.stringify({ name: key, value: "x" }),
        { scope: ["sh.secretcell.fetch"] }
      );

      expect(setRefused.status).toBe(403);
      expect((yield* refusal(setRefused)).error.rule).toBe("pass");

      const grantRefused = yield* viaPass(
        "run-1",
        "sh.secretcell.grant",
        "/v1/grant",
        JSON.stringify({ grantee: { desk: "acme/desk" }, scope: {} })
      );

      expect(grantRefused.status).toBe(403);
      expect((yield* refusal(grantRefused)).error.rule).toBe("pass");
      expect(fixture.resolves()).toBe(1);

      const listed = yield* decoded(GrantList)(
        yield* as(
          desk,
          "/v1/grants",
          "sh.secretcell.grant.list",
          undefined,
          "GET"
        )
      );

      expect(listed.grants.map((grant) => grant.id)).toEqual([rootId, runId]);

      const outsider = yield* as(
        beta,
        "/v1/grant/revoke",
        "sh.secretcell.grant.revoke",
        JSON.stringify({ id: runId })
      );

      expect(outsider.status).toBe(403);

      const revoked = yield* as(
        desk,
        "/v1/grant/revoke",
        "sh.secretcell.grant.revoke",
        JSON.stringify({ id: runId })
      );

      expect((yield* decoded(Revoked)(revoked)).revoked).toEqual([runId]);

      const afterRevoke = yield* use("run-1");

      expect(afterRevoke.status).toBe(403);
      expect(fixture.resolves()).toBe(1);

      const deskUse = yield* as(
        desk,
        "/v1/fetch",
        "sh.secretcell.fetch",
        fetchBody("other.example.com")
      );

      expect(deskUse.status).toBe(302);
      yield* Effect.promise(() => deskUse.text());
      expect(fixture.resolves()).toBe(2);
      yield* TestClock.adjust(61 * minute);

      const expired = yield* as(
        desk,
        "/v1/fetch",
        "sh.secretcell.fetch",
        fetchBody("api.example.com")
      );

      expect(expired.status).toBe(403);
      expect((yield* refusal(expired)).error.rule).toBe("grant");

      const expiredSet = yield* as(
        desk,
        "/v1/set",
        "sh.secretcell.set",
        JSON.stringify({ name: key, value: "y" })
      );

      expect(expiredSet.status).toBe(403);
      expect(fixture.resolves()).toBe(2);

      const attempts = rows(fixture, "registry", "SELECT json FROM attempts");

      const allowedRun = attempts
        .map((text) =>
          Schema.decodeUnknownSync(Schema.fromJsonString(AttemptRow))(text)
        )
        .find(
          (entry) => entry.runHandle === "run-1" && entry.decision === "allowed"
        );

      expect(allowedRun?.grants).toEqual([rootId, runId]);

      const uses = rows(fixture, key, "SELECT json FROM uses");

      expect(uses.some((text) => text.includes(runId))).toBe(true);

      const grantRows = rows(fixture, "grants", "SELECT json FROM grants");

      for (const surface of [...texts, ...attempts, ...uses, ...grantRows]) {
        expect(surface).not.toContain(canary);
        expect(surface).not.toContain(canary.slice(3, 20));
      }
    }).pipe(Effect.scoped)
);

it.effect(
  "revoking a root cascades, and a manager-owned credential's own callers lose access with it",
  () =>
    Effect.gen(function* cascade() {
      const { as, decoded, fixture, grantRun, now, rootId, setKey, use } =
        yield* delegated;

      yield* setKey(["acme/desk"]);
      yield* grantRun("run-1", now + 30 * minute);

      const revoked = yield* as(
        approver,
        "/v1/grant/revoke",
        "sh.secretcell.grant.revoke",
        JSON.stringify({ id: rootId })
      );

      expect((yield* decoded(Revoked)(revoked)).revoked).toHaveLength(2);

      const deskOwn = yield* as(
        desk,
        "/v1/fetch",
        "sh.secretcell.fetch",
        fetchBody("api.example.com")
      );

      expect(deskOwn.status).toBe(403);
      expect((yield* use("run-1")).status).toBe(401);
      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);

it.effect(
  "worker passes: bad key, wrong sid, overlong, outliving the chain, stale, unpassable scope, bad did:key, foreign signer and name tickets are refused before resolve",
  () =>
    Effect.gen(function* passes() {
      const { fixture, grantRun, now, refusal, setKey, use, workerKey } =
        yield* delegated;

      yield* setKey();
      yield* grantRun("run-1", now + 30 * minute);
      yield* grantRun("run-short", now + 5 * minute);

      const thief = yield* p256();
      const ok = yield* use("run-1");

      expect(ok.status).toBe(302);
      yield* Effect.promise(() => ok.text());

      const foreignWorker = (
        encodeDidKeyP256({
          crv: "P-256",
          kty: "EC",
          x: workerKey.x ?? "",
          y: workerKey.y ?? "",
        }) ?? ""
      ).replace("did:key:zDn", "did:key:zDm");

      const cases = [
        [
          "wrong signing key",
          yield* use("run-1", { token: thief }),
          401,
          "pass",
        ],
        ["sid mismatch", yield* use("run-1", { sid: "run-2" }), 401, "pass"],
        ["overlong pass", yield* use("run-1", { lifetime: 601 }), 401, "pass"],
        [
          "pass outlives grant",
          yield* use("run-short", { lifetime: 600 }),
          403,
          "pass-expiry",
        ],
        ["no grant for run", yield* use("run-9"), 403, "grant"],
        [
          "set in scope",
          yield* use("run-1", { scope: ["sh.secretcell.set"] }),
          401,
          "pass",
        ],
        [
          "bare * pattern",
          yield* use("run-1", { scope: ["sh.secretcell.fetch:*"] }),
          401,
          "pass",
        ],
        ["empty scope", yield* use("run-1", { scope: [] }), 401, "pass"],
        [
          "unknown lxm",
          yield* use("run-1", { scope: ["sh.secretcell.nope"] }),
          401,
          "pass",
        ],
        [
          "scope pattern misses credential",
          yield* use("run-1", { scope: ["sh.secretcell.fetch:acme/other"] }),
          403,
          "pass",
        ],
        [
          "wrong multicodec worker did:key",
          yield* use("run-1", { worker: foreignWorker }),
          401,
          "pass",
        ],
        [
          "foreign desk signer",
          yield* use("run-1", { signer: thief }),
          401,
          "pass",
        ],
      ] as const;

      for (const [label, response, status, rule] of cases) {
        expect([label, response.status]).toEqual([label, status]);
        expect([label, (yield* refusal(response)).error.rule]).toEqual([
          label,
          rule,
        ]);
      }

      const malformed = yield* fixture.call(
        "/v1/fetch",
        fetchBody("api.example.com"),
        yield* fixture.tokenAs(desk, "sh.secretcell.fetch", { sid: "run-1" }),
        "POST",
        { "x-sc-pass": "not.a.pass" }
      );

      expect(malformed.status).toBe(401);

      const nameTicket = yield* fixture.call(
        "/v1/fetch",
        fetchBody("api.example.com"),
        yield* fixture.tokenAs(desk, "sh.secretcell.fetch"),
        "POST",
        { "x-sc-ticket": "a.b.c" }
      );

      expect(nameTicket.status).toBe(401);
      expect((yield* refusal(nameTicket)).error.rule).toBe("name-ticket");

      const pass = yield* fixture.pass(desk, "acme/desk", "run-1", workerKey, {
        lifetime: 120,
      });

      yield* TestClock.adjust(4 * minute);

      const stale = yield* fixture.call(
        "/v1/fetch",
        fetchBody("api.example.com"),
        yield* fixture.tokenAs(
          desk,
          "sh.secretcell.fetch",
          { sid: "run-1" },
          yield* p256()
        ),
        "POST",
        { "x-sc-pass": pass }
      );

      expect(stale.status).toBe(401);
      expect((yield* refusal(stale)).error.why).toContain("lifetime");
      expect(fixture.resolves()).toBe(1);
    }).pipe(Effect.scoped)
);

it.effect(
  "a worker pass with a name ticket for another desk is refused before resolve; its own desk's ticket is accepted",
  () =>
    Effect.gen(function* mismatchedTicket() {
      const { fixture, grantRun, now, refusal, setKey, worker, workerKey } =
        yield* delegated;

      yield* setKey();
      yield* grantRun("run-1", now + 30 * minute);

      const issuers = [yield* p256(), yield* p256(), yield* p256()];
      const host = issuers[0] ?? (yield* Effect.die("no issuer"));
      const hostKey = yield* publicKey(host);

      const bindings: Bindings = {
        ...fixture.env,
        TICKET_ISSUERS: JSON.stringify(
          yield* Effect.all(
            issuers.map((issuer, index) =>
              publicKey(issuer).pipe(
                Effect.map((issuerKey) => ({
                  issuer: index === 0 ? "test-host" : `test-host-${index}`,
                  key: issuerKey,
                  namespaces: ["acme", "beta"],
                }))
              )
            )
          )
        ),
      };

      const seconds = Math.floor(now / 1000);

      const ticketFor = (did: string, name: string) =>
        Effect.gen(function* ticket() {
          const pair = fixture.keys.get(did) ?? (yield* Effect.die(did));
          const deskKey = yield* publicKey(pair);

          const fingerprint = yield* Signatures.use((crypto) =>
            crypto.digest(fingerprintBytes(deskKey))
          ).pipe(Effect.provide(signatures));

          return JSON.stringify(
            yield* signTicket(
              signingKey(hostKey, host.privateKey),
              {
                $type: "sh.ratking.ticket",
                did,
                exp: seconds + 300,
                fingerprint,
                iat: seconds,
                issuer: "test-host",
                name,
                namespace: name.split("/")[0] ?? "",
              },
              deskKey
            )
          );
        });

      const withTicket = (ticket: string) =>
        Effect.gen(function* passAndTicket() {
          return yield* fixture.call(
            "/v1/fetch",
            fetchBody("api.example.com"),
            yield* fixture.tokenAs(
              desk,
              "sh.secretcell.fetch",
              { sid: "run-1" },
              worker
            ),
            "POST",
            {
              "x-sc-pass": yield* fixture.pass(
                desk,
                "acme/desk",
                "run-1",
                workerKey
              ),
              "x-sc-ticket": ticket,
            },
            bindings
          );
        });

      for (const [label, ticket] of [
        ["another desk", yield* ticketFor(beta, "beta/desk")],
        ["another name", yield* ticketFor(desk, "acme/other")],
      ] as const) {
        const response = yield* withTicket(ticket);

        expect([label, response.status]).toEqual([label, 401]);
        expect([label, (yield* refusal(response)).error.rule]).toEqual([
          label,
          "name-ticket",
        ]);
      }

      expect(fixture.resolves()).toBe(0);

      const own = yield* withTicket(yield* ticketFor(desk, "acme/desk"));

      expect(own.status).toBe(302);
      yield* Effect.promise(() => own.text());
      expect(fixture.resolves()).toBe(1);
    }).pipe(Effect.scoped)
);

it.effect(
  "a stolen worker pass presented with the thief's own key is refused before resolve",
  () =>
    Effect.gen(function* stolen() {
      const { fixture, grantRun, now, refusal, setKey, workerKey } =
        yield* delegated;

      yield* setKey();
      yield* grantRun("run-1", now + 30 * minute);

      const pass = yield* fixture.pass(desk, "acme/desk", "run-1", workerKey);
      const thief = yield* p256();

      const response = yield* fixture.call(
        "/v1/fetch",
        fetchBody("api.example.com"),
        yield* fixture.tokenAs(
          desk,
          "sh.secretcell.fetch",
          { sid: "run-1" },
          thief
        ),
        "POST",
        { "x-sc-pass": pass }
      );

      expect(response.status).toBe(401);

      const { error } = yield* refusal(response);

      expect(error.rule).toBe("pass");
      expect(error.why).toContain("worker key");
      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);

it.effect(
  "pass callers are grant-only: no setter, policy-caller or approver rights through the desk's DID",
  () =>
    Effect.gen(function* grantOnly() {
      const { as, fixture, now, refusal, setKey, use, viaPass } =
        yield* delegated;

      yield* setKey(["acme/desk"]);

      const deskOwn = yield* as(
        desk,
        "/v1/fetch",
        "sh.secretcell.fetch",
        fetchBody("api.example.com")
      );

      expect(deskOwn.status).toBe(302);
      yield* Effect.promise(() => deskOwn.text());

      const policyCaller = yield* use("run-1");

      expect(policyCaller.status).toBe(403);
      expect((yield* refusal(policyCaller)).error.rule).toBe("grant");

      const asSetter = yield* viaPass(
        "run-1",
        "sh.secretcell.set",
        "/v1/set",
        JSON.stringify({ name: key, value: "z" }),
        {
          bindings: { ...fixture.env, SETTERS: JSON.stringify([desk]) },
          scope: ["sh.secretcell.fetch"],
        }
      );

      expect(asSetter.status).toBe(403);
      expect((yield* refusal(asSetter)).error.rule).toBe("pass");

      const asApprover = { ...fixture.env, APPROVER_DID: desk };

      const approve = yield* viaPass(
        "run-1",
        "sh.secretcell.approve",
        "/v1/approve",
        JSON.stringify({ name: key, policy }),
        { bindings: asApprover }
      );

      expect(approve.status).toBe(403);

      const rootGrant = yield* viaPass(
        "run-1",
        "sh.secretcell.grant",
        "/v1/grant",
        JSON.stringify({
          grantee: { desk: "acme/desk", runHandle: "run-1" },
          scope: {
            credentials: ["*"],
            exp: now + minute,
            grantees: [],
            hosts: ["api.example.com"],
            ops: ["use"],
          },
        }),
        { bindings: asApprover }
      );

      expect(rootGrant.status).toBe(403);

      const list = yield* viaPass(
        "run-1",
        "sh.secretcell.list",
        "/v1/list",
        undefined,
        { method: "GET", scope: ["sh.secretcell.list"] }
      );

      expect(list.status).toBe(200);
      expect(yield* Effect.promise(() => list.text())).toBe(
        '{"credentials":[]}'
      );
      expect(fixture.resolves()).toBe(1);
    }).pipe(Effect.scoped)
);

it.effect(
  "a pass scope wider than the stored grant authorises only the intersection",
  () =>
    Effect.gen(function* intersection() {
      const { fixture, grantRun, now, refusal, setKey, use, viaPass } =
        yield* delegated;

      yield* setKey();
      yield* grantRun("run-1", now + 30 * minute, ["use"]);

      const wide = [
        "sh.secretcell.fetch",
        "sh.secretcell.describe",
        "sh.secretcell.list",
      ];

      const fetched = yield* use("run-1", { scope: wide });

      expect(fetched.status).toBe(302);
      yield* Effect.promise(() => fetched.text());

      const described = yield* viaPass(
        "run-1",
        "sh.secretcell.describe",
        `/v1/describe?name=${key}`,
        undefined,
        { method: "GET", scope: wide }
      );

      expect(described.status).toBe(403);
      expect((yield* refusal(described)).error.rule).toBe("grant");

      const otherHost = yield* use(
        "run-1",
        { scope: wide },
        "other.example.com"
      );

      expect((yield* refusal(otherHost)).error.rule).toBe("grant");

      yield* grantRun("run-2", now + 30 * minute, ["use", "describe"]);

      const narrowPass = yield* viaPass(
        "run-2",
        "sh.secretcell.describe",
        `/v1/describe?name=${key}`,
        undefined,
        { method: "GET", scope: ["sh.secretcell.fetch"] }
      );

      expect(narrowPass.status).toBe(403);
      expect((yield* refusal(narrowPass)).error.rule).toBe("pass");

      const describedBoth = yield* viaPass(
        "run-2",
        "sh.secretcell.describe",
        `/v1/describe?name=${key}`,
        undefined,
        { method: "GET", scope: ["sh.secretcell.describe:acme/*"] }
      );

      expect(describedBoth.status).toBe(200);
      expect(fixture.resolves()).toBe(1);
    }).pipe(Effect.scoped)
);

it.effect(
  "pass nonces bind on first use to worker key and run, and an expired binding stays dead",
  () =>
    Effect.gen(function* nonces() {
      const { fixture, grantRun, now, refusal, setKey, workerKey, worker } =
        yield* delegated;

      yield* setKey();
      yield* grantRun("run-1", now + 30 * minute);
      yield* grantRun("run-2", now + 30 * minute);

      const nonce = "fixed-nonce-0123456789abcdef";

      const present = (run: string) =>
        Effect.gen(function* presentPass() {
          const pass = yield* fixture.pass(desk, "acme/desk", run, workerKey, {
            nonce,
          });

          return yield* fixture.call(
            "/v1/fetch",
            fetchBody("api.example.com"),
            yield* fixture.tokenAs(
              desk,
              "sh.secretcell.fetch",
              { sid: run },
              worker
            ),
            "POST",
            { "x-sc-pass": pass }
          );
        });

      const reuse = yield* fixture.pass(desk, "acme/desk", "run-1", workerKey, {
        nonce,
      });

      for (const attempt of [1, 2]) {
        const response = yield* fixture.call(
          "/v1/fetch",
          fetchBody("api.example.com"),
          yield* fixture.tokenAs(
            desk,
            "sh.secretcell.fetch",
            { sid: "run-1" },
            worker
          ),
          "POST",
          { "x-sc-pass": reuse }
        );

        expect([attempt, response.status]).toEqual([attempt, 302]);
        yield* Effect.promise(() => response.text());
      }

      const otherRun = yield* present("run-2");

      expect(otherRun.status).toBe(401);
      expect((yield* refusal(otherRun)).error.why).toContain("already bound");

      yield* TestClock.adjust(7 * minute);

      const dead = yield* fixture.call(
        "/v1/fetch",
        fetchBody("api.example.com"),
        yield* fixture.tokenAs(
          desk,
          "sh.secretcell.fetch",
          { sid: "run-1" },
          worker
        ),
        "POST",
        { "x-sc-pass": reuse }
      );

      expect(dead.status).toBe(401);
      expect(fixture.resolves()).toBe(2);
    }).pipe(Effect.scoped)
);

it.effect(
  "list under a pass shows only credentials the run grant covers, never the desk's full view",
  () =>
    Effect.gen(function* listing() {
      const { as, decoded, fixture, grantRun, now, setKey, viaPass } =
        yield* delegated;

      yield* setKey();

      fixture.registry.register({
        createdAt: now,
        description: "",
        expiresAt: null,
        kind: "key",
        name: "acme/other",
        owner: "cell",
      });

      yield* grantRun("run-1", now + 30 * minute);

      const deskView = yield* decoded(Listed)(
        yield* as(desk, "/v1/list", "sh.secretcell.list", undefined, "GET")
      );

      expect(deskView.credentials.map((entry) => entry.name)).toEqual([
        "acme/key",
        "acme/other",
      ]);

      const runView = yield* decoded(Listed)(
        yield* viaPass("run-1", "sh.secretcell.list", "/v1/list", undefined, {
          method: "GET",
          scope: ["sh.secretcell.list", "sh.secretcell.fetch"],
        })
      );

      expect(runView.credentials.map((entry) => entry.name)).toEqual([
        "acme/key",
      ]);

      const narrowed = yield* decoded(Listed)(
        yield* viaPass("run-1", "sh.secretcell.list", "/v1/list", undefined, {
          method: "GET",
          scope: ["sh.secretcell.list:acme/other"],
        })
      );

      expect(narrowed.credentials).toEqual([]);
    }).pipe(Effect.scoped)
);
