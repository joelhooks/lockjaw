// oxlint-disable typescript/promise-function-async -- Replay DO methods are native Promise adapters.
import { expect, it } from "@effect/vitest";
import { Grant, encodeDidKeyP256 } from "@lockjaw/domain";
import { signingKey } from "@rat-king/lexicon/pass-webcrypto";
import {
  NonceBinding,
  signPass,
  signRequest,
  signTicket,
  verifyPass,
  verifyRequest,
  verifyTicket,
} from "@rat-king/lexicon/passes";
import {
  PublicKey,
  Signatures,
  fingerprintBytes,
} from "@rat-king/lexicon/trust";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Effect, Result, Schema } from "effect";

import { Documents } from "../src/caller-auth.js";
import { nonceBinding, passVerifier } from "../src/pass.js";
import { Replay } from "../src/replay-do.js";
import { p256, publicJwk, setup } from "./fixtures.js";

const key = Effect.gen(function* key() {
  const pair = yield* p256();

  const publicKey = yield* Schema.decodeUnknownEffect(PublicKey)(
    yield* publicJwk(pair)
  );

  const did = encodeDidKeyP256(publicKey);

  if (did === undefined) {
    return yield* Effect.die("generated key failed did:key encoding");
  }

  return {
    did,
    pair,
    publicKey,
    signer: signingKey(publicKey, pair.privateKey),
  };
});

const scenario = Effect.gen(function* scenario() {
  const fixture = yield* setup;
  const desk = yield* key;
  const worker = yield* key;
  const host = yield* key;

  const record = {
    $type: "sh.ratking.pass",
    desk: "acme/desk",
    deskDid: "did:web:desk.invalid",
    exp: 1300,
    iat: 1000,
    nonce: "plant-nonce",
    run: "run-1",
    scope: ["sh.secretcell.fetch:acme/*"],
    v: 1,
    worker: worker.did,
  };

  const authority = {
    grantable: new Set(["sh.secretcell.fetch"]),
    issuerScope: ["sh.secretcell.fetch:acme/*"],
    knownDesk: { did: record.deskDid, key: desk.publicKey, name: record.desk },
  };

  const verify = (input: Parameters<typeof verifyPass>[1]) =>
    verifyPass(authority, input, 1000).pipe(
      Effect.provideService(NonceBinding, nonceBinding(fixture.env, 1000)),
      Effect.provide(signatures)
    );

  return { authority, desk, fixture, host, record, verify, worker };
});

it.effect(
  "cell desk ceiling refuses wider scopes before resolve and supports authenticated desk-key rotation",
  () =>
    Effect.gen(function* deskCeiling() {
      const { desk, fixture, record } = yield* scenario;
      const oldKey = yield* key;

      const grant = yield* Schema.decodeUnknownEffect(Grant)({
        createdAt: 1_000_000,
        grantee: { desk: record.desk },
        grantor: "approver",
        id: `g_${"a".repeat(32)}`,
        scope: {
          credentials: ["acme/*"],
          exp: 2_000_000,
          grantees: [],
          hosts: ["api.example.com"],
          ops: ["use"],
        },
      });

      const documents = yield* Schema.decodeUnknownEffect(Documents)([
        {
          authentication: [`${record.deskDid}#old`, `${record.deskDid}#new`],
          id: record.deskDid,
          issuer: "test-host",
          name: record.desk,
          verificationMethod: [oldKey, desk].map((entry, index) => ({
            controller: record.deskDid,
            id: `${record.deskDid}#${index === 0 ? "old" : "new"}`,
            publicKeyJwk: entry.publicKey,
          })),
        },
      ]);

      const verify = (signed: Parameters<typeof verifyPass>[1]) =>
        passVerifier(documents)(JSON.stringify(signed), 1000, fixture.env);

      expect(
        Result.isFailure(
          yield* verify(yield* signPass(desk.signer, record)).pipe(
            Effect.result
          )
        )
      ).toBe(true);
      fixture.grantStore.insert(grant);
      yield* verify(yield* signPass(desk.signer, record));
      yield* verify(
        yield* signPass(desk.signer, {
          ...record,
          scope: ["sh.secretcell.list:acme/*"],
        })
      );

      for (const planted of [
        { ...record, scope: ["sh.secretcell.fetch:other/*"] },
        { ...record, worker: oldKey.did },
      ]) {
        const result = yield* verify(
          yield* signPass(desk.signer, planted)
        ).pipe(Effect.result);

        expect(Result.isFailure(result)).toBe(true);

        if (Result.isFailure(result)) {
          expect(result.failure.status).toBe(401);
          expect(result.failure.what.length).toBeGreaterThan(0);
          expect(result.failure.why.length).toBeGreaterThan(0);
          expect(result.failure.next.length).toBeGreaterThan(0);
        }
      }

      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);

it.effect(
  "vendored verifier plants refuse desk-key workers, widened scope, forged signatures and altered request bytes",
  () =>
    Effect.gen(function* plants() {
      const { desk, record, verify, worker } = yield* scenario;

      for (const planted of [
        { ...record, worker: desk.did },
        { ...record, scope: ["sh.secretcell.fetch:other/*"] },
      ]) {
        const result = yield* verify(
          yield* signPass(desk.signer, planted)
        ).pipe(Effect.result);

        expect(Result.isFailure(result)).toBe(true);

        if (Result.isFailure(result)) {
          expect(result.failure.reason.split(";")).toHaveLength(3);
        }
      }

      const signed = yield* signPass(desk.signer, record);
      expect(
        Result.isFailure(
          yield* verify({ ...signed, signature: "A".repeat(86) }).pipe(
            Effect.result
          )
        )
      ).toBe(true);
      const pass = yield* verify(signed);
      const bytes = new TextEncoder().encode("header.payload");
      const signature = yield* signRequest(worker.signer, bytes);
      yield* verifyRequest(pass, bytes, signature).pipe(
        Effect.provide(signatures)
      );
      expect(
        Result.isFailure(
          yield* verifyRequest(
            pass,
            new TextEncoder().encode("header.altered"),
            signature
          ).pipe(Effect.provide(signatures), Effect.result)
        )
      ).toBe(true);
      expect(
        Result.isFailure(
          yield* verifyRequest(
            pass,
            bytes,
            yield* signRequest(desk.signer, bytes)
          ).pipe(Effect.provide(signatures), Effect.result)
        )
      ).toBe(true);
    }).pipe(Effect.scoped)
);

it.effect(
  "Replay NonceBinding refuses the same nonce on another run and keeps terminal retention after reconstruction",
  () =>
    Effect.gen(function* otherRun() {
      const { desk, fixture, record, verify, worker } = yield* scenario;
      const signed = yield* signPass(desk.signer, record);
      yield* verify(signed);
      yield* verify(signed);

      const result = yield* verify(
        yield* signPass(desk.signer, { ...record, run: "run-2" })
      ).pipe(Effect.result);

      expect(Result.isFailure(result)).toBe(true);

      if (Result.isFailure(result)) {
        expect(result.failure.reason).toContain("already bound");
      }

      const context = fixture.contexts.get("replay");

      if (context === undefined) {
        return yield* Effect.die("missing replay context");
      }

      const restarted = new Replay(context);

      const identity = JSON.stringify({
        run: record.run,
        workerThumbprint: yield* Signatures.use((crypto) =>
          crypto.digest(fingerprintBytes(worker.publicKey))
        ).pipe(Effect.provide(signatures)),
      });

      expect(
        yield* Effect.promise(() =>
          restarted.bind(
            record.deskDid,
            record.nonce,
            identity,
            1_200_000,
            1_100_000
          )
        )
      ).toBe("match");
      expect(
        yield* Effect.promise(() =>
          restarted.bind(
            record.deskDid,
            record.nonce,
            identity,
            1_360_000,
            1_360_000
          )
        )
      ).toBe("match");
      expect(
        yield* Effect.promise(() =>
          restarted.bind(
            record.deskDid,
            record.nonce,
            identity,
            1_600_000,
            1_360_001
          )
        )
      ).toBe("conflict");

      const prior = yield* nonceBinding(fixture.env, 1400).bind(
        record.deskDid,
        record.nonce,
        { run: "run-1", workerThumbprint: "new-key" },
        1600
      );

      expect(prior).toBe("conflict");

      return yield* Effect.void;
    }).pipe(Effect.scoped)
);

it.effect(
  "an expired pass is still refused after its nonce tombstone is pruned",
  () =>
    Effect.gen(function* prunedPass() {
      const { authority, desk, fixture, record, verify } = yield* scenario;
      const signed = yield* signPass(desk.signer, record);
      yield* verify(signed);
      yield* Effect.promise(() => fixture.replay.alarm());

      const sql = fixture.contexts.get("replay")?.storage.sql;

      expect([...(sql?.exec("SELECT nonce FROM pass_nonces") ?? [])]).toEqual(
        []
      );

      const stale = yield* verifyPass(authority, signed, record.exp + 61).pipe(
        Effect.provideService(
          NonceBinding,
          nonceBinding(fixture.env, record.exp + 61)
        ),
        Effect.provide(signatures),
        Effect.result
      );

      expect(Result.isFailure(stale)).toBe(true);

      if (Result.isFailure(stale)) {
        expect(stale.failure.reason).toContain("lifetime");
      }
    }).pipe(Effect.scoped)
);

it.effect(
  "vendored verifier refuses an expired ticket and accepts a pinned current ticket",
  () =>
    Effect.gen(function* tickets() {
      const { desk, host } = yield* scenario;

      const fingerprint = yield* Signatures.use((crypto) =>
        crypto.digest(fingerprintBytes(desk.publicKey))
      ).pipe(Effect.provide(signatures));

      const signed = yield* signTicket(
        host.signer,
        {
          $type: "sh.ratking.ticket",
          did: "did:web:desk.invalid",
          exp: 1300,
          fingerprint,
          iat: 1000,
          issuer: "test-host",
          name: "acme/desk",
          namespace: "acme",
          v: 1,
        },
        desk.publicKey
      );

      const pinned = new Map([
        ["test-host", { key: host.publicKey, namespaces: ["acme"] }],
      ]);

      yield* verifyTicket(pinned, signed, 1000).pipe(
        Effect.provide(signatures)
      );

      const expired = yield* verifyTicket(pinned, signed, 1361).pipe(
        Effect.provide(signatures),
        Effect.result
      );

      expect(Result.isFailure(expired)).toBe(true);
    }).pipe(Effect.scoped)
);
