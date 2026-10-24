import { expect, it } from "@effect/vitest";
import { Effect, Redacted, Result } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import type { Audit } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Keyring } from "../src/keyring.js";
import { NodeSqlite } from "../src/node-sqlite.js";
import {
  caller,
  canary,
  dependencies,
  metadata,
  name,
  op,
  sameValue,
  storeLayer,
} from "./fixtures.js";

const entry: Audit = {
  at: 0,
  callerDid: "caller",
  callerName: "test/agent",
  decision: "allowed",
  host: "api.example.com",
  method: "GET",
  op: "resolve",
  pathPrefix: "/allowed/",
  reason: "authorized",
  sessionId: "test",
};

it.effect(
  "prunes uses at 90 days and 100k rows on each write, with a migration row",
  () =>
    Effect.gen(function* retentionTest() {
      const store = yield* CredentialStore;
      const sqlite = yield* NodeSqlite;
      expect(
        [...sqlite.sql.exec("SELECT version FROM migration")][0]?.version
      ).toBe(1);
      yield* store.log(entry);
      yield* store.log({ ...entry, at: 90 * 24 * 60 * 60 * 1000 + 1 });
      expect((yield* store.uses()).length).toBe(1);
      sqlite.sql.exec(
        "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100001) INSERT INTO uses (at,json) SELECT ?,? FROM n",
        entry.at,
        JSON.stringify(entry)
      );
      yield* store.log(entry);
      expect(
        [...sqlite.sql.exec("SELECT COUNT(*) AS total FROM uses")][0]?.total
      ).toBe(100_000);
    }).pipe(Effect.provide(storeLayer))
);

it.effect(
  "malformed persisted rows and SQL errors fail with sanitized typed errors",
  () =>
    Effect.gen(function* badRowTest() {
      const store = yield* CredentialStore;
      const sqlite = yield* NodeSqlite;
      sqlite.sql.exec("INSERT INTO meta VALUES (1,?)", canary);
      const invalid = yield* store.meta().pipe(Effect.result);
      expect(Result.isFailure(invalid)).toBe(true);
      expect(JSON.stringify(invalid)).not.toContain(canary);

      const broken = CredentialStore.layer({
        exec: () => {
          throw new Error(canary);
        },
        transactionSync: sqlite.sql.transactionSync,
      });

      const failure = yield* CredentialStore.use((service) =>
        service.meta()
      ).pipe(Effect.provide(broken), Effect.result);

      expect(Result.isFailure(failure)).toBe(true);
      expect(JSON.stringify(failure)).not.toContain(canary);
    }).pipe(Effect.provide(storeLayer))
);

it.effect(
  "rotation abort and active snapshots survive service restart; interrupted refresh fails closed",
  () =>
    Effect.gen(function* restartTest() {
      const store = yield* CredentialStore;
      const ring = yield* Keyring;
      const dek = yield* ring.newDek();
      const wrapped = yield* ring.wrap(dek, name);
      const sealed = yield* ring.encrypt(Redacted.make(canary), dek, name, 1);
      yield* store.set(
        { sealed, version: 1, wrapped },
        metadata,
        metadata.policy
      );
      yield* store.transition({ revision: 2, state: "active" }, 0);
      yield* Effect.gen(function* firstActivation() {
        const credential = yield* Credential;
        yield* credential.rotateBegin(Redacted.make("next-value"));
      }).pipe(Effect.scoped, Effect.provide(Credential.layer(name)));
      yield* Effect.gen(function* secondActivation() {
        const credential = yield* Credential;
        expect((yield* credential.describe()).lifecycle?.state).toBe(
          "rotating"
        );
        expect((yield* store.snapshot())?.xstate).toMatchObject({
          value: "rotating",
        });
        yield* credential.rotateAbort();
        expect(
          sameValue(
            yield* credential.resolve(caller, op),
            Redacted.make(canary)
          )
        ).toBe(true);
      }).pipe(Effect.scoped, Effect.provide(Credential.layer(name)));
      yield* store.transition({ revision: 5, state: "refreshing" }, 0);
      yield* Effect.gen(function* interruptedActivation() {
        const credential = yield* Credential;
        expect((yield* credential.describe()).lifecycle?.state).toBe(
          "needsAuth"
        );
        expect(
          Result.isFailure(
            yield* credential.resolve(caller, op).pipe(Effect.result)
          )
        ).toBe(true);
      }).pipe(Effect.scoped, Effect.provide(Credential.layer(name)));
    }).pipe(Effect.provide(dependencies()))
);
