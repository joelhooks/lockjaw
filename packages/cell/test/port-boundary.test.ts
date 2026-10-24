import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { expect, it } from "@effect/vitest";
import { Effect, Result } from "effect";

import { CredentialStore, StoreUnavailable } from "../src/credential-store.js";
import type { SqlValue } from "../src/credential-store.js";
import { durableSqlPort } from "../src/durable-sql.js";
import { NodeSqlite } from "../src/node-sqlite.js";
import { storeLayer } from "./fixtures.js";

it("transaction SQL is private to Node's database handle, never sent through the application exec port", () => {
  const directory = "packages/cell/src";

  const files = readdirSync(directory, {
    recursive: true,
    withFileTypes: true,
  });

  for (const file of files) {
    if (!file.isFile() || !file.name.endsWith(".ts")) {
      continue;
    }

    const source = readFileSync(path.join(file.parentPath, file.name), "utf-8");

    if (file.name === "node-sqlite.ts") {
      expect(source).not.toMatch(
        /\bsql\s*\.\s*exec\s*\(\s*["'`]\s*(?:BEGIN|SAVEPOINT)\b/iu
      );
      expect(source).toContain(
        'database.exec("SAVEPOINT node_credential_write")'
      );
    } else {
      expect(source).not.toMatch(
        /\bexec\s*\(\s*["'`]\s*(?:BEGIN|SAVEPOINT|COMMIT|RELEASE|ROLLBACK)\b/iu
      );
      expect(source).not.toContain("SAVEPOINT");
    }
  }
});

it.effect(
  "the live-shaped port delegates transactionSync, passes no argument, and rolls back on a write failure",
  () =>
    Effect.gen(function* portTest() {
      const sqlite = yield* NodeSqlite;

      for (const query of ["BEGIN", "SAVEPOINT application", "COMMIT"]) {
        expect(() => sqlite.sql.exec(query)).toThrow(StoreUnavailable);
      }

      let failing = false;

      const storage = {
        sql: {
          exec: (query: string, ...bindings: SqlValue[]) => {
            if (failing && query.startsWith("INSERT OR REPLACE INTO value")) {
              throw new Error("synthetic SQL fault");
            }

            return sqlite.sql.exec(query, ...bindings);
          },
        },
        transactionSync: <A>(run: () => A): A =>
          sqlite.sql.transactionSync(run),
      };

      const port = durableSqlPort(storage);
      port.transactionSync((...args: never[]) => {
        expect(args).toHaveLength(0);
      });
      const store = yield* CredentialStore;
      yield* store.transition({ revision: 1, state: "empty" }, 0);
      const before = yield* store.snapshot();
      const failingStore = CredentialStore.layer(port);
      failing = true;

      const result = yield* CredentialStore.use((other) =>
        other.set(
          {
            sealed: { ciphertext: [1], iv: [2] },
            version: 1,
            wrapped: { ciphertext: [3], iv: [4], kekId: "test" },
          },
          {
            createdAt: 0,
            description: "must roll back",
            expiresAt: null,
            kind: "key",
            name: "test",
            owner: "cell",
          },
          { callers: [], hosts: [], placements: [] }
        )
      ).pipe(Effect.provide(failingStore), Effect.result);

      expect(Result.isFailure(result)).toBe(true);
      expect(yield* store.meta()).toBeUndefined();
      expect(yield* store.policy()).toBeUndefined();
      expect(yield* store.snapshot()).toEqual(before);
    }).pipe(Effect.provide(storeLayer))
);
