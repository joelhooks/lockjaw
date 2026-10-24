import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import { Context, Effect, Layer } from "effect";

import { CredentialStore, StoreUnavailable } from "./credential-store.js";
import type { SqlPort, SqlValue } from "./credential-store.js";

const acquire = () => {
  const directory = mkdtempSync(path.join(tmpdir(), "secret-cell-"));
  const file = path.join(directory, "credential.sqlite");
  const database = new DatabaseSync(file);
  database.exec("PRAGMA journal_mode=WAL");
  let closed = false;

  const close = () => {
    if (!closed) {
      database.close();
      closed = true;
    }
  };

  const sql: SqlPort = {
    exec: (query: string, ...bindings: SqlValue[]) => {
      if (
        /^\s*(?:BEGIN|SAVEPOINT|COMMIT|END|RELEASE|ROLLBACK)\b/iu.test(query)
      ) {
        throw new StoreUnavailable({ operation: "transaction-control" });
      }

      const statement = database.prepare(query);

      if (statement.columns().length > 0) {
        return statement.all(...bindings);
      }

      statement.run(...bindings);

      return [];
    },
    transactionSync: <A>(run: () => A): A => {
      database.exec("SAVEPOINT node_credential_write");

      try {
        const result = run();
        database.exec("RELEASE node_credential_write");

        return result;
      } catch (error) {
        database.exec("ROLLBACK TO node_credential_write");
        database.exec("RELEASE node_credential_write");
        throw error;
      }
    },
  };

  return { close, directory, path: file, sql };
};

export class NodeSqlite extends Context.Service<
  NodeSqlite,
  ReturnType<typeof acquire>
>()("secret-cell/NodeSqlite") {
  static readonly layer = Layer.effect(
    NodeSqlite,
    Effect.acquireRelease(Effect.sync(acquire), (resource) =>
      Effect.sync(() => {
        resource.close();
        rmSync(resource.directory, { recursive: true });
      })
    )
  );
}

export const nodeStoreLayer = Layer.effect(
  CredentialStore,
  Effect.gen(function* nodeStoreLayer() {
    const sqlite = yield* NodeSqlite;

    return yield* Effect.service(CredentialStore).pipe(
      Effect.provide(CredentialStore.layer(sqlite.sql))
    );
  })
);
