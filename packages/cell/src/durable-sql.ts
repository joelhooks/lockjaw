import type { SqlPort } from "./credential-store.js";

export interface DurableStoragePort {
  readonly sql: Pick<SqlPort, "exec">;
  readonly transactionSync: SqlPort["transactionSync"];
}

export const durableSqlPort = (storage: DurableStoragePort): SqlPort => ({
  exec: (query, ...bindings) => storage.sql.exec(query, ...bindings),
  transactionSync: (run) => storage.transactionSync(run),
});
