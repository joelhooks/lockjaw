import { GitHubAppMetadata, Policy } from "@lockjaw/domain";
import { Context, Effect, Layer, Schema } from "effect";

import { StoreUnavailable } from "./store-unavailable.js";

export type SqlValue = string | number | null;

export interface SqlPort {
  readonly transactionSync: <A>(run: () => A) => A;
  readonly exec: (
    query: string,
    ...bindings: SqlValue[]
  ) => Iterable<
    Record<string, string | number | bigint | null | ArrayBuffer | Uint8Array>
  >;
}

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const State = Schema.Literals([
  "empty",
  "active",
  "refreshing",
  "rotating",
  "expired",
  "needsAuth",
  "revoked",
]);

export type State = typeof State.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const LifecycleSnapshot = Schema.Struct({
  recoveryAttempt: Schema.optionalKey(Schema.Int),
  revision: Schema.Int,
  state: State,
  xstate: Schema.optionalKey(Schema.Json),
});

export type LifecycleSnapshot = typeof LifecycleSnapshot.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const Metadata = Schema.Struct({
  createdAt: Schema.Finite,
  description: Schema.String,
  expiresAt: Schema.NullOr(Schema.Finite),
  githubApp: Schema.optionalKey(GitHubAppMetadata),
  kind: Schema.Literals(["key", "oauth", "github-app", "signing", "login"]),
  name: Schema.String,
  owner: Schema.Literals(["agent-secrets", "cell"]),
});

export type Metadata = typeof Metadata.Type;

const Sealed = Schema.Struct({
  ciphertext: Schema.Array(Schema.Int),
  iv: Schema.Array(Schema.Int),
});

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const StoredValue = Schema.Struct({
  sealed: Sealed,
  version: Schema.Int,
  wrapped: Schema.Struct({
    ciphertext: Schema.Array(Schema.Int),
    iv: Schema.Array(Schema.Int),
    kekId: Schema.String,
  }),
});

export type StoredValue = typeof StoredValue.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const Audit = Schema.Struct({
  at: Schema.Finite,
  callerDid: Schema.String,
  callerName: Schema.String,
  decision: Schema.Literals(["allowed", "refused"]),
  grants: Schema.optionalKey(Schema.Array(Schema.String)),
  host: Schema.String,
  method: Schema.String,
  op: Schema.Literals(["lifecycle", "resolve"]),
  pathPrefix: Schema.String,
  reason: Schema.String,
  runHandle: Schema.optionalKey(Schema.String),
  sessionId: Schema.String,
});

export type Audit = typeof Audit.Type;

export { StoreUnavailable } from "./store-unavailable.js";

const Row = Schema.Struct({ json: Schema.String });

const parse = <A, I>(schema: Schema.Codec<A, I>, json: string) =>
  Schema.decodeSync(Schema.fromJsonString(schema))(json);

const boundary = <A>(operation: string, run: () => A) =>
  Effect.try({ catch: () => new StoreUnavailable({ operation }), try: run });

const make = (sql: SqlPort) =>
  Effect.gen(function* makeOperation() {
    yield* boundary("migrate", () => {
      sql.exec(
        "CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)"
      );
      sql.exec(
        "CREATE TABLE IF NOT EXISTS value (slot TEXT PRIMARY KEY CHECK(slot IN ('current','previous','refresh')), json TEXT NOT NULL)"
      );
      sql.exec(
        "CREATE TABLE IF NOT EXISTS policy (id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)"
      );
      sql.exec(
        "CREATE TABLE IF NOT EXISTS lifecycle (id INTEGER PRIMARY KEY CHECK(id=1), json TEXT NOT NULL)"
      );
      sql.exec(
        "CREATE TABLE IF NOT EXISTS uses (id INTEGER PRIMARY KEY, at REAL NOT NULL, json TEXT NOT NULL)"
      );
      sql.exec("CREATE INDEX IF NOT EXISTS uses_at ON uses(at)");
      sql.exec(
        "CREATE TABLE IF NOT EXISTS refresh_schedule (id INTEGER PRIMARY KEY CHECK(id=1), at REAL NOT NULL, failures INTEGER NOT NULL)"
      );
      sql.exec(
        "CREATE TABLE IF NOT EXISTS migration (id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL)"
      );
      sql.exec("INSERT OR IGNORE INTO migration VALUES (1,1)");

      const versions = [
        ...sql.exec("SELECT version FROM migration WHERE id=1"),
      ];

      if (versions[0]?.version !== 1) {
        throw new StoreUnavailable({ operation: "migration-version" });
      }
    });

    const read = <A, I>(
      table: string,
      schema: Schema.Codec<A, I>,
      slot?: string
    ) =>
      boundary("read", () => {
        const rows = [
          ...sql.exec(
            slot === undefined
              ? `SELECT json FROM ${table} WHERE id=1`
              : `SELECT json FROM ${table} WHERE slot=?`,
            ...(slot === undefined ? [] : [slot])
          ),
        ];

        const [row] = rows;

        return row
          ? parse(schema, Schema.decodeUnknownSync(Row)(row).json)
          : undefined;
      });

    const write = (
      table: string,
      value: Metadata | Policy | StoredValue | LifecycleSnapshot,
      slot?: string
    ) => {
      sql.exec(
        slot === undefined
          ? `INSERT OR REPLACE INTO ${table} (id,json) VALUES (?,?)`
          : `INSERT OR REPLACE INTO ${table} (slot,json) VALUES (?,?)`,
        slot ?? 1,
        JSON.stringify(value)
      );
    };

    const append = (entry: Audit) => {
      sql.exec(
        "INSERT INTO uses (at,json) VALUES (?,?)",
        entry.at,
        JSON.stringify(entry)
      );
      sql.exec(
        "DELETE FROM uses WHERE at < ?",
        entry.at - 90 * 24 * 60 * 60 * 1000
      );
      sql.exec(
        "DELETE FROM uses WHERE id IN (SELECT id FROM uses ORDER BY id DESC LIMIT -1 OFFSET 100000)"
      );
    };

    const transaction = <A>(operation: string, run: () => A) =>
      boundary(operation, () => sql.transactionSync(run));

    return {
      clearRefresh: () =>
        transaction("clear-refresh", () => {
          sql.exec("DELETE FROM refresh_schedule");
        }),
      log: (entry: Audit) =>
        transaction("log", () => {
          append(entry);
        }),
      meta: () => read("meta", Metadata),
      policy: () => read("policy", Policy),
      refreshSchedule: () =>
        boundary("refresh-schedule", () => {
          const [row] = [
            ...sql.exec("SELECT at,failures FROM refresh_schedule WHERE id=1"),
          ];

          return row
            ? Schema.decodeUnknownSync(
                Schema.Struct({ at: Schema.Finite, failures: Schema.Int })
              )(row)
            : undefined;
        }),
      replace: (
        value: StoredValue,
        refresh?: StoredValue,
        expiresAt?: number | null
      ) =>
        transaction("replace", () => {
          write("value", value, "current");

          if (refresh) {
            write("value", refresh, "refresh");
          }

          if (expiresAt !== undefined) {
            const [row] = [...sql.exec("SELECT json FROM meta WHERE id=1")];

            if (!row) {
              throw new StoreUnavailable({ operation: "refresh-metadata" });
            }

            const meta = parse(
              Metadata,
              Schema.decodeUnknownSync(Row)(row).json
            );

            write("meta", { ...meta, expiresAt });
          }
        }),
      rotateAbort: () =>
        transaction("rotate-abort", () => {
          sql.exec(
            "INSERT OR REPLACE INTO value (slot,json) SELECT 'current',json FROM value WHERE slot='previous'"
          );
          sql.exec("DELETE FROM value WHERE slot='previous'");
        }),
      rotateBegin: (value: StoredValue) =>
        transaction("rotate-begin", () => {
          sql.exec(
            "INSERT OR REPLACE INTO value (slot,json) SELECT 'previous',json FROM value WHERE slot='current'"
          );
          write("value", value, "current");
        }),
      rotateCommit: () =>
        transaction("rotate-commit", () =>
          sql.exec("DELETE FROM value WHERE slot='previous'")
        ),
      scheduleRefresh: (at: number, failures: number) =>
        transaction("schedule-refresh", () => {
          sql.exec(
            "INSERT OR REPLACE INTO refresh_schedule VALUES (1,?,?)",
            at,
            failures
          );
        }),
      set: (
        value: StoredValue,
        meta: Metadata,
        policy: Policy,
        refresh?: StoredValue
      ) =>
        transaction("set", () => {
          write("meta", meta);
          write("policy", policy);
          sql.exec("DELETE FROM value");
          sql.exec("DELETE FROM refresh_schedule");
          write("value", value, "current");

          if (refresh) {
            write("value", refresh, "refresh");
          }
        }),
      setGithubApp: (githubApp: GitHubAppMetadata, policy: Policy) =>
        transaction("set-github-app", () => {
          const [row] = [...sql.exec("SELECT json FROM meta WHERE id=1")];

          if (!row) {
            throw new StoreUnavailable({ operation: "missing-metadata" });
          }

          const meta = parse(Metadata, Schema.decodeUnknownSync(Row)(row).json);

          if (meta.kind !== "github-app") {
            throw new StoreUnavailable({ operation: "credential-kind" });
          }

          write("meta", { ...meta, githubApp });
          write("policy", policy);
        }),
      setPolicy: (policy: Policy) =>
        transaction("set-policy", () => {
          write("policy", policy);
        }),
      snapshot: () => read("lifecycle", LifecycleSnapshot),
      transition: (snapshot: LifecycleSnapshot, at: number) =>
        transaction("transition", () => {
          write("lifecycle", snapshot);

          if (snapshot.state === "revoked") {
            sql.exec("DELETE FROM value");
          }

          if (
            snapshot.state === "revoked" ||
            snapshot.state === "expired" ||
            snapshot.state === "needsAuth"
          ) {
            sql.exec("DELETE FROM refresh_schedule");
          }

          append({
            at,
            callerDid: "",
            callerName: "",
            decision: "allowed",
            host: "",
            method: "",
            op: "lifecycle",
            pathPrefix: "",
            reason: snapshot.state,
            sessionId: "",
          });
        }),
      uses: () =>
        boundary("uses", () =>
          [...sql.exec("SELECT json FROM uses ORDER BY id")].map((row) =>
            parse(Audit, Schema.decodeUnknownSync(Row)(row).json)
          )
        ),
      value: (slot: "current" | "previous" | "refresh" = "current") =>
        read("value", StoredValue, slot),
    };
  });

export class CredentialStore extends Context.Service<
  CredentialStore,
  Effect.Success<ReturnType<typeof make>>
>()("secret-cell/CredentialStore") {
  static readonly layer = (sql: SqlPort) =>
    Layer.effect(CredentialStore, make(sql));
  static readonly testLayer = CredentialStore.layer;
}
