// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.

import { durableSqlPort } from "@lockjaw/cell";
import { Grant, GrantId, GrantRecord } from "@lockjaw/domain";
import { maxDepth } from "@lockjaw/gateway-rules";
import { DurableObject } from "cloudflare:workers";
import { Schema } from "effect";

import type { CellBindings, CellContext } from "./credential-do.js";

const Row = Schema.Struct({
  json: Schema.String,
  revoked_at: Schema.NullOr(Schema.Finite),
});

const OwnerRow = Schema.Struct({ grant_id: GrantId });

const DepthRow = Schema.Struct({ depth: Schema.Int });

export type Inserted =
  | { readonly inserted: true }
  | { readonly inserted: false; readonly reason: "parent" | "depth" };

export class Grants extends DurableObject<Partial<CellBindings>> {
  readonly #sql;
  constructor(ctx: CellContext, env: Partial<CellBindings> = {}) {
    super(ctx, env);
    this.#sql = durableSqlPort(ctx.storage);
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, parent TEXT, depth INTEGER NOT NULL, json TEXT NOT NULL, revoked_at REAL)"
    );
    this.#sql.exec(
      "CREATE INDEX IF NOT EXISTS grants_parent ON grants(parent)"
    );
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS owners (credential TEXT PRIMARY KEY, grant_id TEXT NOT NULL)"
    );
  }
  list() {
    return [
      ...this.#sql.exec("SELECT json, revoked_at FROM grants ORDER BY rowid"),
    ].map((row) => {
      const decoded = Schema.decodeUnknownSync(Row)(row);

      return GrantRecord.make({
        grant: Schema.decodeSync(Schema.fromJsonString(Grant))(decoded.json),
        revokedAt: decoded.revoked_at,
      });
    });
  }
  insert(input: Grant): Inserted {
    const grant = Schema.decodeSync(Grant)(input);

    return this.#sql.transactionSync((): Inserted => {
      let depth = 1;

      if (grant.parent !== undefined) {
        const [row] = [
          ...this.#sql.exec(
            "SELECT depth FROM grants WHERE id = ? AND revoked_at IS NULL",
            grant.parent
          ),
        ];

        if (row === undefined) {
          return { inserted: false, reason: "parent" };
        }

        depth = Schema.decodeUnknownSync(DepthRow)(row).depth + 1;
      }

      if (depth > maxDepth) {
        return { inserted: false, reason: "depth" };
      }

      this.#sql.exec(
        "INSERT INTO grants (id, parent, depth, json, revoked_at) VALUES (?,?,?,?,NULL)",
        grant.id,
        grant.parent ?? null,
        depth,
        JSON.stringify(grant)
      );

      return { inserted: true };
    });
  }
  revoke(id: GrantId, at: number) {
    return this.#sql.transactionSync(() => {
      const rows = [
        ...this.#sql.exec(
          "WITH RECURSIVE tree(id) AS (SELECT id FROM grants WHERE id = ? UNION SELECT grants.id FROM grants JOIN tree ON grants.parent = tree.id) UPDATE grants SET revoked_at = ? WHERE id IN (SELECT id FROM tree) AND revoked_at IS NULL RETURNING id",
          id,
          at
        ),
      ];

      return rows.map(
        (row) =>
          Schema.decodeUnknownSync(Schema.Struct({ id: GrantId }))(row).id
      );
    });
  }
  own(credential: string, grant: GrantId) {
    this.#sql.exec(
      "INSERT OR IGNORE INTO owners (credential, grant_id) VALUES (?,?)",
      credential,
      grant
    );
  }
  owner(credential: string) {
    const [row] = [
      ...this.#sql.exec(
        "SELECT grant_id FROM owners WHERE credential = ?",
        credential
      ),
    ];

    return row === undefined
      ? null
      : Schema.decodeUnknownSync(OwnerRow)(row).grant_id;
  }
}
