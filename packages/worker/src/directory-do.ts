// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.

import { Metadata, durableSqlPort } from "@lockjaw/cell";
import { CredentialName } from "@lockjaw/domain";
import { DurableObject } from "cloudflare:workers";
import { Schema } from "effect";

import type { CellBindings, CellContext } from "./credential-do.js";

const Entry = Schema.Struct({ ...Metadata.fields, name: CredentialName });

export interface Attempt {
  readonly credential: string;
  readonly host: string;
  readonly method: string;
  readonly pathPrefix: string;
  readonly at: number;
  readonly callerDid: string;
  readonly callerName: string;
  readonly sessionId: string;
  readonly operation: string;
  readonly decision: "allowed" | "refused";
  readonly reason: string;
  readonly grants?: readonly string[];
  readonly runHandle?: string;
}

export class Registry extends DurableObject<Partial<CellBindings>> {
  readonly #sql;
  constructor(ctx: CellContext, env: Partial<CellBindings> = {}) {
    super(ctx, env);
    this.#sql = durableSqlPort(ctx.storage);
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS registry (name TEXT PRIMARY KEY, json TEXT NOT NULL)"
    );
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS attempts (id INTEGER PRIMARY KEY, at REAL NOT NULL, json TEXT NOT NULL)"
    );
  }
  list() {
    return [...this.#sql.exec("SELECT json FROM registry ORDER BY name")].map(
      (row) =>
        Schema.decodeSync(Schema.fromJsonString(Entry))(
          Schema.decodeUnknownSync(Schema.Struct({ json: Schema.String }))(row)
            .json
        )
    );
  }
  register(metadata: Metadata) {
    const entry = Entry.make({
      ...metadata,
      name: CredentialName.make(metadata.name),
    });

    this.#sql.exec(
      "INSERT OR REPLACE INTO registry VALUES (?,?)",
      entry.name,
      JSON.stringify(entry)
    );
  }
  record(entry: Attempt) {
    this.#sql.transactionSync(() => {
      this.#sql.exec(
        "INSERT INTO attempts(at,json) VALUES (?,?)",
        entry.at,
        JSON.stringify(entry)
      );
      this.#sql.exec(
        "DELETE FROM attempts WHERE at < ?",
        entry.at - 90 * 86_400_000
      );
      this.#sql.exec(
        "DELETE FROM attempts WHERE id IN (SELECT id FROM attempts ORDER BY id DESC LIMIT -1 OFFSET 100000)"
      );
    });
  }
}
