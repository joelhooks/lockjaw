// oxlint-disable typescript/promise-function-async -- Native Durable Object RPC boundary.

import { durableSqlPort } from "@lockjaw/cell";
import { DurableObject } from "cloudflare:workers";
import { Clock, Effect } from "effect";

import type { CellBindings, CellContext } from "./credential-do.js";
import { boundaryFault } from "./fault.js";

const NONCE_PRUNE_BATCH = 500;

export class Replay extends DurableObject<Partial<CellBindings>> {
  readonly #sql;
  readonly #ctx: CellContext;
  constructor(ctx: CellContext, env: Partial<CellBindings> = {}) {
    super(ctx, env);
    this.#ctx = ctx;
    this.#sql = durableSqlPort(ctx.storage);
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS replay (key TEXT NOT NULL, jti TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(key,jti))"
    );
    this.#sql.exec(
      "CREATE TABLE IF NOT EXISTS pass_nonces (key TEXT NOT NULL, nonce TEXT NOT NULL, binding TEXT NOT NULL, expires REAL NOT NULL, PRIMARY KEY(key,nonce))"
    );
  }
  async #rearm() {
    const [first] = [
      ...this.#sql.exec(
        "SELECT MIN(at) AS at FROM (SELECT MIN(expires) AS at FROM replay UNION ALL SELECT MIN(expires) + 1 AS at FROM pass_nonces)"
      ),
    ];

    await (first?.at === null || first?.at === undefined
      ? this.#ctx.storage.deleteAlarm()
      : this.#ctx.storage.setAlarm(Number(first.at)));
  }
  async bind(
    key: string,
    nonce: string,
    binding: string,
    expires: number,
    now: number
  ) {
    const result = this.#sql.transactionSync(() => {
      if (!Number.isFinite(now) || !Number.isFinite(expires) || expires < now) {
        return "conflict" as const;
      }

      const [row] = [
        ...this.#sql.exec(
          "SELECT binding, expires FROM pass_nonces WHERE key=? AND nonce=?",
          key,
          nonce
        ),
      ];

      if (row !== undefined) {
        if (row.binding !== binding || Number(row.expires) < now) {
          return "conflict" as const;
        }

        this.#sql.exec(
          "UPDATE pass_nonces SET expires=MAX(expires,?) WHERE key=? AND nonce=?",
          expires,
          key,
          nonce
        );

        return "match" as const;
      }

      this.#sql.exec(
        "INSERT INTO pass_nonces VALUES (?,?,?,?)",
        key,
        nonce,
        binding,
        expires
      );

      return "new" as const;
    });

    if (result !== "conflict") {
      await this.#rearm();
    }

    return result;
  }
  async consume(key: string, jti: string, expires: number, now: number) {
    const accepted = this.#sql.transactionSync(() => {
      this.#sql.exec("DELETE FROM replay WHERE expires <= ?", now);

      if (
        expires <= now ||
        [
          ...this.#sql.exec(
            "SELECT jti FROM replay WHERE key=? AND jti=?",
            key,
            jti
          ),
        ].length
      ) {
        return false;
      }

      this.#sql.exec("INSERT INTO replay VALUES (?,?,?)", key, jti, expires);

      return true;
    });

    await this.#rearm();

    return accepted;
  }
  async alarm() {
    await Effect.runPromise(
      Clock.currentTimeMillis.pipe(
        Effect.flatMap((now) =>
          Effect.tryPromise({
            catch: boundaryFault,
            try: async () => {
              this.#sql.exec("DELETE FROM replay WHERE expires <= ?", now);
              this.#sql.exec(
                "DELETE FROM pass_nonces WHERE rowid IN (SELECT rowid FROM pass_nonces WHERE expires < ? LIMIT ?)",
                now,
                NONCE_PRUNE_BATCH
              );
              await this.#rearm();
            },
          })
        )
      )
    );
  }
}
