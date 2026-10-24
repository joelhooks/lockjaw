// oxlint-disable typescript/promise-function-async -- DO alarm tests call native Promise adapters.
import { expect, it } from "@effect/vitest";
import { CredentialStore, durableSqlPort } from "@lockjaw/cell";
import { Clock, Effect } from "effect";

import type { CellContext } from "../src/credential-do.js";
import { canary, name, setup } from "./fixtures.js";

it.live("expiry and durable refresh backoff drive Credential alarms", () =>
  Effect.gen(function* alarms() {
    const fixture = yield* setup;
    expect(
      (yield* Effect.promise(() => fixture.credential.set(canary))).ok
    ).toBe(true);
    const context = fixture.contexts.get(name);

    if (!context) {
      return yield* Effect.die("Missing fake cell context");
    }

    return yield* CredentialStore.use((store) =>
      Effect.gen(function* backoff() {
        const now = yield* Clock.currentTimeMillis;
        yield* store.scheduleRefresh(now - 1, 1);
        const alarm = yield* Effect.promise(() => fixture.credential.alarm());
        expect(alarm.ok).toBe(true);
        const scheduled = yield* store.refreshSchedule();
        expect(scheduled?.failures).toBe(2);
        expect(scheduled?.at).toBeGreaterThan(now);
        expect(fixture.alarmTimes.get(name)?.at).toBe(scheduled?.at);
        yield* store.clearRefresh();
        const value = yield* store.value();

        if (!value) {
          return yield* Effect.die("Missing encrypted fixture");
        }

        yield* store.replace(value, undefined, now - 1);
        yield* Effect.promise(() => fixture.credential.describe());
        expect(fixture.alarmTimes.get(name)?.at).toBe(now - 1);
        yield* Effect.promise(() => fixture.credential.alarm());

        const description = yield* Effect.promise(() =>
          fixture.credential.describe()
        );

        expect(description.ok && description.value.lifecycle?.state).toBe(
          "expired"
        );
        expect(fixture.alarmTimes.get(name)?.at).toBeUndefined();
        yield* Effect.promise(() => fixture.credential.set(canary));

        const replacement = yield* Effect.promise(() =>
          fixture.credential.describe()
        );

        expect(replacement.ok && replacement.value.lifecycle?.state).toBe(
          "active"
        );
        expect(replacement.ok && replacement.value.meta?.expiresAt).toBeNull();

        return yield* Effect.void;
      })
    ).pipe(
      Effect.provide(CredentialStore.layer(durableSqlPort(context.storage)))
    );
  }).pipe(Effect.scoped)
);

it.live(
  "Replay alarm prunes expired entries without dropping another unexpired token",
  () =>
    Effect.gen(function* replayAlarm() {
      const fixture = yield* setup;
      const now = yield* Clock.currentTimeMillis;
      expect(
        yield* Effect.promise(() =>
          fixture.replay.consume("key", "expired", now + 5000, now - 10_000)
        )
      ).toBe(true);
      expect(
        yield* Effect.promise(() =>
          fixture.replay.consume("key", "valid", now + 60_000, now)
        )
      ).toBe(true);
      const sql = fixture.contexts.get("replay")?.storage.sql;
      sql?.exec("UPDATE replay SET expires=? WHERE jti=?", now - 1, "expired");
      yield* Effect.promise(() => fixture.replay.alarm());
      expect([...(sql?.exec("SELECT jti FROM replay") ?? [])]).toEqual([
        { jti: "valid" },
      ]);
      expect(fixture.alarmTimes.get("replay")?.at).toBe(now + 60_000);
      expect(
        yield* Effect.promise(() =>
          fixture.replay.consume("key", "valid", now + 60_000, now)
        )
      ).toBe(false);
    }).pipe(Effect.scoped)
);

const noncesOf = (fixture: { readonly contexts: Map<string, CellContext> }) =>
  fixture.contexts.get("replay")?.storage.sql;

it.live("Replay alarm keeps a retained nonce and prunes an expired one", () =>
  Effect.gen(function* nonceAlarm() {
    const fixture = yield* setup;
    const now = yield* Clock.currentTimeMillis;

    const bind = (nonce: string, expires: number, at: number) =>
      Effect.promise(() =>
        fixture.replay.bind("desk", nonce, "id", expires, at)
      );

    expect(yield* bind("retained", now + 60_000, now)).toBe("new");
    expect(yield* bind("expired", now - 1000, now - 5000)).toBe("new");

    expect(fixture.alarmTimes.get("replay")?.at).toBe(now - 1000 + 1);
    yield* Effect.promise(() => fixture.replay.alarm());
    expect([
      ...(noncesOf(fixture)?.exec("SELECT nonce FROM pass_nonces") ?? []),
    ]).toEqual([{ nonce: "retained" }]);
    expect(fixture.alarmTimes.get("replay")?.at).toBe(now + 60_000 + 1);
    expect(yield* bind("retained", now + 60_000, now)).toBe("match");
  }).pipe(Effect.scoped)
);

it.live(
  "Replay alarm prunes nonces 500 at a time and re-arms while rows remain",
  () =>
    Effect.gen(function* nonceBatches() {
      const fixture = yield* setup;
      const now = yield* Clock.currentTimeMillis;
      const sql = noncesOf(fixture);

      for (let index = 0; index < 501; index += 1) {
        sql?.exec(
          "INSERT INTO pass_nonces VALUES (?,?,?,?)",
          "desk",
          `n${index}`,
          "id",
          now - 1000
        );
      }

      const count = () =>
        Number(
          [...(sql?.exec("SELECT COUNT(*) AS n FROM pass_nonces") ?? [])][0]?.n
        );

      yield* Effect.promise(() => fixture.replay.alarm());
      expect(count()).toBe(1);
      expect(fixture.alarmTimes.get("replay")?.at).toBe(now - 1000 + 1);
      yield* Effect.promise(() => fixture.replay.alarm());
      expect(count()).toBe(0);
      expect(fixture.alarmTimes.get("replay")?.at).toBeUndefined();
    }).pipe(Effect.scoped)
);
