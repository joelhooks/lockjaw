import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, grants, name, setup, target } from "./fixtures.js";

it.live(
  "describe is metadata-only and replay-checked, revoke is setter-only and idempotent",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;
      const { call } = fixture;

      const saved = yield* call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.set")
      );

      expect(saved.status).toBe(200);
      yield* Effect.promise(
        async () => await fixture.credential.approve(grants)
      );
      const signed = yield* fixture.token("sh.secretcell.describe");

      const description = yield* call(
        `/v1/describe?name=${name}`,
        undefined,
        signed,
        "GET"
      );

      expect(description.status).toBe(200);
      const text = yield* Effect.promise(async () => await description.text());
      expect(text.includes(canary)).toBe(false);
      expect(text).not.toContain("ciphertext");
      expect(text).toContain('"version":1');

      const replay = yield* call(
        `/v1/describe?name=${name}`,
        undefined,
        signed,
        "GET"
      );

      expect(replay.status).toBe(401);

      const notSetter = {
        ...fixture.env,
        APPROVER_DID: "did:web:approver.invalid",
        SETTERS: "[]",
      };

      const refused = yield* call(
        "/v1/revoke",
        JSON.stringify({ name }),
        yield* fixture.token("sh.secretcell.revoke"),
        "POST",
        {},
        notSetter
      );

      expect(refused.status).toBe(403);

      const settersOnly = {
        ...fixture.env,
        APPROVER_DID: "did:web:approver.invalid",
      };

      for (let count = 0; count < 2; count += 1) {
        const revoked = yield* call(
          "/v1/revoke",
          JSON.stringify({ name }),
          yield* fixture.token("sh.secretcell.revoke"),
          "POST",
          {},
          settersOnly
        );

        expect(revoked.status).toBe(200);
      }

      const fetch = yield* call(
        "/v1/fetch",
        JSON.stringify(target),
        yield* fixture.token()
      );

      expect(fetch.status).toBe(403);
      expect(fixture.resolves()).toBe(0);

      const rows = [
        ...(fixture.contexts
          .get("registry")
          ?.storage.sql.exec("SELECT json FROM attempts") ?? []),
      ];

      expect(rows).toHaveLength(7);
    }).pipe(Effect.scoped)
);

it.live(
  "unknown describe is a three-part 404 with sc list as its next command",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;

      const response = yield* fixture.call(
        `/v1/describe?name=${name}`,
        undefined,
        yield* fixture.token("sh.secretcell.describe"),
        "GET"
      );

      expect(response.status).toBe(404);
      const text = yield* Effect.promise(async () => await response.text());
      expect(text).toContain('"what":');
      expect(text).toContain('"why":');
      expect(text).toContain('"next":"sc list"');
    }).pipe(Effect.scoped)
);
