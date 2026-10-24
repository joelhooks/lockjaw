// oxlint-disable typescript/promise-function-async -- Response body readers are native Promise adapters.
import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, grants, name, setup } from "./fixtures.js";

it.live(
  "setters require the DID allowlist and policy approval requires approver's identity",
  () =>
    Effect.gen(function* permissions() {
      const fixture = yield* setup;

      const setter = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.set"),
        "POST",
        {},
        { ...fixture.env, SETTERS: "[]" }
      );

      expect(setter.status).toBe(403);
      expect(yield* Effect.promise(() => setter.text())).not.toContain(canary);

      const approver = yield* fixture.call(
        "/v1/approve",
        JSON.stringify({ name, policy: grants }),
        yield* fixture.token("sh.secretcell.approve"),
        "POST",
        {},
        { ...fixture.env, APPROVER_DID: "did:web:approver.invalid" }
      );

      expect(approver.status).toBe(403);
      expect(yield* Effect.promise(() => approver.text())).not.toContain(
        canary
      );

      const wrongOperation = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.fetch")
      );

      expect(wrongOperation.status).toBe(401);
      expect(yield* Effect.promise(() => wrongOperation.text())).not.toContain(
        canary
      );
    }).pipe(Effect.scoped)
);

it.live(
  "a modified signature is rejected and concurrent reuse consumes a jti only once",
  () =>
    Effect.gen(function* replayRace() {
      const fixture = yield* setup;
      const signed = yield* fixture.token("sh.secretcell.list");
      const [header = "", payload = "", signature = ""] = signed.split(".");

      const modified = `${header}.${payload}.${
        signature.startsWith("A") ? "B" : "A"
      }${signature.slice(1)}`;

      const invalid = yield* fixture.call(
        "/v1/list",
        undefined,
        modified,
        "GET"
      );

      expect(invalid.status).toBe(401);

      const responses = yield* Effect.all(
        [
          fixture.call("/v1/list", undefined, signed, "GET"),
          fixture.call("/v1/list", undefined, signed, "GET"),
        ],
        { concurrency: "unbounded" }
      );

      expect(
        responses.map((response) => response.status).toSorted((a, b) => a - b)
      ).toEqual([200, 401]);
    }).pipe(Effect.scoped)
);
