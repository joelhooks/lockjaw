// oxlint-disable typescript/promise-function-async -- Native response readers and DO test adapters are Promise boundaries.
import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, grants, name, setup, target } from "./fixtures.js";

const text = (response: Response) =>
  Effect.promise(async () => await response.text());

const scan = (value: string) => {
  for (let index = 0; index + 8 <= canary.length; index += 1) {
    expect(value).not.toContain(canary.slice(index, index + 8));
  }
};

const seed = (fixture: Effect.Success<typeof setup>) =>
  Effect.gen(function* seedCredential() {
    const set = yield* fixture.call(
      "/v1/set",
      JSON.stringify({ name, value: canary }),
      yield* fixture.token("sh.secretcell.set")
    );

    expect(set.status).toBe(200);
    scan(yield* text(set));

    const approve = yield* fixture.call(
      "/v1/approve",
      JSON.stringify({ name, policy: grants }),
      yield* fixture.token("sh.secretcell.approve")
    );

    expect(approve.status).toBe(200);
    scan(yield* text(approve));
  });

it.live(
  "canary traverses set, approve, fetch and list; every response and raw database stays clean",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;
      yield* seed(fixture);

      const result = yield* fixture.call(
        "/v1/fetch",
        JSON.stringify(target),
        yield* fixture.token()
      );

      expect(result.status).toBe(302);
      expect(fixture.received).toHaveLength(1);
      expect(fixture.received[0]?.redirect).toBe("manual");
      expect(fixture.received[0]?.headers).toEqual([
        { name: "authorization", value: `Bearer ${canary}` },
      ]);
      scan(yield* text(result));
      scan(JSON.stringify([...result.headers]));
      scan(result.statusText);
      scan(result.url);

      const list = yield* fixture.call(
        "/v1/list",
        undefined,
        yield* fixture.token("sh.secretcell.list"),
        "GET"
      );

      expect(list.status).toBe(200);
      scan(yield* text(list));
      const invalid = yield* fixture.call("/no-route", undefined, "bad", "GET");
      scan(yield* text(invalid));

      for (const file of fixture.disk()) {
        scan(new TextDecoder().decode(file));
      }
    }).pipe(Effect.scoped)
);

it.live(
  "every refusal precedes all credential resolves and writes a three-part error and use row",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;
      yield* seed(fixture);

      const bodies = [
        { ...target, url: "https://evil.example/resource" },
        { ...target, url: "http://api.example.com/resource" },
        { ...target, body: "{{secret:canary/key}}" },
        { ...target, url: "https://api.example.com/{{secret:canary/key}}" },
        {
          ...target,
          headers: [
            { name: "authorization", value: "Bearer {{secret:unknown}}" },
          ],
        },
      ];

      let refused = 0;

      const refuse = (body: string, signed: string) =>
        Effect.gen(function* expectRefused() {
          const response = yield* fixture.call("/v1/fetch", body, signed);
          expect(response.status).toBeGreaterThanOrEqual(400);
          const content = yield* text(response);
          scan(content);
          expect(content).toContain('"what":');
          expect(content).toContain('"why":');
          expect(content).toContain('"next":');
          expect(fixture.resolves()).toBe(0);
          refused += 1;
        });

      for (const body of bodies) {
        yield* refuse(JSON.stringify(body), yield* fixture.token());
      }

      for (const override of [
        { exp: 1, iat: 0 },
        { aud: "did:web:wrong.invalid" },
        { lxm: "sh.secretcell.set" },
        { sid: "" },
        { exp: 9_999_999_999 },
      ]) {
        yield* refuse(
          JSON.stringify(target),
          yield* fixture.token("sh.secretcell.fetch", override)
        );
      }

      const replayed = yield* fixture.token();
      yield* refuse(JSON.stringify(bodies[0]), replayed);
      yield* refuse(JSON.stringify(target), replayed);
      yield* Effect.promise(
        async () =>
          await fixture.credential.approve({
            ...grants,
            callers: ["somebody-else"],
          })
      );
      yield* refuse(JSON.stringify(target), yield* fixture.token());
      yield* Effect.promise(
        async () => await fixture.credential.approve(grants)
      );
      yield* Effect.promise(async () => await fixture.credential.revoke());
      yield* refuse(JSON.stringify(target), yield* fixture.token());
      const registry = fixture.contexts.get("registry");

      const rows = [
        ...(registry?.storage.sql.exec("SELECT json FROM attempts") ?? []),
      ];

      expect(rows).toHaveLength(refused + 2);
      scan(JSON.stringify(rows));
    }).pipe(Effect.scoped)
);

it.live(
  "base URL swap strips caller authentication and returns an unfollowed redirect",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;
      yield* seed(fixture);

      const response = yield* fixture.call(
        "/v1/u/api.example.com/resource",
        undefined,
        yield* fixture.token(),
        "GET",
        {
          authorization: "Bearer {{secret:canary/key}}",
          "x-sc-resolution": "headers-only",
        }
      );

      scan(yield* text(response));
      scan(JSON.stringify([...response.headers]));
      scan(response.statusText);
      expect(fixture.resolves()).toBe(1);
      expect(response.status).toBe(302);
      expect(
        fixture.received[0]?.headers.some((header) =>
          header.name.startsWith("x-sc-")
        )
      ).toBe(false);
    }).pipe(Effect.scoped)
);

it.live(
  "saving does not approve hosts; setters cannot approve as anyone but approver",
  () =>
    Effect.gen(function* test() {
      const fixture = yield* setup;

      const saved = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ name, policy: grants, value: canary }),
        yield* fixture.token("sh.secretcell.set")
      );

      expect(saved.status).toBe(200);

      const denied = yield* fixture.call(
        "/v1/fetch",
        JSON.stringify(target),
        yield* fixture.token()
      );

      expect(denied.status).toBe(403);
      expect(fixture.resolves()).toBe(0);

      const description = yield* Effect.promise(
        async () => await fixture.credential.describe()
      );

      expect(description.ok && description.value.policy?.hosts).toEqual([]);
    }).pipe(Effect.scoped)
);
