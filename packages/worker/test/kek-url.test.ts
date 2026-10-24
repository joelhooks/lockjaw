import { expect, it } from "@effect/vitest";
// oxlint-disable typescript/promise-function-async -- The fake key service and response readers are native Promise boundaries.
import { makeKekLoader } from "@lockjaw/cell";
import type { KekFetch } from "@lockjaw/cell";
import { Effect, Logger } from "effect";

import type { CellBindings } from "../src/credential-do.js";
import { canary, grants, name, setupWith, target } from "./fixtures.js";

const access = "SC_KEK_ACCESS_CANARY_w3Pz8Nq1Lc6Vy4Tg9Hd2Rf7Bx5";

const urlMode: CellBindings = {
  KEK_ACCESS: access,
  KEK_URL: "http://127.0.0.1:8080/kek",
};

const keyService = (statuses: readonly number[]) => {
  let calls = 0;

  const fetcher: KekFetch = () => {
    calls += 1;
    const status = statuses[Math.min(calls, statuses.length) - 1] ?? 200;

    return Promise.resolve(
      new Response(status === 200 ? new Uint8Array(32).fill(5) : null, {
        headers: { "content-type": "application/octet-stream" },
        status,
      })
    );
  };

  return { calls: () => calls, fetcher };
};

const run = (bindings: CellBindings, statuses: readonly number[]) =>
  Effect.gen(function* fixtureWithKeyService() {
    const service = keyService(statuses);
    const lines: string[] = [];

    const logger = Logger.make(({ cause, message }) => {
      lines.push(`${JSON.stringify(message)} ${String(cause)}`);
    });

    const fixture = yield* setupWith({
      kek: { bindings, loader: makeKekLoader(service.fetcher) },
      logger,
    });

    const texts: string[] = [];

    const call = (...args: Parameters<typeof fixture.call>) =>
      fixture.call(...args).pipe(
        Effect.flatMap((response) =>
          Effect.promise(() => response.text()).pipe(
            Effect.map((text) => {
              texts.push(text, JSON.stringify([...response.headers]));

              return { status: response.status, text };
            })
          )
        )
      );

    const set = Effect.gen(function* setCanary() {
      return yield* call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.set")
      );
    });

    const surfaces = () => [
      ...texts,
      ...lines,
      ...fixture.disk().map((bytes) => bytes.toString()),
    ];

    return { call, fixture, service, set, surfaces };
  });

it.live(
  "URL mode serves fetches with the loopback KEK, fetched once per loader",
  () =>
    Effect.gen(function* test() {
      const { call, fixture, service, set, surfaces } = yield* run(
        urlMode,
        [200]
      );

      expect((yield* set).status).toBe(200);
      yield* call(
        "/v1/approve",
        JSON.stringify({ name, policy: grants }),
        yield* fixture.token("sh.secretcell.approve")
      );

      const fetched = yield* call(
        "/v1/fetch",
        JSON.stringify(target),
        yield* fixture.token()
      );

      expect(fetched.status).toBe(302);
      expect(fixture.resolves()).toBe(1);
      expect(service.calls()).toBe(1);
      expect(surfaces().join("\n")).not.toContain(access);
    }).pipe(Effect.scoped)
);

it.live(
  "a failing key service is a three-part 503, and the next request retries",
  () =>
    Effect.gen(function* test() {
      const { service, set, surfaces } = yield* run(urlMode, [401, 200]);
      const refused = yield* set;

      expect(refused.status).toBe(503);
      expect(JSON.parse(refused.text)).toEqual({
        error: {
          credential: "keyring",
          next: "The cell operator must check the guest key service at KEK_URL and the KEK_ACCESS token. Then retry; the cell fetches the KEK again on the next request.",
          rule: "kek",
          what: "Lockjaw could not load its KEK from the key service",
          why: "The key service answered with status 401, not 200.",
        },
      });

      expect((yield* set).status).toBe(200);
      expect(service.calls()).toBe(2);
      expect(surfaces().join("\n")).not.toContain(access);
    }).pipe(Effect.scoped)
);

it.live.each([
  { bindings: { ...urlMode, LOCKJAW_KEK: "{}" }, label: "both modes" },
  { bindings: {}, label: "neither mode" },
  {
    bindings: { ...urlMode, KEK_URL: "http://localhost:8080/kek" },
    label: "a localhost KEK_URL",
  },
])("$label is refused at boot and serves 503", ({ bindings }) =>
  Effect.gen(function* test() {
    const { service, set, surfaces } = yield* run(bindings, [200]);
    const refused = yield* set;

    expect(refused.status).toBe(503);
    expect(JSON.parse(refused.text)).toMatchObject({
      error: {
        rule: "kek",
        what: "Lockjaw has no usable KEK configuration",
      },
    });
    expect(service.calls()).toBe(0);
    expect(surfaces().join("\n")).not.toContain(access);
  }).pipe(Effect.scoped)
);
