// oxlint-disable typescript/promise-function-async -- Native response readers and DO test adapters are Promise boundaries.
import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, grants, name, setup } from "./fixtures.js";

const seed = (fixture: Effect.Success<typeof setup>) =>
  Effect.gen(function* seedCredential() {
    yield* fixture.call(
      "/v1/set",
      JSON.stringify({ name, value: canary }),
      yield* fixture.token("sh.secretcell.set")
    );
    yield* fixture.call(
      "/v1/approve",
      JSON.stringify({ name, policy: grants }),
      yield* fixture.token("sh.secretcell.approve")
    );
  });

const swap = (headers: Readonly<Record<string, string>>) =>
  Effect.gen(function* swapped() {
    const fixture = yield* setup;
    yield* seed(fixture);

    const response = yield* fixture.call(
      "/v1/u/api.example.com/resource",
      undefined,
      yield* fixture.token(),
      "GET",
      {
        accept: "application/json",
        authorization: "Bearer {{secret:canary/key}}",
        ...headers,
      }
    );

    return { fixture, response };
  });

const cases = [
  {
    absent: [
      "connection",
      "keep-alive",
      "proxy-authorization",
      "proxy-connection",
      "te",
      "trailer",
      "transfer-encoding",
      "x-hop",
    ],
    headers: {
      connection: "keep-alive, x-hop",
      "keep-alive": "timeout=5",
      "proxy-authorization": "Basic cHJveHk6cHJveHk=",
      "proxy-connection": "keep-alive",
      te: "trailers",
      trailer: "x-checksum",
      "transfer-encoding": "chunked",
      "x-hop": "listed-by-connection",
    },
    rule: "hop-by-hop",
  },
  {
    absent: [
      "forwarded",
      "host",
      "true-client-ip",
      "x-forwarded-for",
      "x-forwarded-proto",
      "x-real-ip",
    ],
    headers: {
      forwarded: "for=192.0.2.1",
      host: "cell.example.com",
      "true-client-ip": "192.0.2.1",
      "x-forwarded-for": "192.0.2.1",
      "x-forwarded-proto": "https",
      "x-real-ip": "192.0.2.1",
    },
    rule: "client address and host",
  },
  {
    absent: ["cf-connecting-ip", "cf-ipcountry", "cf-ray"],
    headers: {
      "cf-connecting-ip": "192.0.2.1",
      "cf-ipcountry": "XX",
      "cf-ray": "0000000000000000-XXX",
    },
    rule: "Cloudflare edge",
  },
  {
    absent: [
      "cf-access-client-id",
      "cf-access-client-secret",
      "cf-access-jwt-assertion",
    ],
    headers: {
      "cf-access-client-id": "example.access",
      "cf-access-client-secret": "access-secret-example",
      "cf-access-jwt-assertion": "header.payload.signature",
    },
    rule: "Cloudflare Access",
  },
  {
    absent: ["cookie"],
    headers: {
      cookie: "CF_Authorization=header.payload.signature; theme=dark",
    },
    rule: "cookie",
  },
];

it.live.each(cases)(
  "base URL swap does not forward $rule headers upstream",
  ({ absent, headers }) =>
    Effect.gen(function* test() {
      const { fixture, response } = yield* swap(headers);

      expect(response.status).toBe(302);
      expect(fixture.resolves()).toBe(1);

      const sent = (fixture.received[0]?.headers ?? []).map((header) =>
        header.name.toLowerCase()
      );

      expect(sent).toContain("accept");
      expect(sent).toContain("authorization");
      expect(sent.filter((header) => absent.includes(header))).toEqual([]);
    }).pipe(Effect.scoped)
);

it.live(
  "base URL swap still refuses an upgrade that carries a credential",
  () =>
    Effect.gen(function* test() {
      const { fixture, response } = yield* swap({
        connection: "upgrade",
        upgrade: "websocket",
      });

      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(fixture.received).toEqual([]);
      expect(fixture.resolves()).toBe(0);
    }).pipe(Effect.scoped)
);
