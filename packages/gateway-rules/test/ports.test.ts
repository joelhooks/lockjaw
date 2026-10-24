import { expect, it } from "@effect/vitest";
import { CredentialName, Host, Policy } from "@lockjaw/domain";
import { Effect, Schema } from "effect";

import { Placement } from "../src/placement.js";

const name = CredentialName.make("port-key");

const policy = {
  callers: ["test"],
  hosts: [Host.make("api.example.com")],
  placements: ["test"],
};

const request = (port: number) => ({
  headers: [{ name: "authorization", value: "Bearer {{secret:port-key}}" }],
  method: "GET",
  url: `https://api.example.com:${port}/`,
});

it.effect(
  "explicit port is denied by default and allowed only by every credential's policy",
  () =>
    Effect.gen(function* ports() {
      const denied = yield* Placement.use((p) => p.check(request(8443))).pipe(
        Effect.provide(Placement.layer(new Map([[name, policy]]))),
        Effect.result
      );

      expect(denied._tag).toBe("Failure");

      const allowed = yield* Placement.use((p) => p.check(request(8443))).pipe(
        Effect.provide(
          Placement.layer(new Map([[name, { ...policy, ports: [8443] }]]))
        )
      );

      expect(allowed).toHaveLength(1);

      const other = yield* Placement.use((p) => p.check(request(9443))).pipe(
        Effect.provide(
          Placement.layer(new Map([[name, { ...policy, ports: [8443] }]]))
        ),
        Effect.result
      );

      expect(other._tag).toBe("Failure");
    })
);

it("ports are unique integers in 1..65535, excluding the implicit HTTPS port", () => {
  for (const ports of [[0], [65_536], [8443, 8443], [1.5], [443]]) {
    expect(Schema.is(Policy)({ ...policy, ports })).toBe(false);
  }

  expect(Schema.is(Policy)({ ...policy, ports: [1, 65_535, 8443] })).toBe(true);
});
