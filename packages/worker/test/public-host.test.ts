import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, grants, name, setup, target } from "./fixtures.js";

it.live(
  "non-public request targets return a three-part 403 before resolve or forwarding",
  () =>
    Effect.gen(function* refusedTargets() {
      const fixture = yield* setup;

      const set = yield* fixture.call(
        "/v1/set",
        JSON.stringify({ name, value: canary }),
        yield* fixture.token("sh.secretcell.set")
      );

      expect(set.status).toBe(200);

      const approve = yield* fixture.call(
        "/v1/approve",
        JSON.stringify({ name, policy: grants }),
        yield* fixture.token("sh.secretcell.approve")
      );

      expect(approve.status).toBe(200);

      for (const host of [
        "127.0.0.1",
        [10, 0, 0, 5].join("."),
        [100, 64, 1, 1].join("."),
        "127.1",
        "0x7f.1",
        "2130706433",
        "[::1]",
        ["EXAMPLE", "INTERNAL"].join("."),
        ["example", "ts", "net"].join("."),
        `${["example", "ts", "net"].join(".")}.`,
      ]) {
        const response = yield* fixture.call(
          "/v1/fetch",
          JSON.stringify({ ...target, url: `https://${host}/resource` }),
          yield* fixture.token()
        );

        expect(response.status, host).toBe(403);

        const content = yield* Effect.promise(
          async () => await response.text()
        );

        expect(content).toContain('"rule":"host-not-public"');
        expect(content).toContain('"what":');
        expect(content).toContain(
          '"why":"IP literals and internal or special-use hostnames cannot be approved upstreams."'
        );
        expect(content).toContain(
          '"next":"Use the service\'s public DNS hostname in the policy and the request, not an IP literal or internal name, then retry /v1/fetch."'
        );
        expect(content).not.toContain(canary);
        expect(fixture.resolves()).toBe(0);
        expect(fixture.received).toHaveLength(0);
      }
    }).pipe(Effect.scoped)
);
