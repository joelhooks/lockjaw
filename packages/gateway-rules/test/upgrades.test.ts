import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { Placement } from "../src/index.js";
import { policies, request } from "./fixtures.js";

it.effect("credential-bearing upgrades are refused before filling", () =>
  Effect.gen(function* upgrades() {
    const placement = yield* Placement;

    for (const header of [
      { name: "Upgrade", value: "websocket" },
      { name: "Connection", value: "keep-alive, Upgrade" },
    ]) {
      const error = yield* placement
        .check({ ...request, headers: [...request.headers, header] })
        .pipe(Effect.flip);

      expect(error._tag).toBe("BrokerRefused");
    }
  }).pipe(Effect.provide(Placement.testLayer(policies)))
);
