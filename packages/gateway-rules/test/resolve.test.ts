import { expect, it } from "@effect/vitest";
import { CredentialExpired } from "@lockjaw/domain/errors";
import { Effect, Layer, Redacted, Result, Schema } from "effect";

import { Fill, Placement } from "../src/index.js";
import { credential, policies, request } from "./fixtures.js";

const layers = Layer.mergeAll(Fill.testLayer, Placement.testLayer(policies));

it.effect.prop(
  "every string either fills or receives a value-free typed refusal",
  { value: Schema.String },
  ({ value }) =>
    Effect.gen(function* arbitraryValues() {
      const placement = yield* Placement;
      const fill = yield* Fill;

      const result = yield* fill
        .apply(request, yield* placement.check(request), () =>
          Effect.succeed(Redacted.make(value))
        )
        .pipe(Effect.result);

      const permitted =
        value.length > 0 &&
        !/[\r\n\0]/u.test(value) &&
        new TextDecoder().decode(new TextEncoder().encode(value)) === value;

      expect(Result.isSuccess(result)).toBe(permitted);

      if (Result.isSuccess(result)) {
        expect(result.success.request.headers[0]?.value).toBe(
          `Bearer ${value}`
        );
      } else {
        expect(result.failure._tag).toBe("PlacementNotAllowed");
      }
    }).pipe(Effect.provide(layers)),
  { arbitrary: { runs: 150 } }
);

it.effect(
  "wiped values fail safely and typed resolver failures retain their meaning",
  () =>
    Effect.gen(function* resolverBoundary() {
      const placement = yield* Placement;
      const fill = yield* Fill;
      const fills = yield* placement.check(request);
      const canary = "CANARY-private-8c7bc48be272-internal";
      const wiped = Redacted.make(canary);
      expect(Redacted.wipeUnsafe(wiped)).toBe(true);

      const error = yield* fill
        .apply(request, fills, () => Effect.succeed(wiped))
        .pipe(Effect.flip);

      expect(error._tag).toBe("KeyUnavailable");
      expect(error.message).not.toContain(canary);
      expect(String(error)).not.toContain(canary);
      expect(JSON.stringify(error)).not.toContain(canary);
      const expired = new CredentialExpired({ credential, rule: "expired" });
      expect(
        yield* fill
          .apply(request, fills, () => Effect.fail(expired))
          .pipe(Effect.flip)
      ).toBe(expired);
    }).pipe(Effect.provide(layers))
);
