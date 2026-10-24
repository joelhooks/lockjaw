import { expect, it } from "@effect/vitest";
import { Effect, Redacted } from "effect";
import { TestClock } from "effect/testing";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { Refresher } from "../src/refresher.js";
import {
  caller,
  canary,
  credentialLayer,
  metadata,
  op,
  sameValue,
} from "./fixtures.js";

it.effect(
  "refresh commits the new expiry with the tokens before any waiter can resolve",
  () =>
    Effect.gen(function* expiryTest() {
      const credential = yield* Credential;
      const store = yield* CredentialStore;
      yield* credential.set(Redacted.make(canary), {
        ...metadata,
        expiresAt: 1,
      });
      yield* credential.refreshDue();
      const value = yield* credential.resolve(caller, op);
      expect(sameValue(value, Redacted.make("refreshed-access"))).toBe(true);
      expect((yield* store.meta())?.expiresAt).toBe(1000);
      yield* TestClock.setTime(2);
      expect(
        sameValue(
          yield* credential.resolve(caller, op),
          Redacted.make("refreshed-access")
        )
      ).toBe(true);
    }).pipe(
      Effect.provide(
        credentialLayer(
          Refresher.layer({
            refresh: () =>
              Effect.succeed({
                expiresAt: 1000,
                refreshToken: Redacted.make("refreshed-refresh"),
                value: Redacted.make("refreshed-access"),
              }),
          })
        )
      )
    )
);
