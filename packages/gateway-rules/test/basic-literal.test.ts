import { expect, it } from "@effect/vitest";
import {
  parsePlaceholder,
  placeholderNames,
  PlaceholderText,
} from "@lockjaw/domain";
import { Effect, Schema } from "effect";

import { makeCheck } from "../src/placement.js";
import { credential, policies, policy, request } from "./fixtures.js";

it("Basic literal grammar resolves only the password and bounds the literal username", () => {
  const text = `{{secret-basic:user=x-access-token,password=${credential}}}`;
  const placeholder = parsePlaceholder(text);
  expect(placeholder?._tag).toBe("BasicLiteral");
  expect(Schema.is(PlaceholderText)(text)).toBe(true);

  if (placeholder) {
    expect(placeholderNames(placeholder)).toEqual([credential]);
  }

  for (const user of [
    "",
    "a".repeat(65),
    "bad/user",
    "bad:name",
    "name\n",
    "name,foo=bar",
  ]) {
    expect(
      parsePlaceholder(`{{secret-basic:user=${user},password=${credential}}}`)
    ).toBeUndefined();
  }
});

it.effect(
  "Basic literal injection requires explicit policy permission and a whole Authorization header",
  () =>
    Effect.gen(function* basicPermission() {
      const text = `{{secret-basic:user=x-access-token,password=${credential}}}`;

      const target = {
        ...request,
        headers: [{ name: "Authorization", value: text }],
      };

      expect((yield* makeCheck(policies)(target).pipe(Effect.flip))._tag).toBe(
        "PlacementNotAllowed"
      );

      const approved = new Map([
        [
          credential,
          {
            ...policy,
            inject: {
              basicUser: "x-access-token",
              header: "Authorization",
              template: "Bearer {value}",
            },
          },
        ],
      ]);

      expect((yield* makeCheck(approved)(target)).length).toBe(1);

      for (const header of [
        { name: "Authorization", value: `Basic ${text}` },
        { name: "X-Auth", value: text },
      ]) {
        expect(
          (yield* makeCheck(approved)({ ...target, headers: [header] }).pipe(
            Effect.flip
          ))._tag
        ).toBe("PlacementNotAllowed");
      }
    })
);
