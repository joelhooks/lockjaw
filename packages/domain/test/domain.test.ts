import { expect, it } from "@effect/vitest";
import { Effect, Redacted, Schema } from "effect";

import * as Errors from "../src/errors.js";
import {
  Caller,
  CredentialName,
  Host,
  Operation,
  Placeholder,
  PlaceholderText,
  Policy,
  Route,
  Rule,
  UseRecord,
  parsePlaceholder,
} from "../src/index.js";

it.prop(
  "credential names match the complete charset and length",
  { text: Schema.String },
  ({ text }) => {
    expect(Schema.is(CredentialName)(text)).toBe(
      text.length >= 1 &&
        text.length <= 128 &&
        Array.from(text, (char) =>
          "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-".includes(
            char
          )
        ).every(Boolean)
    );
  }
);

it("host grammar rejects authority syntax and unsafe wildcards", () => {
  for (const host of [
    "*.com",
    "*.github.io",
    "*.co.uk",
    "*.pages.dev",
    "https://example.com",
    "example.com:443",
    "example.com/path",
    "UPPER.com",
    "*.*.example.com",
    "*.a.example.com",
    "*.127.0.0.1",
    "example.com\n",
  ]) {
    expect(Schema.is(Host)(host), host).toBe(false);
  }

  for (const host of [
    "example.com",
    "api.example.com",
    "*.example.com",
    "*.foo.co.uk",
    "*.alice.github.io",
  ]) {
    expect(Schema.is(Host)(host), host).toBe(true);
  }
});

it("placeholder grammar keeps the literal documentation form inert", () => {
  expect(parsePlaceholder("{{secret:<name>}} ")).toBeUndefined();
  expect(parsePlaceholder("{{secret:<name>}}")).toBeUndefined();
  expect(parsePlaceholder("{{secret:a}}\n")).toBeUndefined();
  expect(Schema.is(PlaceholderText)("{{secret:<name>}}")).toBe(false);
  expect(parsePlaceholder("{{secret:a/b-1}}")).toEqual(
    Placeholder.cases.Secret.make({ name: CredentialName.make("a/b-1") })
  );
  expect(
    parsePlaceholder("{{secret-basic:username=user,password=pass}}")
  ).toEqual(
    Placeholder.cases.Basic.make({
      password: CredentialName.make("pass"),
      username: CredentialName.make("user"),
    })
  );
});

it.effect(
  "all domain metadata and every typed error omit the fixed canary",
  () =>
    Effect.gen(function* operation() {
      const canary = "CANARY-private-8c7bc48be272-internal";
      const name = CredentialName.make("canary-name");

      const policy = Policy.make({
        callers: ["tester"],
        hosts: [Host.make("example.com")],
        inject: { header: "Authorization", template: "Bearer {value}" },
        placements: ["test"],
      });

      const record = UseRecord.make({
        at: 1,
        callerDid: "did:test",
        callerName: "tester",
        credential: name,
        decision: "refused",
        host: Host.make("example.com"),
        method: "POST",
        operation: "fetch",
        pathPrefix: "/",
        reason: "caller",
        sessionId: "session",
      });

      const metadata = [
        name,
        Host.make("example.com"),
        Placeholder.cases.Secret.make({ name }),
        policy,
        record,
        Caller.make({
          did: "did:test",
          issuer: "test",
          name: "tester",
          sid: "session",
        }),
        Operation.make({
          credential: name,
          host: "example.com",
          method: "POST",
          path: "/",
        }),
        Route.make({ method: "POST", pathPrefix: "/" }),
        Rule.make("caller"),
        Redacted.make(canary),
      ];

      const constructors = [
        Errors.CallerUnauthenticated,
        Errors.CallerNotAllowed,
        Errors.PlacementNotAllowed,
        Errors.CredentialNotFound,
        Errors.CredentialExpired,
        Errors.CredentialRevoked,
        Errors.CredentialNeedsAuth,
        Errors.HostNotAllowed,
        Errors.SchemeNotHttps,
        Errors.PlaceholderOutsideHeader,
        Errors.PlaceholderInAuthority,
        Errors.EncodedPlaceholderRefused,
        Errors.RouteNotAllowed,
        Errors.RefreshFailed,
        Errors.KeyUnavailable,
        Errors.UpstreamFailed,
        Errors.BrokerRefused,
        Errors.GatewayUnavailable,
      ];

      for (const ErrorType of constructors) {
        const error = new ErrorType({ credential: name, rule: "caller" });
        const caught = yield* Effect.fail(error).pipe(Effect.flip);
        expect(caught.message).not.toContain(canary);
        expect(String(caught)).not.toContain(canary);
        expect(JSON.stringify(caught)).not.toContain(canary);
        expect(Object.keys(error).toSorted()).toEqual([
          "_tag",
          "credential",
          "rule",
        ]);
      }

      for (const object of metadata) {
        // oxlint-disable-next-line typescript/no-base-to-string -- The canary deliberately audits default toString on every metadata object.
        expect(String(object)).not.toContain(canary);
        expect(JSON.stringify(object)).not.toContain(canary);
      }

      expect(Object.keys(record)).not.toContain("value");
      const withValue = { ...record, value: canary };
      const encoded = yield* Schema.encodeEffect(UseRecord)(withValue);
      expect(JSON.stringify(encoded)).not.toContain(canary);
    })
);
