import { expect, it } from "@effect/vitest";
import { Result, Schema } from "effect";

import { Host, Policy, isPublicHost } from "../src/index.js";

const suffixes = [
  "localhost",
  "localdomain",
  "local",
  "internal",
  "lan",
  "home.arpa",
  "intranet",
  "corp",
  "private",
  "test",
  "invalid",
  "example",
  "onion",
  "alt",
  "ts.net",
];

const refused = [
  "127.0.0.1",
  [10, 0, 0, 5].join("."),
  [100, 64, 1, 1].join("."),
  "127.1",
  "0x7f.1",
  "0x7f.0x1",
  "127.0.0.0x1",
  "a.0x",
  "0x7f000001",
  "2130706433",
  "[::1]",
  "::1",
  "api.example.com:443",
  ...suffixes.flatMap((suffix) => [suffix, `example.${suffix}`]),
];

const policyFor = (host: string) => ({
  callers: ["tester"],
  hosts: [host],
  placements: ["test-host"],
});

it("public-host policy table refuses exact, wildcard and uppercase internal hosts", () => {
  for (const host of refused) {
    for (const form of [host, host.toUpperCase(), `*.${host}`]) {
      expect(isPublicHost(form), form).toBe(false);
      const result = Schema.decodeUnknownResult(Policy)(policyFor(form));
      expect(Result.isFailure(result), form).toBe(true);

      if (Result.isFailure(result)) {
        expect(result.failure.message).toContain("host-not-public");
      }
    }
  }
});

it("public-host policy table keeps public exact and wildcard policies decodable", () => {
  for (const host of [
    "api.github.com",
    "*.github.com",
    "example.com",
    "*.example.com",
    "api.example.org",
    "*.foo.co.uk",
    "*.alice.github.io",
    "notinternal.com",
    "example.internal.com",
    "localhost.com",
    "0x7f.example.com",
    "api.0xfoo.dev",
  ]) {
    expect(isPublicHost(host), host).toBe(true);
    expect(Schema.is(Host)(host), host).toBe(true);
    expect(
      Result.isSuccess(Schema.decodeUnknownResult(Policy)(policyFor(host))),
      host
    ).toBe(true);
  }
});

it.prop(
  "contest: every numeric last label is refused at policy decode",
  {
    digits: Schema.Array(
      Schema.Int.check(Schema.isBetween({ maximum: 9, minimum: 0 }))
    ).check(Schema.isMinLength(1), Schema.isMaxLength(63)),
    prefix: Schema.String,
  },
  ({ prefix, digits }) => {
    const label =
      Array.from(prefix, (char) => char.codePointAt(0)?.toString(16) ?? "0")
        .join("")
        .slice(0, 60) || "a";

    for (const host of [
      `${label}.${digits.join("")}`,
      `*.${label}.${digits.join("")}`,
    ]) {
      expect(isPublicHost(host), host).toBe(false);
      expect(
        Result.isFailure(Schema.decodeUnknownResult(Policy)(policyFor(host))),
        host
      ).toBe(true);
    }
  },
  { arbitrary: { runs: 200 } }
);
