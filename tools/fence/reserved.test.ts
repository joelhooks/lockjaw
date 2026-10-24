import { Schema } from "effect";
import { expect, it } from "vitest";

import {
  Instance,
  instanceLiterals,
  reservedLiteral,
  violations,
} from "./rules.ts";

it("skips only whole reserved literals, never neighboring real-looking names", () => {
  const reserved = [
    "localhost",
    "127.0.0.1",
    "::1",
    "example.com",
    "example.org",
    "example.net",
    "api.example.com",
    "host.example",
    "host.test",
    "host.invalid",
    "host.localhost",
    "192.0.2.1",
    "198.51.100.20",
    "203.0.113.255",
    "2001:db8::1",
    "2001:0DB8:0:0:0:0:0:1",
  ];

  const neighboring = [
    "localhost-prod",
    "example.com.attacker.dev",
    "notexample.com",
    "test.production.dev",
    "192.0.3.1",
    "198.51.101.20",
    "203.0.114.255",
    "2001:db9::1",
  ];

  for (const value of reserved) {
    expect(reservedLiteral(value)).toBe(true);
  }

  for (const value of neighboring) {
    expect(reservedLiteral(value)).toBe(false);
  }

  const inventory = Schema.decodeUnknownSync(Instance)({
    domains: ["network.production.dev"],
    hosts: [...reserved, ...neighboring],
    ips: ["198.18.0.1"],
    secretNames: ["example_credential"],
    sites: ["site-a"],
  });

  const literals = instanceLiterals(inventory).flatMap(([, values]) => values);

  for (const value of reserved) {
    expect(literals).not.toContain(value);
  }

  for (const value of neighboring) {
    expect(literals).toContain(value);
    expect(violations({ content: value, inventory })).toContain(
      "instance-hosts"
    );
  }
});

it("allows reserved-domain emails and identity prose without weakening credential detection", () => {
  for (const domain of ["example.com", "api.example.net", "host.test"]) {
    expect(
      violations({ content: ["person", domain].join("@"), inventory: null })
    ).toEqual([]);
  }

  for (const domain of [
    "university.edu",
    "example.com.attacker.dev",
    "notexample.com",
  ]) {
    expect(
      violations({ content: ["person", domain].join("@"), inventory: null })
    ).toContain("email");
  }

  expect(
    violations({ content: "agent-secrets identity", inventory: null })
  ).toEqual([]);

  for (const separator of [":", "/"]) {
    expect(
      violations({
        content: ["agent-secrets", "example-credential"].join(separator),
        inventory: null,
      })
    ).toContain("secret-name");
  }

  const inventory = Schema.decodeSync(Instance)({
    domains: ["network.production.dev"],
    hosts: ["node-a"],
    ips: ["198.18.0.1"],
    s3Credentials: {
      accessKey: "example-access",
      secretKey: "example-storage",
    },
    secretNames: ["example-credential"],
    sites: ["site-a"],
  });

  expect(
    violations({ content: inventory.secretNames[0] ?? "", inventory })
  ).toContain("instance-secretNames");
  expect(
    violations({ content: inventory.s3Credentials?.accessKey ?? "", inventory })
  ).toContain("instance-credentialNames");
});
