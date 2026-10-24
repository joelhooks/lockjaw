import { CredentialName, Host, Policy } from "@lockjaw/domain";
import { Schema } from "effect";

import type { GatewayRequest } from "../src/placement.js";

export const credential = CredentialName.make("test/key");

export const second = CredentialName.make("test/password");

export const policy = Policy.make({
  callers: ["secret-cell/*"],
  hosts: [Host.make("api.example.com")],
  inject: { header: "Authorization", template: "Bearer {value}" },
  placements: ["test-host"],
  routes: [{ method: "POST", pathPrefix: "/allowed/" }],
});

export const policies = new Map([[credential, policy]]);

export const placeholder = `{{secret:${credential}}}`;

export const request: GatewayRequest = {
  body: "public",
  headers: [{ name: "Authorization", value: `Bearer ${placeholder}` }],
  method: "POST",
  url: "https://api.example.com/allowed/path",
};

export const Value = Schema.String.check(
  Schema.isMinLength(8),
  Schema.isMaxLength(48),
  Schema.isPattern(/^[a-zA-Z0-9 !@#$%^&*()_+\-=.:,;/'"\\\u00E9\u4E2D]+$/u)
);

export const GeneratedName = Schema.String.check(
  Schema.isMinLength(1),
  Schema.isMaxLength(32),
  Schema.isPattern(/^[a-zA-Z0-9._/-]+$/u)
);

export const byteChunks = (
  bytes: Uint8Array,
  cuts: readonly number[]
): readonly Uint8Array[] => {
  const sorted = [
    ...new Set(cuts.map((cut) => Math.abs(cut) % (bytes.length + 1))),
  ].toSorted((a, b) => a - b);

  const chunks: Uint8Array[] = [];
  let offset = 0;

  for (const cut of sorted) {
    chunks.push(bytes.slice(offset, cut));
    offset = cut;
  }

  chunks.push(bytes.slice(offset));

  return chunks;
};

export const encodings = (text: string): readonly string[] => [
  text,
  encodeURIComponent(text),
  new URLSearchParams({ v: text }).toString().slice(2),
  JSON.stringify(text).slice(1, -1),
];

const byteText = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => String.fromCodePoint(byte)).join("");

export const assertNoWindows = (
  output: Uint8Array,
  value: string,
  expect: (actual: string) => {
    readonly not: { readonly toContain: (expected: string) => void };
  }
): void => {
  const bytes = new TextEncoder().encode(value);
  const actual = byteText(output);

  for (let index = 0; index + 8 <= bytes.length; index += 1) {
    expect(actual).not.toContain(byteText(bytes.slice(index, index + 8)));
  }
};
