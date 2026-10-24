import { Placeholder, placeholderNames } from "@lockjaw/domain";
import type { CredentialName } from "@lockjaw/domain";
import { KeyUnavailable, PlacementNotAllowed } from "@lockjaw/domain/errors";
import type { GatewayError } from "@lockjaw/domain/errors";
import { Context, Effect, Layer, Redacted } from "effect";

import type { GatewayRequest, HeaderFill } from "./placement.js";

export interface RedactionPlan {
  readonly longest: number;
  readonly matchAt: (bytes: Uint8Array, offset: number) => number;
}

export interface FilledRequest {
  readonly request: GatewayRequest;
  readonly values: ReadonlySet<Redacted.Redacted>;
  readonly redaction: RedactionPlan;
}

export type Resolve = (
  name: CredentialName
) => Effect.Effect<Redacted.Redacted, GatewayError>;

export const base64 = (value: string): string =>
  btoa(
    Array.from(new TextEncoder().encode(value), (byte) =>
      String.fromCodePoint(byte)
    ).join("")
  );

const forms = (value: string): readonly string[] => [
  value,
  encodeURIComponent(value),
  new URLSearchParams({ v: value }).toString().slice(2),
  JSON.stringify(value).slice(1, -1),
];

const compilePlan = (texts: ReadonlySet<string>): RedactionPlan => {
  const patterns: Uint8Array[] = [];

  for (const text of texts) {
    if (!text) {
      continue;
    }

    const bytes = new TextEncoder().encode(text);
    patterns.push(bytes);

    for (let index = 0; index + 8 <= bytes.length; index += 1) {
      patterns.push(bytes.slice(index, index + 8));
    }
  }

  patterns.sort((a, b) => b.length - a.length);

  return Object.freeze({
    longest: patterns[0]?.length ?? 1,
    matchAt: (bytes: Uint8Array, offset: number) => {
      for (const pattern of patterns) {
        if (
          offset + pattern.length <= bytes.length &&
          pattern.every((byte, index) => bytes[offset + index] === byte)
        ) {
          return pattern.length;
        }
      }

      return 0;
    },
  });
};

export const apply = Effect.fn("Fill.apply")(function* operation(
  request: GatewayRequest,
  fills: readonly HeaderFill[],
  resolve: Resolve
) {
  const resolved = new Map<CredentialName, Redacted.Redacted>();
  const texts = new Set<string>();
  const substituted = new Set<Redacted.Redacted>();
  const headers = request.headers.map((header) => ({ ...header }));

  for (const fill of fills) {
    const values = new Map<CredentialName, string>();

    for (const name of placeholderNames(fill.placeholder)) {
      let wrapped = resolved.get(name);

      if (!wrapped) {
        wrapped = yield* resolve(name);
        resolved.set(name, wrapped);
      }

      const value = yield* Effect.try({
        catch: () => new KeyUnavailable({ credential: name, rule: "key" }),
        try: () => Redacted.value(wrapped),
      });

      substituted.add(wrapped);

      if (
        !value ||
        /[\r\n\0]/u.test(value) ||
        new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
          new TextEncoder().encode(value)
        ) !== value
      ) {
        return yield* new PlacementNotAllowed({
          credential: name,
          rule: "header-value",
        });
      }

      values.set(name, value);

      for (const form of forms(value)) {
        texts.add(form);
      }
    }

    const value = Placeholder.match(fill.placeholder, {
      Basic: ({ username, password }) =>
        base64(`${values.get(username) ?? ""}:${values.get(password) ?? ""}`),
      BasicLiteral: ({ user, password }) =>
        base64(`${user}:${values.get(password) ?? ""}`),
      Secret: ({ name }) => values.get(name) ?? "",
    });

    if (
      Placeholder.guards.Basic(fill.placeholder) ||
      Placeholder.guards.BasicLiteral(fill.placeholder)
    ) {
      substituted.add(Redacted.make(value));
      texts.add(value);
      texts.add(`Basic ${value}`);
    }

    const target = headers.find(
      (header) => header.name.toLowerCase() === fill.header.toLowerCase()
    );

    if (!target) {
      return yield* new PlacementNotAllowed({
        credential: fill.credential,
        rule: "header",
      });
    }

    target.value = fill.template.replace("{value}", () => value);

    for (const form of forms(target.value)) {
      texts.add(form);
    }
  }

  const output: FilledRequest = {
    redaction: compilePlan(texts),
    request:
      fills.length === 0
        ? request
        : { ...request, headers, redirect: "manual" },
    values: substituted,
  };

  return output;
});

export class Fill extends Context.Service<
  Fill,
  { readonly apply: typeof apply }
>()("secret-cell/Fill") {
  static readonly layer = Layer.succeed(Fill, Fill.of({ apply }));
  static readonly testLayer = Layer.succeed(Fill, Fill.of({ apply }));
}
