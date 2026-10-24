import {
  CredentialName,
  Placeholder,
  HeaderName,
  Template,
  placeholderNames,
  placeholdersIn,
} from "@lockjaw/domain";
import type { Policy } from "@lockjaw/domain";
import {
  BrokerRefused,
  CredentialNotFound,
  EncodedPlaceholderRefused,
  PlacementNotAllowed,
  PlaceholderOutsideHeader,
  RouteNotAllowed,
  SchemeNotHttps,
} from "@lockjaw/domain/errors";
import { Context, Effect, Layer, Schema } from "effect";

import { nothingToFill } from "./nothing-to-fill.js";
import { checkPublicTarget, checkTarget } from "./policy.js";

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const GatewayRequest = Schema.Struct({
  body: Schema.optionalKey(Schema.String),
  headers: Schema.Array(
    Schema.Struct({ name: HeaderName, value: Schema.String })
  ),
  method: Schema.String,
  redirect: Schema.optionalKey(Schema.Literals(["manual", "error", "follow"])),
  url: Schema.String,
});

export type GatewayRequest = typeof GatewayRequest.Type;

export interface HeaderFill {
  readonly header: string;
  readonly credential: CredentialName;
  readonly placeholder: Placeholder;
  readonly template: string;
}

const unidentified = CredentialName.make("request");

const firstName = (placeholder: Placeholder): CredentialName =>
  placeholderNames(placeholder)[0] ?? unidentified;

const decodePercent = (text: string): string => {
  try {
    return decodeURIComponent(text.replaceAll("+", " "));
  } catch {
    return text.replaceAll(/%(?<byte>[a-fA-F0-9]{2})/gu, (_, hex: string) =>
      String.fromCodePoint(Number.parseInt(hex, 16))
    );
  }
};

const decodeBase64 = (text: string): string => {
  try {
    return atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  } catch {
    return text;
  }
};

export const encodedPlaceholder = (text: string): Placeholder | undefined => {
  const seen = new Set<string>([text]);
  const queue = [text];

  for (const current of queue) {
    const candidates = [decodePercent(current)];

    for (const token of current.matchAll(/[A-Za-z0-9+/_-]{8,}={0,2}/gu)) {
      for (let offset = 0; offset < 4; offset += 1) {
        const suffix = token[0].slice(offset);
        candidates.push(
          decodeBase64(suffix.length % 4 === 1 ? suffix.slice(0, -1) : suffix)
        );
      }
    }

    for (const decoded of candidates) {
      if (decoded === current || seen.has(decoded)) {
        continue;
      }

      const [found] = placeholdersIn(decoded);

      if (found) {
        return found.placeholder;
      }

      seen.add(decoded);
      queue.push(decoded);
    }
  }

  return undefined;
};

const refuseOutside = Effect.fn("Placement.refuseOutside")(
  function* refuseOutside(text: string) {
    const [raw] = placeholdersIn(text);

    if (raw) {
      return yield* new PlaceholderOutsideHeader({
        credential: firstName(raw.placeholder),
        rule: "header-only",
      });
    }

    const encoded = encodedPlaceholder(text);

    if (encoded) {
      return yield* new EncodedPlaceholderRefused({
        credential: firstName(encoded),
        rule: "encoding",
      });
    }

    return yield* Effect.void;
  }
);

const parseUrl = Effect.fn("Placement.parseUrl")((text: string) =>
  Effect.try({
    catch: () =>
      new BrokerRefused({ credential: unidentified, rule: "request" }),
    try: () => new URL(text),
  })
);

const checkCredential = Effect.fn("Placement.checkCredential")(
  function* checkCredential(
    policies: ReadonlyMap<CredentialName, Policy>,
    name: CredentialName,
    url: URL,
    request: GatewayRequest,
    header: string,
    template: string,
    basicUser?: string
  ) {
    const policy = policies.get(name);

    if (!policy) {
      return yield* new CredentialNotFound({
        credential: name,
        rule: "missing",
      });
    }

    if (basicUser !== undefined && policy.inject?.basicUser !== basicUser) {
      return yield* new PlacementNotAllowed({
        credential: name,
        rule: "header",
      });
    }

    const host = url.hostname.toLowerCase().replace(/\.$/u, "");

    const op = {
      credential: name,
      host,
      method: request.method.toUpperCase(),
      path: url.pathname,
    };

    yield* checkPublicTarget(op);

    if (url.port && policy.ports?.includes(Number(url.port)) !== true) {
      return yield* new PlacementNotAllowed({
        credential: name,
        rule: "authority",
      });
    }

    yield* checkTarget(policy, op);

    if (policy.routes) {
      if (/%(?:2f|5c|25)/iu.test(url.pathname)) {
        return yield* new RouteNotAllowed({ credential: name, rule: "route" });
      }

      const canonical = yield* parseUrl(
        `${url.origin}${decodePercent(url.pathname)}`
      );

      yield* checkTarget(policy, { ...op, path: canonical.pathname });
    }

    if (
      policy.inject &&
      (header.toLowerCase() !== policy.inject.header.toLowerCase() ||
        (basicUser === undefined
          ? template !== policy.inject.template
          : policy.inject.basicUser !== basicUser ||
            template !== "Basic {value}"))
    ) {
      return yield* new PlacementNotAllowed({
        credential: name,
        rule: "header",
      });
    }

    return yield* Effect.void;
  }
);

const checkHeader = Effect.fn("Placement.checkHeader")(function* checkHeader(
  policies: ReadonlyMap<CredentialName, Policy>,
  url: URL,
  request: GatewayRequest,
  header: GatewayRequest["headers"][number]
) {
  const found = placeholdersIn(header.value);
  const [first] = found;
  const encoded = encodedPlaceholder(header.value);

  if (encoded) {
    return yield* new EncodedPlaceholderRefused({
      credential: firstName(encoded),
      rule: "encoding",
    });
  }

  if (!first) {
    return [];
  }

  const credential = firstName(first.placeholder);

  if (url.protocol !== "https:") {
    return yield* new SchemeNotHttps({ credential, rule: "https" });
  }

  if (url.username || url.password) {
    return yield* new PlacementNotAllowed({ credential, rule: "authority" });
  }

  if (
    found.length !== 1 ||
    !Schema.is(HeaderName)(header.name) ||
    /^(?:host|content-length|connection|transfer-encoding|upgrade|x-sc-.*)$/iu.test(
      header.name
    ) ||
    /[\r\n\0]/u.test(header.value)
  ) {
    return yield* new PlacementNotAllowed({ credential, rule: "header" });
  }

  const literalBasic = Placeholder.guards.BasicLiteral(first.placeholder);

  if (
    literalBasic &&
    (header.value !== first.text ||
      header.name.toLowerCase() !== "authorization")
  ) {
    return yield* new PlacementNotAllowed({ credential, rule: "header" });
  }

  const template = literalBasic
    ? "Basic {value}"
    : header.value.replace(first.text, "{value}");

  if (!Schema.is(Template)(template)) {
    return yield* new PlacementNotAllowed({ credential, rule: "header" });
  }

  for (const name of placeholderNames(first.placeholder)) {
    yield* checkCredential(
      policies,
      name,
      url,
      request,
      header.name,
      template,
      Placeholder.guards.BasicLiteral(first.placeholder)
        ? first.placeholder.user
        : undefined
    );
  }

  const fills: HeaderFill[] = [
    {
      credential,
      header: header.name,
      placeholder: first.placeholder,
      template,
    },
  ];

  return fills;
});

export const makeCheck = (policies: ReadonlyMap<CredentialName, Policy>) =>
  Effect.fn("Placement.check")(function* check(request: GatewayRequest) {
    yield* refuseOutside(request.url);
    const url = yield* parseUrl(request.url);
    const names = request.headers.map((header) => header.name.toLowerCase());

    if (new Set(names).size !== names.length) {
      return yield* new PlacementNotAllowed({
        credential: unidentified,
        rule: "header",
      });
    }

    const off = request.headers.some(
      (header) =>
        header.name.toLowerCase() === "x-sc-resolution" &&
        header.value === "off"
    );

    if (off) {
      return yield* nothingToFill(true);
    }

    yield* refuseOutside(request.body ?? "");
    const fills: HeaderFill[] = [];

    for (const header of request.headers) {
      fills.push(...(yield* checkHeader(policies, url, request, header)));
    }

    if (fills.length === 0) {
      return yield* nothingToFill(false);
    }

    if (
      request.headers.some(
        (header) =>
          header.name.toLowerCase() === "upgrade" ||
          (header.name.toLowerCase() === "connection" &&
            /(?:^|,)\s*upgrade\s*(?:,|$)/iu.test(header.value))
      )
    ) {
      return yield* new BrokerRefused({
        credential: fills[0]?.credential ?? unidentified,
        rule: "broker",
      });
    }

    return fills;
  });

export class Placement extends Context.Service<
  Placement,
  { readonly check: ReturnType<typeof makeCheck> }
>()("secret-cell/Placement") {
  static layer(policies: ReadonlyMap<CredentialName, Policy>) {
    return Layer.succeed(
      Placement,
      Placement.of({ check: makeCheck(policies) })
    );
  }
  static testLayer(policies: ReadonlyMap<CredentialName, Policy>) {
    return Placement.layer(policies);
  }
}
