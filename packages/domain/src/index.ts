import { Schema } from "effect";

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const CredentialName = Schema.String.check(
  Schema.isPattern(/^[a-zA-Z0-9._/-]{1,128}$(?![\s\S])/u)
).pipe(Schema.brand("CredentialName"));

export type CredentialName = typeof CredentialName.Type;

const publicSuffixes = Object.freeze([
  "com",
  "org",
  "net",
  "edu",
  "gov",
  "io",
  "dev",
  "app",
  "uk",
  "co.uk",
  "org.uk",
  "au",
  "com.au",
  "net.au",
  "nz",
  "co.nz",
  "jp",
  "co.jp",
  "de",
  "fr",
  "github.io",
  "pages.dev",
  "workers.dev",
  "vercel.app",
  "netlify.app",
  "appspot.com",
  "blogspot.com",
  "s3.amazonaws.com",
]);

const specialUseSuffixes = Object.freeze([
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
]);

export const isPublicHost = (host: string): boolean => {
  const normalized = host.toLowerCase().replace(/\.$/u, "");

  return (
    !normalized.includes(":") &&
    !normalized.includes("[") &&
    !/^(?:\d+|0x[0-9a-f]*)$/u.test(normalized.split(".").at(-1) ?? "") &&
    !specialUseSuffixes.some(
      (suffix) => normalized === suffix || normalized.endsWith(`.${suffix}`)
    )
  );
};

export const isExactHost = (host: string): boolean =>
  host.length <= 253 &&
  !/[\r\n]/u.test(host) &&
  host === host.toLowerCase() &&
  host.split(".").length >= 2 &&
  host
    .split(".")
    .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label));

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Host = Schema.String.check(
  Schema.makeFilter(
    (host) => isPublicHost(host) || "host-not-public: use a public DNS hostname"
  ),
  Schema.makeFilter((host) => {
    if (!host.startsWith("*.")) {
      return isExactHost(host);
    }

    const base = host.slice(2);

    const suffix =
      publicSuffixes
        .filter(
          (candidate) => base === candidate || base.endsWith(`.${candidate}`)
        )
        .toSorted((a, b) => b.length - a.length)[0] ??
      base.split(".").at(-1) ??
      "";

    return (
      isExactHost(base) &&
      base.split(".").length === suffix.split(".").length + 1
    );
  })
).pipe(Schema.brand("Host"));

export type Host = typeof Host.Type;

export const HeaderName = Schema.String.check(
  Schema.isPattern(/^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$(?![\s\S])/u)
);

export const Template = Schema.String.check(
  Schema.makeFilter(
    (text) => !/[\r\n\0]/u.test(text) && text.split("{value}").length === 2
  )
);

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Route = Schema.Struct({
  method: Schema.String.check(Schema.isPattern(/^[A-Z]+$(?![\s\S])/u)),
  pathPrefix: Schema.String.check(Schema.isPattern(/^\//u)),
});

export type Route = typeof Route.Type;

export const BasicUser = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9._-]{1,64}$(?![\s\S])/u)
);

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Policy = Schema.Struct({
  callers: Schema.Array(Schema.String),
  hosts: Schema.Array(Host),
  inject: Schema.optionalKey(
    Schema.Struct({
      basicUser: Schema.optionalKey(BasicUser),
      header: HeaderName,
      template: Template,
    })
  ),
  placements: Schema.Array(Schema.String),
  ports: Schema.optionalKey(
    Schema.Array(
      Schema.Int.check(Schema.isBetween({ maximum: 65_535, minimum: 1 }))
    ).check(
      Schema.makeFilter(
        (ports) => new Set(ports).size === ports.length && !ports.includes(443)
      )
    )
  ),
  routes: Schema.optionalKey(Schema.Array(Route)),
});

export type Policy = typeof Policy.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const NamePattern = Schema.String.check(
  Schema.isPattern(/^(?:\*|[a-zA-Z0-9._/-]{1,128}\*?)$(?![\s\S])/u)
).pipe(Schema.brand("NamePattern"));

export type NamePattern = typeof NamePattern.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Op = Schema.Literals([
  "use",
  "describe",
  "set",
  "rotate",
  "revoke",
  "grant",
]);

export type Op = typeof Op.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Instant = Schema.Finite.check(Schema.isGreaterThan(0));

export type Instant = typeof Instant.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Scope = Schema.Struct({
  credentials: Schema.Array(NamePattern).check(Schema.isMinLength(1)),
  exp: Instant,
  grantees: Schema.Array(NamePattern),
  hosts: Schema.Array(Host),
  ops: Schema.Array(Op).check(Schema.isMinLength(1)),
  routes: Schema.optionalKey(Schema.Array(Route)),
});

export type Scope = typeof Scope.Type;

export const RunHandle = Schema.String.check(
  Schema.isPattern(/^[A-Za-z0-9._:-]{1,128}$(?![\s\S])/u)
);

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Grantee = Schema.Struct({
  desk: Schema.NonEmptyString,
  runHandle: Schema.optionalKey(RunHandle),
});

export type Grantee = typeof Grantee.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const GrantId = Schema.String.check(
  Schema.isPattern(/^g_[a-f0-9]{32}$(?![\s\S])/u)
).pipe(Schema.brand("GrantId"));

export type GrantId = typeof GrantId.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Grant = Schema.Struct({
  createdAt: Schema.Finite,
  grantee: Grantee,
  grantor: Schema.String,
  id: GrantId,
  parent: Schema.optionalKey(GrantId),
  scope: Scope,
});

export type Grant = typeof Grant.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const GrantRecord = Schema.Struct({
  grant: Grant,
  revokedAt: Schema.NullOr(Schema.Finite),
});

export type GrantRecord = typeof GrantRecord.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Schema and its inferred type share a public name.
export const GitHubAppMetadata = Schema.Struct({
  appId: Schema.String.check(Schema.isPattern(/^[0-9]+$(?![\s\S])/u)),
  installations: Schema.Record(
    Schema.String.check(Schema.isPattern(/^[A-Za-z0-9._-]{1,64}$(?![\s\S])/u)),
    Schema.Int.check(Schema.isGreaterThan(0))
  ),
});

export type GitHubAppMetadata = typeof GitHubAppMetadata.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Placeholder = Schema.TaggedUnion({
  Basic: { password: CredentialName, username: CredentialName },
  BasicLiteral: { password: CredentialName, user: BasicUser },
  Secret: { name: CredentialName },
});

export type Placeholder = typeof Placeholder.Type;

export const parsePlaceholder = (text: string): Placeholder | undefined => {
  const plain = /^\{\{secret:(?<name>[a-zA-Z0-9._/-]{1,128})\}\}$/u.exec(text);

  if (plain?.[1] !== undefined && plain[0] === text) {
    return Placeholder.cases.Secret.make({
      name: CredentialName.make(plain[1]),
    });
  }

  const literal =
    /^\{\{secret-basic:user=(?<user>[A-Za-z0-9._-]{1,64}),password=(?<password>[a-zA-Z0-9._/-]{1,128})\}\}$/u.exec(
      text
    );

  if (
    literal?.[1] !== undefined &&
    literal[2] !== undefined &&
    literal[0] === text
  ) {
    return Placeholder.cases.BasicLiteral.make({
      password: CredentialName.make(literal[2]),
      user: literal[1],
    });
  }

  const basic =
    /^\{\{secret-basic:username=(?<username>[a-zA-Z0-9._/-]{1,128}),password=(?<password>[a-zA-Z0-9._/-]{1,128})\}\}$/u.exec(
      text
    );

  if (basic?.[1] !== undefined && basic[2] !== undefined && basic[0] === text) {
    return Placeholder.cases.Basic.make({
      password: CredentialName.make(basic[2]),
      username: CredentialName.make(basic[1]),
    });
  }

  return undefined;
};

export const PlaceholderText = Schema.String.check(
  Schema.makeFilter((text) => parsePlaceholder(text) !== undefined)
);

export const placeholdersIn = (
  text: string
): readonly { readonly text: string; readonly placeholder: Placeholder }[] => {
  const found: { text: string; placeholder: Placeholder }[] = [];

  for (const match of text.matchAll(/\{\{secret(?:-basic)?:[^{}]*\}\}/gu)) {
    const placeholder = parsePlaceholder(match[0]);

    if (placeholder) {
      found.push({ placeholder, text: match[0] });
    }
  }

  return found;
};

export const placeholderNames = (
  placeholder: Placeholder
): readonly CredentialName[] =>
  Placeholder.match(placeholder, {
    Basic: ({ username, password }) => [username, password],
    BasicLiteral: ({ password }) => [password],
    Secret: ({ name }) => [name],
  });

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Caller = Schema.Struct({
  did: Schema.String,
  issuer: Schema.String,
  name: Schema.String,
  run: Schema.optionalKey(
    Schema.Struct({
      expiresAt: Schema.Finite,
      handle: Schema.NonEmptyString,
      scope: Schema.Array(Schema.String),
    })
  ),
  sid: Schema.String,
  ticketOnly: Schema.optionalKey(Schema.Literal(true)),
});

export type Caller = typeof Caller.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Operation = Schema.Struct({
  credential: CredentialName,
  host: Schema.String,
  method: Schema.String,
  path: Schema.String,
  subkey: Schema.optionalKey(Schema.String),
});

export type Operation = typeof Operation.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const Rule = Schema.Literals([
  "caller-auth",
  "caller",
  "placement",
  "missing",
  "expired",
  "revoked",
  "needs-auth",
  "host",
  "host-not-public",
  "https",
  "header-only",
  "authority",
  "encoding",
  "route",
  "refresh",
  "key",
  "upstream",
  "broker",
  "gateway",
  "header",
  "request",
  "header-value",
]);

export type Rule = typeof Rule.Type;

// oxlint-disable-next-line eslint/no-redeclare -- Effect schema and its inferred type share one public name.
export const UseRecord = Schema.Struct({
  at: Schema.Finite,
  callerDid: Schema.String,
  callerName: Schema.String,
  credential: CredentialName,
  decision: Schema.Literals(["allowed", "refused"]),
  host: Host,
  method: Schema.String,
  operation: Schema.String,
  pathPrefix: Schema.String,
  reason: Rule,
  sessionId: Schema.String,
});

export type UseRecord = typeof UseRecord.Type;

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const p256Prime =
  0xff_ff_ff_ff_00_00_00_01_00_00_00_00_00_00_00_00_00_00_00_00_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ff_ffn;

const p256B =
  0x5a_c6_35_d8_aa_3a_93_e7_b3_eb_bd_55_76_98_86_bc_65_1d_06_b0_cc_53_b0_f6_3b_ce_3c_3e_27_d2_60_4bn;

export interface P256PublicJwk {
  readonly crv: "P-256";
  readonly kty: "EC";
  readonly x: string;
  readonly y: string;
}

const coordinate = (bytes: Uint8Array): bigint =>
  bytes.reduce((value, byte) => value * 256n + BigInt(byte), 0n);

const toBytes = (value: bigint, length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  let rest = value;

  for (let index = length - 1; index >= 0; index -= 1) {
    bytes[index] = Number(rest % 256n);
    rest /= 256n;
  }

  return bytes;
};

const modPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
  let result = 1n;
  let factor = base % modulus;
  let rest = exponent;

  while (rest > 0n) {
    if (rest % 2n === 1n) {
      result = (result * factor) % modulus;
    }

    factor = (factor * factor) % modulus;
    rest /= 2n;
  }

  return result;
};

const base58Encode = (bytes: Uint8Array): string => {
  let value = coordinate(bytes);
  let text = "";

  while (value > 0n) {
    text = `${alphabet[Number(value % 58n)] ?? ""}${text}`;
    value /= 58n;
  }

  for (const byte of bytes) {
    if (byte !== 0) {
      break;
    }

    text = `1${text}`;
  }

  return text;
};

const base58Decode = (text: string): Uint8Array | undefined => {
  let value = 0n;

  for (const character of text) {
    const digit = alphabet.indexOf(character);

    if (digit === -1) {
      return undefined;
    }

    value = value * 58n + BigInt(digit);
  }

  let zeros = 0;

  while (text[zeros] === "1") {
    zeros += 1;
  }

  let length = 0;

  for (let rest = value; rest > 0n; rest /= 256n) {
    length += 1;
  }

  const body = toBytes(value, length);
  const bytes = new Uint8Array(zeros + body.length);
  bytes.set(body, zeros);

  return bytes;
};

const base64urlEncode = (bytes: Uint8Array): string =>
  btoa(Array.from(bytes, (byte) => String.fromCodePoint(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const base64urlDecode = (text: string): Uint8Array | undefined => {
  if (!/^[A-Za-z0-9_-]*$(?![\s\S])/u.test(text)) {
    return undefined;
  }

  return Uint8Array.from(
    atob(text.replaceAll("-", "+").replaceAll("_", "/")),
    (character) => character.codePointAt(0) ?? 0
  );
};

export const encodeDidKeyP256 = (jwk: P256PublicJwk): string | undefined => {
  const x = base64urlDecode(jwk.x);
  const y = base64urlDecode(jwk.y);

  if (x?.length !== 32 || y?.length !== 32) {
    return undefined;
  }

  const prefixed = new Uint8Array(35);
  prefixed.set([0x80, 0x24, (y.at(-1) ?? 0) % 2 === 0 ? 0x02 : 0x03]);
  prefixed.set(x, 3);

  return `did:key:z${base58Encode(prefixed)}`;
};

export type DidKeyRefusal =
  | "multibase"
  | "multicodec"
  | "length"
  | "prefix"
  | "range"
  | "off-curve";

export type DidKeyDecoded =
  | { readonly ok: true; readonly jwk: P256PublicJwk }
  | { readonly ok: false; readonly reason: DidKeyRefusal };

const refuse = (reason: DidKeyRefusal): DidKeyDecoded => ({
  ok: false,
  reason,
});

export const decodeDidKeyP256 = (did: string): DidKeyDecoded => {
  if (!did.startsWith("did:key:z")) {
    return refuse("multibase");
  }

  const bytes = base58Decode(did.slice("did:key:z".length));

  if (bytes === undefined) {
    return refuse("multibase");
  }

  if (bytes[0] !== 0x80 || bytes[1] !== 0x24) {
    return refuse("multicodec");
  }

  const point = bytes.subarray(2);

  if (point.length !== 33) {
    return refuse("length");
  }

  const [sign] = point;

  if (sign !== 0x02 && sign !== 0x03) {
    return refuse("prefix");
  }

  const xBytes = point.slice(1);
  const x = coordinate(xBytes);

  if (x >= p256Prime) {
    return refuse("range");
  }

  const rhs =
    (((x * x * x - 3n * x + p256B) % p256Prime) + p256Prime) % p256Prime;

  let y = modPow(rhs, (p256Prime + 1n) / 4n, p256Prime);

  if ((y * y) % p256Prime !== rhs) {
    return refuse("off-curve");
  }

  if (Number(y % 2n) !== sign - 2) {
    y = p256Prime - y;
  }

  return {
    jwk: {
      crv: "P-256",
      kty: "EC",
      x: base64urlEncode(xBytes),
      y: base64urlEncode(toBytes(y, 32)),
    },
    ok: true,
  };
};

const refusalWhy = new Map<DidKeyRefusal, string>([
  ["multibase", "The key is not a did:key with z (base58btc) multibase."],
  ["multicodec", "The multicodec prefix is not P-256 public key (0x80 0x24)."],
  ["length", "The key point is not exactly 33 bytes."],
  [
    "prefix",
    "The point is not compressed: its first byte must be 0x02 or 0x03.",
  ],
  ["range", "The x coordinate is not below the P-256 field prime."],
  ["off-curve", "The x coordinate has no point on the P-256 curve."],
]);

export const didKeyRefusal = (reason: DidKeyRefusal) => ({
  next: "Export the public key from a fresh P-256 key pair as a compressed did:key (or a {kty, crv, x, y} JWK), then retry.",
  what: "The worker key is not a valid P-256 did:key",
  why: refusalWhy.get(reason) ?? "The did:key failed validation.",
});
