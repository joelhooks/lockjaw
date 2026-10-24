// oxlint-disable typescript/promise-function-async -- Web Crypto promise callbacks are adapter boundaries; Effect owns async composition.
import { CredentialName } from "@lockjaw/domain";
import { KeyUnavailable, ValueNotWellFormed } from "@lockjaw/domain/errors";
import { Context, Effect, Layer, Redacted } from "effect";

import { signingKeyInvalid } from "./github-app.js";
import type { SigningAlgorithm } from "./github-app.js";
import { KekUnavailable } from "./kek-unavailable.js";

export interface Sealed {
  readonly ciphertext: readonly number[];
  readonly iv: readonly number[];
}

export interface Wrapped extends Sealed {
  readonly kekId: string;
}

export interface KekBinding {
  readonly kekId: string;
  readonly key: Redacted.Redacted<Uint8Array>;
}

export interface KeySet {
  readonly current: CryptoKey;
  readonly currentId: string;
  readonly keys: ReadonlyMap<string, CryptoKey>;
  readonly missing: (
    stored: string,
    credential: CredentialName
  ) => KeyUnavailable | KekUnavailable;
}

export interface KekBindings {
  readonly LOCKJAW_KEK?: string | undefined;
  readonly LOCKJAW_KEK_NEXT?: string | undefined;
  readonly KEK_URL?: string | undefined;
  readonly KEK_ACCESS?: string | undefined;
}

export interface KekUrlConfig {
  readonly access: Redacted.Redacted;
  readonly url: string;
}

export type KekSelection =
  | {
      readonly mode: "binding";
      readonly current: string;
      readonly next: string | undefined;
    }
  | { readonly mode: "url"; readonly config: KekUrlConfig }
  | { readonly mode: "refused"; readonly error: KekUnavailable };

export type KekFetch = (
  url: string,
  init: {
    readonly headers: { readonly authorization: string };
    readonly method: "GET";
    readonly redirect: "error";
  }
) => Promise<Response>;

export interface KekLoader {
  readonly load: (
    config: KekUrlConfig
  ) => Effect.Effect<KeySet, KekUnavailable>;
}

const importSigningBytes = (
  bytes: Uint8Array,
  credential: CredentialName,
  algorithm: SigningAlgorithm
) =>
  Effect.tryPromise({
    catch: () => signingKeyInvalid(credential),
    try: () => {
      if (algorithm !== "RSASSA-PKCS1-v1_5/SHA-256") {
        throw new Error("Unsupported signing algorithm");
      }

      const pem = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: true,
      }).decode(bytes);

      const match =
        /^-----BEGIN PRIVATE KEY-----\s+(?<body>[A-Za-z0-9+/=\s]+)\s+-----END PRIVATE KEY-----\s*$/u.exec(
          pem
        );

      if (match?.[1] === undefined || match[1].length === 0) {
        throw new Error("Invalid signing key");
      }

      const der = Uint8Array.from(
        atob(match[1].replaceAll(/\s/gu, "")),
        (byte) => byte.codePointAt(0) ?? 0
      );

      return crypto.subtle
        .importKey(
          "pkcs8",
          der,
          { hash: "SHA-256", name: "RSASSA-PKCS1-v1_5" },
          false,
          ["sign"]
        )
        .finally(() => {
          der.fill(0);
        });
    },
  });

const unavailable = (credential: CredentialName) =>
  new KeyUnavailable({ credential, rule: "key" });

const keyCredential = CredentialName.make("keyring");

const aad = (value: string) => new TextEncoder().encode(value);

const algorithm = (
  iv: Uint8Array<ArrayBuffer>,
  additionalData: Uint8Array<ArrayBuffer>
) => ({ additionalData, iv, name: "AES-GCM", tagLength: 128 });

const envelopeAad = (credential: CredentialName, id: string) =>
  `secret-cell.v1|dek|${credential}|${id}`;

const valueAad = (credential: CredentialName, version: number) =>
  `secret-cell.v1|${credential}|${version}`;

const seal = (
  key: CryptoKey,
  bytes: Uint8Array<ArrayBuffer>,
  context: string,
  credential: CredentialName
) =>
  Effect.tryPromise({
    catch: () => unavailable(credential),
    try: () => {
      const iv = crypto.getRandomValues(new Uint8Array(12));

      return crypto.subtle
        .encrypt(algorithm(iv, aad(context)), key, bytes)
        .then((ciphertext): Sealed => ({
          ciphertext: [...new Uint8Array(ciphertext)],
          iv: [...iv],
        }));
    },
  });

const open = (
  key: CryptoKey,
  value: Sealed,
  context: string,
  credential: CredentialName
) =>
  Effect.tryPromise({
    catch: () => unavailable(credential),
    try: () =>
      crypto.subtle.decrypt(
        algorithm(new Uint8Array(value.iv), aad(context)),
        key,
        new Uint8Array(value.ciphertext)
      ),
  });

const importDek = (
  bytes: Uint8Array<ArrayBuffer>,
  credential: CredentialName
) =>
  Effect.tryPromise({
    catch: () => unavailable(credential),
    try: () =>
      crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ]),
  });

const importKek = Effect.fn("Keyring.importKek")(function* importKekOperation(
  binding: KekBinding
) {
  const bytes = yield* Effect.try({
    catch: () => unavailable(keyCredential),
    try: () => Redacted.value(binding.key),
  });

  const material = new Uint8Array(bytes);

  return yield* Effect.tryPromise({
    catch: () => unavailable(keyCredential),
    try: () => {
      if (bytes.length !== 32) {
        throw new Error("Invalid KEK length");
      }

      return crypto.subtle.importKey("raw", material, "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ]);
    },
  }).pipe(
    Effect.ensuring(
      Effect.sync(() => {
        bytes.fill(0);
        material.fill(0);
        Redacted.wipeUnsafe(binding.key);
      })
    )
  );
});

const fromBinding = Effect.fn("Keyring.fromBinding")(
  function* fromBindingOperation(binding: KekBinding, next?: KekBinding) {
    if (next?.kekId === binding.kekId) {
      return yield* unavailable(keyCredential);
    }

    const current = yield* importKek(binding);
    const keys = new Map([[binding.kekId, current]]);

    if (next) {
      keys.set(next.kekId, yield* importKek(next));
    }

    const set: KeySet = {
      current,
      currentId: binding.kekId,
      keys,
      missing: (_stored, credential) => unavailable(credential),
    };

    return set;
  }
);

const kekRefused = (
  what: string,
  why: string,
  next: string,
  credential = "keyring"
) => new KekUnavailable({ credential, next, rule: "kek", what, why });

const configRefused = (why: string) =>
  kekRefused(
    "Lockjaw has no usable KEK configuration",
    why,
    "The cell operator must configure exactly one KEK mode, either LOCKJAW_KEK or KEK_URL with KEK_ACCESS, and redeploy. Credentials stay sealed until then."
  );

const loadRefused = (why: string) =>
  kekRefused(
    "Lockjaw could not load its KEK from the key service",
    why,
    "The cell operator must check the guest key service at KEK_URL and the KEK_ACCESS token. Then retry; the cell fetches the KEK again on the next request."
  );

const kekMismatch = (
  stored: string,
  current: string,
  credential: CredentialName
) =>
  kekRefused(
    "The credential is sealed under a different KEK",
    `Its stored kekId ${stored} does not match ${current}, the id of the KEK the key service returned.`,
    "The cell operator must restore the key service's original KEK for this cell. The stored value cannot be opened with the current one.",
    credential
  );

const kekUrl = /^http:\/\/127\.0\.0\.1:(?<port>[1-9][0-9]{0,4})\/kek$/u;

export const selectKek = (bindings: KekBindings): KekSelection => {
  const url = bindings.KEK_URL;
  const access = bindings.KEK_ACCESS;
  const urlMode = url !== undefined || access !== undefined;

  if (bindings.LOCKJAW_KEK !== undefined && urlMode) {
    return {
      error: configRefused(
        "LOCKJAW_KEK and KEK_URL or KEK_ACCESS are both set, but exactly one KEK mode may be configured."
      ),
      mode: "refused",
    };
  }

  if (bindings.LOCKJAW_KEK !== undefined) {
    return {
      current: bindings.LOCKJAW_KEK,
      mode: "binding",
      next: bindings.LOCKJAW_KEK_NEXT,
    };
  }

  if (!urlMode) {
    return {
      error: configRefused(
        "Neither LOCKJAW_KEK nor KEK_URL with KEK_ACCESS is set."
      ),
      mode: "refused",
    };
  }

  if (bindings.LOCKJAW_KEK_NEXT !== undefined) {
    return {
      error: configRefused(
        "LOCKJAW_KEK_NEXT is a binding-mode rotation input, and URL mode does not rotate."
      ),
      mode: "refused",
    };
  }

  if (url === undefined || access === undefined) {
    return {
      error: configRefused("URL mode needs both KEK_URL and KEK_ACCESS."),
      mode: "refused",
    };
  }

  const port = kekUrl.exec(url)?.groups?.port;

  if (port === undefined || Number(port) > 65_535) {
    return {
      error: configRefused(
        "KEK_URL must be exactly http://127.0.0.1:<port>/kek, with no other host, path, query, fragment or user information."
      ),
      mode: "refused",
    };
  }

  if (access.length === 0) {
    return {
      error: configRefused("KEK_ACCESS is empty."),
      mode: "refused",
    };
  }

  return { config: { access: Redacted.make(access), url }, mode: "url" };
};

const kekLength = 32;

const kekIdContext = new TextEncoder().encode("secret-cell.v1|kek-id|");

export const deriveKekId = Effect.fn("Keyring.deriveKekId")(
  function* deriveKekIdOperation(bytes: Uint8Array) {
    const input = new Uint8Array(kekIdContext.length + bytes.length);
    input.set(kekIdContext);
    input.set(bytes, kekIdContext.length);

    const digest = yield* Effect.tryPromise({
      catch: () => loadRefused("The KEK id could not be derived."),
      try: () => crypto.subtle.digest("SHA-256", input),
    }).pipe(Effect.ensuring(Effect.sync(() => input.fill(0))));

    const hex = Array.from(new Uint8Array(digest).slice(0, 8), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");

    return `kek-${hex}`;
  }
);

const fetchKek = Effect.fn("Keyring.fetchKek")(function* fetchKekOperation(
  fetcher: KekFetch,
  config: KekUrlConfig
) {
  return yield* Effect.tryPromise({
    catch: () =>
      loadRefused("The request to the key service failed or was redirected."),
    try: () =>
      fetcher(config.url, {
        headers: { authorization: `Bearer ${Redacted.value(config.access)}` },
        method: "GET",
        redirect: "error",
      }),
  });
});

const wrongBody = () =>
  loadRefused(
    "The key service did not return exactly 32 bytes of application/octet-stream."
  );

const readKek = Effect.fn("Keyring.readKek")(function* readKekOperation(
  response: Response
) {
  const reader = response.body?.getReader();

  const cancel = Effect.tryPromise(
    () => reader?.cancel() ?? Promise.resolve()
  ).pipe(Effect.ignore);

  if (response.status !== 200) {
    yield* cancel;

    return yield* loadRefused(
      `The key service answered with status ${response.status}, not 200.`
    );
  }

  const type = response.headers
    .get("content-type")
    ?.split(";")[0]
    ?.trim()
    .toLowerCase();

  if (reader === undefined || type !== "application/octet-stream") {
    yield* cancel;

    return yield* wrongBody();
  }

  const bytes = new Uint8Array(kekLength);
  let length = 0;

  const read = Effect.tryPromise({
    catch: wrongBody,
    try: () => reader.read(),
  });

  for (
    let chunk = yield* read;
    !chunk.done && length <= kekLength;
    chunk = yield* read
  ) {
    if (length + chunk.value.length <= kekLength) {
      bytes.set(chunk.value, length);
    }

    length += chunk.value.length;
    chunk.value.fill(0);
  }

  yield* cancel;

  if (length !== kekLength) {
    bytes.fill(0);

    return yield* wrongBody();
  }

  return bytes;
});

const importLoaded = (bytes: Uint8Array<ArrayBuffer>) =>
  Effect.tryPromise({
    catch: () =>
      loadRefused(
        "The key service bytes could not be imported as an AES-GCM key."
      ),
    try: () =>
      crypto.subtle.importKey("raw", bytes, "AES-GCM", false, [
        "encrypt",
        "decrypt",
      ]),
  });

export const makeKekLoader = (fetcher: KekFetch): KekLoader => {
  let cached: { readonly url: string; readonly set: KeySet } | undefined;

  const load = Effect.fn("Keyring.loadKek")(function* loadKekOperation(
    config: KekUrlConfig
  ) {
    if (cached?.url === config.url) {
      return cached.set;
    }

    const bytes = yield* readKek(yield* fetchKek(fetcher, config));

    const [currentId, current] = yield* Effect.all([
      deriveKekId(bytes),
      importLoaded(bytes),
    ]).pipe(Effect.ensuring(Effect.sync(() => bytes.fill(0))));

    const set: KeySet = {
      current,
      currentId,
      keys: new Map([[currentId, current]]),
      missing: (stored, credential) =>
        kekMismatch(stored, currentId, credential),
    };

    cached = { set, url: config.url };

    return set;
  });

  return { load };
};

const keyFor = (set: KeySet, id: string, credential: CredentialName) => {
  const key = set.keys.get(id);

  return key ? Effect.succeed(key) : Effect.fail(set.missing(id, credential));
};

const make = Effect.fn("Keyring.make")(function* makeOperation(
  keySet: Effect.Effect<KeySet, KeyUnavailable | KekUnavailable>
) {
  const pending = new WeakMap<CryptoKey, Uint8Array<ArrayBuffer>>();
  const buffers = new Set<Uint8Array<ArrayBuffer>>();
  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      for (const buffer of buffers) {
        buffer.fill(0);
      }

      buffers.clear();
    })
  );

  const newDek = Effect.fn("Keyring.newDek")(function* newDekOperation() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));

    const dek = yield* importDek(bytes, keyCredential).pipe(
      Effect.onError(() => Effect.sync(() => bytes.fill(0)))
    );

    pending.set(dek, bytes);
    buffers.add(bytes);

    return dek;
  });

  const wrap = Effect.fn("Keyring.wrap")(function* wrapOperation(
    dek: CryptoKey,
    credential: CredentialName
  ) {
    const bytes = pending.get(dek);

    if (!bytes) {
      return yield* unavailable(credential);
    }

    return yield* keySet.pipe(
      Effect.flatMap((set) =>
        seal(
          set.current,
          bytes,
          envelopeAad(credential, set.currentId),
          credential
        ).pipe(Effect.map((sealed) => ({ ...sealed, kekId: set.currentId })))
      ),
      Effect.ensuring(
        Effect.sync(() => {
          bytes.fill(0);
          pending.delete(dek);
          buffers.delete(bytes);
        })
      )
    );
  });

  const unwrap = Effect.fn("Keyring.unwrap")(function* unwrapOperation(
    wrapped: Wrapped,
    credential: CredentialName,
    kekId: string
  ) {
    if (wrapped.kekId !== kekId) {
      return yield* unavailable(credential);
    }

    const key = yield* keyFor(yield* keySet, kekId, credential);

    return yield* open(
      key,
      wrapped,
      envelopeAad(credential, kekId),
      credential
    ).pipe(
      Effect.flatMap((raw) => {
        const bytes = new Uint8Array(raw);

        return importDek(bytes, credential).pipe(
          Effect.ensuring(Effect.sync(() => bytes.fill(0)))
        );
      })
    );
  });

  const encrypt = Effect.fn("Keyring.encrypt")(function* encryptOperation(
    value: Redacted.Redacted,
    dek: CryptoKey,
    credential: CredentialName,
    version: number,
    signingAlgorithm?: SigningAlgorithm
  ) {
    const text = Redacted.value(value);

    if (!text.isWellFormed()) {
      return yield* ValueNotWellFormed.refusal(credential);
    }

    const bytes = new TextEncoder().encode(text);

    const validate =
      signingAlgorithm === undefined
        ? Effect.void
        : Effect.gen(function* validateSigningValue() {
            if (
              new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })
                .decode(bytes)
                .startsWith("-----BEGIN RSA PRIVATE KEY-----")
            ) {
              return yield* signingKeyInvalid(credential, true);
            }

            yield* importSigningBytes(bytes, credential, signingAlgorithm);

            return yield* Effect.void;
          });

    return yield* validate.pipe(
      Effect.andThen(
        seal(dek, bytes, valueAad(credential, version), credential)
      ),
      Effect.ensuring(Effect.sync(() => bytes.fill(0)))
    );
  });

  const importSigningKey = Effect.fn("Keyring.importSigningKey")(
    function* importSigningKeyOperation(
      value: Sealed,
      dek: CryptoKey,
      credential: CredentialName,
      version: number,
      signingAlgorithm: SigningAlgorithm
    ) {
      const raw = yield* open(
        dek,
        value,
        valueAad(credential, version),
        credential
      );

      const bytes = new Uint8Array(raw);

      return yield* importSigningBytes(
        bytes,
        credential,
        signingAlgorithm
      ).pipe(Effect.ensuring(Effect.sync(() => bytes.fill(0))));
    }
  );

  const decrypt = Effect.fn("Keyring.decrypt")(function* decryptOperation(
    value: Sealed,
    dek: CryptoKey,
    credential: CredentialName,
    version: number
  ) {
    return yield* open(
      dek,
      value,
      valueAad(credential, version),
      credential
    ).pipe(
      Effect.flatMap((raw) => {
        const bytes = new Uint8Array(raw);

        return Effect.try({
          catch: () => unavailable(credential),
          try: () =>
            Redacted.make(
              new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
                bytes
              )
            ),
        }).pipe(Effect.ensuring(Effect.sync(() => bytes.fill(0))));
      })
    );
  });

  const rewrap = Effect.fn("Keyring.rewrap")(function* rewrapOperation(
    wrapped: Wrapped,
    credential: CredentialName,
    nextId: string
  ) {
    const set = yield* keySet;
    const old = yield* keyFor(set, wrapped.kekId, credential);
    const target = yield* keyFor(set, nextId, credential);

    return yield* open(
      old,
      wrapped,
      envelopeAad(credential, wrapped.kekId),
      credential
    ).pipe(
      Effect.flatMap((raw) => {
        const bytes = new Uint8Array(raw);

        return seal(
          target,
          bytes,
          envelopeAad(credential, nextId),
          credential
        ).pipe(
          Effect.map((sealed) => ({ ...sealed, kekId: nextId })),
          Effect.ensuring(Effect.sync(() => bytes.fill(0)))
        );
      })
    );
  });

  return { decrypt, encrypt, importSigningKey, newDek, rewrap, unwrap, wrap };
});

export class Keyring extends Context.Service<
  Keyring,
  Effect.Success<ReturnType<typeof make>>
>()("secret-cell/Keyring") {
  static readonly layer = (binding: KekBinding, next?: KekBinding) =>
    Layer.effect(
      Keyring,
      fromBinding(binding, next).pipe(
        Effect.flatMap((set) => make(Effect.succeed(set)))
      )
    );
  static readonly urlLayer = (config: KekUrlConfig, loader: KekLoader) =>
    Layer.effect(Keyring, make(Effect.suspend(() => loader.load(config))));
  static readonly refusedLayer = (error: KekUnavailable) =>
    Layer.effect(Keyring, make(Effect.fail(error)));
  static readonly testLayer = () =>
    Keyring.layer({
      kekId: "test-v1",
      key: Redacted.make(new Uint8Array(32).fill(7)),
    });
}
