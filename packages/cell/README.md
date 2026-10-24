# Credential core

Phase 1b provides per-credential Effect services. It has no Worker entry, DO class, celld dependency, transport, or real credentials.

## Services and layers

- `Keyring.layer(binding, next?)` consumes a 32-byte `Redacted<Uint8Array>` KEK and its id. `testLayer()` supplies a fixed synthetic KEK. A binding is single-use: construct a fresh Redacted buffer for each layer acquisition.
- `selectKek(bindings)` chooses binding mode (`LOCKJAW_KEK`) or URL mode (`KEK_URL` with `KEK_ACCESS`) and refuses both, neither, a partial URL mode, `LOCKJAW_KEK_NEXT` with URL mode, an empty access token, or any `KEK_URL` other than `http://127.0.0.1:<port>/kek`. Refusals are three-part `KekUnavailable` errors with `rule: kek`.
- `Keyring.urlLayer(config, loader)` builds without network access and loads the KEK on first use. `makeKekLoader(fetch)` caches one imported key per loader; the Worker holds one loader per isolate. Failures are not cached. URL mode derives its `kekId` with `deriveKekId`, so a wrong key surfaces as a three-part kekId mismatch. `Keyring.refusedLayer(error)` fails every key operation with a configuration refusal.
- `CredentialStore.layer(sql)` accepts synchronous `exec(query, ...bindings)` and `transactionSync(fn)` ports. `durableSqlPort(ctx.storage)` delegates both calls to the live storage owner. `NodeSqlite.layer` and `nodeStoreLayer` provide the same adapter against a temporary Node 24 SQLite file. Import the Node adapter through `@lockjaw/cell/node-sqlite`, not the Worker-facing barrel.
- `Refresher.layer(implementation)` supplies the provider port. Its test layer returns a typed retryable failure. Successful results contain Redacted access and optional rotated refresh tokens, plus the replacement `expiresAt` (a timestamp or null). These commit together. Failures contain only `invalid_grant` or `retryable`, never provider bodies.
- `Credential.layer(name)` requires those three services and 1a's `Policy`. Its scope owns one lifecycle actor. `testLayer(name)` uses the same logic; compose it with the test dependency layers as in `test/fixtures.ts`.

`set(value, metadata)` accepts metadata, policy and an optional Redacted refresh token. `resolve(caller, operation)` authorizes before decryption, checks lifecycle and wall-clock expiry, and logs allowed and refused attempts. Only its Redacted result crosses the internal gateway boundary. `describe()` returns metadata, policy and the persisted lifecycle snapshot, never ciphertext or tokens.

Rotation begins by retaining `previous` and replacing `current`. The grace window serves the whole new value. Abort restores the whole previous value; commit deletes it. A semaphore serializes value mutations and resolutions, including the crypto awaits. Uses admitted while refresh runs release that semaphore and wait for the actor, so they cannot block the refresh commit.

## Encryption and the unwrap fence

Both the envelope and the value use Web Crypto AES-256-GCM, 128-bit tags and independent random 12-byte IVs. There is no AES-KW dependency, JWK secret-key export, or `wrapKey()` call. This uses celld's documented GCM support and avoids its secret-key export/wrap caveat.

AAD is exactly:

- Envelope: `secret-cell.v1|dek|<credentialId>|<kekId>`.
- Value: `secret-cell.v1|<credentialId>|<valueVersion>`.

The desk approved three distinct cell unwrap sites:

1. `Keyring.importKek` reads binding bytes once, imports a non-extractable CryptoKey used only for envelope encryption/decryption, zeros the original and import-copy buffers, and wipes the Redacted wrapper.
2. `Keyring.encrypt` reads the Redacted string once and encrypts its UTF-8 bytes. Decrypt returns a Redacted string.
3. `Keyring.fetchKek` reads `KEK_ACCESS` once, to build the key service's `authorization: Bearer` header. Nothing else is merged into that request.

The source test retains 1a's `Fill.apply` checks and permits exactly these three additional sites. No aliases or reflection bypass it.

`newDek()` creates a non-extractable key and keeps raw bytes privately until the immediately following, one-shot `wrap(dek, credentialId)`. Wrap zeros and discards those bytes. Layer cleanup zeros any abandoned pending buffers. Unwrap and rewrap zero their temporary raw DEK buffers. Rewrap changes only the envelope and `kekId`, not the value ciphertext. JavaScript strings and CryptoKey internals cannot be explicitly zeroed; buffer wiping is best effort, not a claim about heap erasure.

## Persistence and recovery

SQLite holds `meta`, `value` (`current`, optional `previous`, optional encrypted `refresh`), `policy`, `lifecycle`, `uses`, and a version-1 migration row. Each stored JSON row passes its Effect Schema on read. SQL and malformed-row failures become `StoreUnavailable` with an operation label only. `RefreshFailure` and `StoreUnavailable` are cell-local errors; no domain error variants were added.

Every lifecycle mode entry commits its state, revision, actual serialized XState snapshot and `op=lifecycle` use row in one synchronous `transactionSync` call. The administrative ready acknowledgment is not a second domain transition. Revocation deletes every value row, including wrapped DEKs and refresh tokens, in the same transaction as the tombstone. It is terminal: no service command restores a revoked credential.

On activation, the machine restores its validated state/revision projection rather than replaying an in-flight provider invocation from a native snapshot. An interrupted `refreshing` snapshot becomes `needsAuth`; the core never silently repeats a possibly rotated refresh token. A refresh result encrypts and commits access and rotated refresh tokens together before the actor enters `active` and releases waiters. A retryable failure preserves the old tokens and returns to `active`; `invalid_grant` enters `needsAuth`.

Use-log pruning runs in the write transaction. It removes entries older than 90 days and retains at most the latest 100,000 ids. Resolve logs retain the configured matching route prefix, never the raw request path. Provider bodies and token hashes are not logged.

celld forbids application `BEGIN` and `SAVEPOINT` through SQL exec (`crates/celld/storage.rs:1325–1331`). Its `docs/services/durable-objects.md:106–108` specifies `transactionSync` with a no-argument callback. The desk approved extending the brief's exec-only port to include this required function. Only the Node adapter opens private savepoints on its database handle; it rejects transaction control through its public exec. A source test and a rollback test guard this boundary.

Phase 1c must supply provider adapters, the alarm schedule (including retry backoff), the DO response/durability boundary and binding loading. Node tests prove local SQLite ordering, not celld replication or bucket durability. Only one `Credential` service instance may own a credential's store at a time.

## Platform facts this package relies on

- Effect `4.0.5`, XState `6.0.0-alpha.65` and `@xstate/effect` `0.1.0-alpha.7`. The Effect source mirror matches `effect@4.0.5`. The package preserves the exact `@effect/vitest#it` unstable opt-in and the root fence.
- celld `docs/README.md` confirms single-thread/await interleaving, synchronous storage and durable alarms before the response boundary. Its fetch admission limit is **64 by default**, not an unconditional maximum: `CELLD_MAX_CELL_REQUESTS` can change it.
- `docs/cloudflare-compat.md` documents GCM tags from 96 through 128 bits. It does not document an AES-KW guarantee; it forbids JWK secret-key export/wrap. This package uses only AES-GCM with raw import.
- Clean room: no Kody source was opened, fetched, searched or cloned. The implementation follows its own design, the domain contracts, celld's docs and the rat-stack XState example.

## Evidence

`test/credential.model.test.ts` runs 75 generated event traces against a separate small state/value model. Each trace includes a controlled concurrent refresh before random events, so shrinking cannot remove the single-flight assertion. It checks stored rotated refresh tokens at every returning waiter and checks the next provider's refresh-token input. `test/concurrency.test.ts` races uses against rotation commits/aborts and revocation against an in-flight refresh.

`test/canary.test.ts` runs every operation against the live SQL adapter, scans each public result/error, every use row and every describe output for every 8-byte canary window, scans SQLite/WAL/SHM while open, then closes and scans every remaining file. Crypto tests cover credential/version AAD, wrong KEKs and envelope rotation. Store tests cover retention, malformed rows and activation recovery.

The intentional single-flight mutation and its restored green result are recorded in `test/red-proof.md`. Run the suite from the root with `pnpm test`; no celld or real secret is required.

## Phase 1d: GitHub App credentials

`github-app` stores a PKCS#8 PEM through the same envelope encryption as other values. Non-secret `githubApp` metadata contains an `appId` string and an `installations` owner-to-positive-integer map. `/v1/set` accepts `githubApp` with the initial value and infers the kind. Later sets retain the approved metadata. Kind changes and installation-map changes through set fail; `/v1/approve` can change `githubApp` metadata and policy together, in one store transaction, using approver's identity. Key order does not count as a map change.

`{{secret:example-key/acme}}` addresses the `example-key` DO with owner `acme`. Exact registered names retain their existing meaning, including older names containing a slash. An unregistered suffixed reference addresses its root credential. Non-GitHub kinds refuse sub-keys with a typed error and the corrected placeholder. A GitHub App requires an approved owner; the bare root never resolves to its PEM.

`Credential.layer(name, githubAppLayer?)` accepts a `GitHubApp` mint port. Its default fails closed without networking. The Worker adapter uses the injected 1c `Upstream`; tests route it to a Node HTTPS server on loopback. The fake uses runtime-generated RSA keys and a throwaway TLS certificate. These tests require `openssl` to create that certificate.

The JWT has RS256, `iss=appId`, `iat=now-60s`, and `exp=now+540s`. A 5xx retries once. A mint 401 or 403 sends `AUTH_FAILED` from active or rotating to `needsAuth`, persists the lifecycle state, and clears the caches. Provider bodies never become errors. The token response is schema-checked and limited to 16 KiB. Installation tokens are Redacted values held only in an Effect Cache in DO memory. Per-owner entries expire five minutes before the provider expiry. The existing credential semaphore serializes resolution and mutations; Cache supplies keyed deduplication and expiry. Set, approve of App metadata, both rotation outcomes, revoke, and scope disposal discard tokens and the cached signing key. Activation re-mints; no installation token is persisted.

The desk approved `Keyring.importSigningKey` on 2026-10-18. It opens the sealed value inside Keyring, accepts only the explicit `RSASSA-PKCS1-v1_5/SHA-256` algorithm, imports with `extractable=false` and `usages=["sign"]`, and wipes temporary PEM and DER byte buffers. Only an opaque CryptoKey leaves Keyring. There are still exactly four `Redacted.value` sites across the application. Malformed PEM errors contain only a credential name and static instructions. PKCS#1 armour is refused before storage with the exact conversion step: `openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pk8.pem`. JavaScript strings and CryptoKey storage cannot be explicitly erased.

For git, use a whole Authorization header with `{{secret-basic:user=x-access-token,password=example-key/acme}}`, without a `Basic ` prefix. `user` is a literal matching `[A-Za-z0-9._-]{1,64}`. The policy must explicitly allow `inject.basicUser="x-access-token"`, as well as its Authorization header and Bearer template. Fill constructs `Basic base64(user:token)` and adds the encoded credential and its windows to the redaction plan. The older two-secret `username=` form is unchanged.

GitHub's [JWT documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app) recommends backdating `iat` by 60 seconds, permits `exp` at most ten minutes into the future, requires RS256, and accepts an App id as `iss` (it recommends the client id). Its [installation-token documentation](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app) specifies the access-token POST, optional repository restriction, and one-hour lifetime. This phase mints at installation scope, without a repository restriction.

The App flow is the standard one: an RS256 JWT, installation lookup, an access-token POST with optional repositories, and a token-and-expiry response. No client secret is handled. End-to-end, canary, non-extractability and red-proof tests are in `packages/worker/test/github-app.test.ts`, `test/github-app.test.ts` and `test/github-app-red-proof.md`. They use generated keys only.
