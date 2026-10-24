# Lockjaw on Cloudflare (Alchemy)

Deploys the Lockjaw Worker to Cloudflare Workers with SQLite-backed Durable Objects. Alchemy is pinned at `2.0.0-beta.83`.

**Status: untested on a live account.** No account has been chosen and nothing has been deployed. `pnpm check` compiles the graph and tests it with a fetch that refuses every request. Two Worker changes made it runnable on Cloudflare and celld; see [Worker changes](#worker-changes).

## What gets declared

One `Cloudflare.Worker` (logical id `cell`), built from `packages/worker/src/index.ts` with the compatibility date from `packages/worker/wrangler.json`, plus these bindings:

| Binding | Kind | Source |
| --- | --- | --- |
| `CREDENTIAL`, `REGISTRY`, `REPLAY` | Durable Object namespaces (`Credential`, `Registry`, `Replay`) | `wrangler.json` |
| `CELL_DID`, `APPROVER_DID` | plain text | private config |
| `CALLER_DOCUMENTS`, `SETTERS` | plain text (JSON) | private config |
| `LOCKJAW_KEK`, optional `LOCKJAW_KEK_NEXT` | `secret_text` | deploy-time environment variable named in the private config |

Durable Object storage: on account Workers, Alchemy beta.83 doesn't upload a `migrations` block. It declares an `exports` map, built by `buildDurableObjectExports`, in which every new class gets `storage: "sqlite"` (`alchemy/src/Cloudflare/Workers/WorkerProvider.ts` 5577–5600, uploaded at 3776–3810). So Cloudflare never sees the tag `v1`. The stack refuses to compile if any bound class is missing from a `new_sqlite_classes` migration in `wrangler.json`, which keeps the two descriptions in step.

## Cloudflare trust boundary

Cloudflare holds both the Worker-secret KEK and the DO storage, so it can decrypt everything. Envelope encryption keeps values out of plaintext storage and storage backups. It does not keep them from Cloudflare.

The Worker is on the public internet unless optional Access is enabled. Authentication still requires signed single-use caller tokens with a 60-second maximum lifetime, the `Replay` DO, static caller documents with no DID resolution, per-credential host, caller and placement policy, and refusal before decrypt. Without a valid signed token, callers get refusals.

DO placement is managed by Cloudflare. A Durable Object "is instantiated in a data center close to where the initial `get()` request is made. This may not be in the same data center" ([Data location](https://developers.cloudflare.com/durable-objects/reference/data-location/)). Workers use Cap'n Proto RPC "for internal communications" ([Durable Object Stub](https://developers.cloudflare.com/durable-objects/api/stub/)). **Whether that hop is encrypted is unknown.** The pages cited here don't say. Treat it as inside Cloudflare's boundary, like the KEK.

### Optional Cloudflare Access

Set `access: {"enabled": true, "serviceTokenId": "<uuid>"}` to put a dedicated Access application in front of the Worker. It has one `non_identity` policy that admits that service token, and it covers `workers.dev`, routes, the custom domain and preview URLs. It's off by default. Create the service token outside this stack: Alchemy state would otherwise hold its client secret. Callers then send `CF-Access-Client-Id` and `CF-Access-Client-Secret` alongside their cell token. Don't use Access's single-header mode, because `/v1/fetch` already uses `Authorization`.

The base-URL swap drops every `cf-*` header and every `cookie`, so the Access credentials and the `CF_Authorization` cookie never reach the upstream host.

## Platform checks

- **Transactions.** "`sql.exec()` cannot execute transaction-related statements like `BEGIN TRANSACTION` or `SAVEPOINT`. Instead, use … `ctx.storage.transactionSync()`." `transactionSync` is "only available when using SQLite-backed Durable Objects" ([SQLite storage API](https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/)). That's the same contract the cell already meets on celld.
- **Web Crypto.** Workers implements sign/verify and importKey for RSASSA PKCS1 v1.5, ECDSA and Ed25519, and encrypt/decrypt and importKey for AES GCM ([Web Crypto](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)). That covers GitHub App JWTs, P-256 and Ed25519 caller tokens, and envelope encryption.
- **Credential names.** `ctx.id.name` is available inside a DO when the caller used `idFromName()` or `getByName()` ([Durable Object ID](https://developers.cloudflare.com/durable-objects/api/id/)). `Credential` relies on this.
- **Bundle.** The Worker bundles to one ES module, about 1.1 MB. Its only import is the `cloudflare:workers` built-in, which Alchemy's bundler leaves external. It has no `node:` imports, so it doesn't need `nodejs_compat`.

## Worker changes

1. **The DO classes extend `DurableObject` from `cloudflare:workers`.** The gateway calls every DO over RPC, and both runtimes refuse RPC to a plain class: "The receiving Durable Object does not support RPC, because its class was not declared with `extends DurableObject`." Cloudflare and workerd make the same check unless the `js_rpc` flag is set ([RPC](https://developers.cloudflare.com/workers/runtime-apis/rpc/)). celld does it the same way:
   - `crates/celld/js/bootstrap.rs` 735–740 records each export that derives from its `DurableObject` with a prototype walk;
   - `crates/celld/js/harness.js` 2876–2879 grants RPC only to those classes, or when `js_rpc` is set, and 5388–5396 throws the refusal;
   - `crates/celld/js/modules.rs` 331 and 915 provide `cloudflare:workers` as a built-in, and `harness.js` 9508–9513 defines the base class.

   workerd's base class also requires `env` as an object, so every class passes `env` to `super`. Node tests alias `cloudflare:workers` to a small local class (`packages/worker/test/cloudflare-workers.ts`).

2. **The base-URL swap only forwards what the caller meant to send.** After the fill, `/v1/u` drops these headers on top of `x-sc-*`:
   - hop-by-hop headers and any header that `Connection` names;
   - `host`, `forwarded`, `x-forwarded-*`, `x-real-ip` and `true-client-ip`;
   - `cf-*`, which covers `cf-connecting-ip` and the Access headers;
   - `cookie`, always. A credential placed in a cookie must use `/v1/fetch`, where the caller writes every header explicitly.

   An upgrade request that carries a credential is still refused, not quietly stripped.

## Secrets and Alchemy state

Alchemy beta.83 persists secrets in plaintext state, which is why this stack has its own state decorator. It writes `Redacted` values under `"__redacted__"` ([`StateEncoding.ts` 62–84](https://github.com/alchemy-run/alchemy/blob/v2.0.0-beta.83/packages/alchemy/src/State/StateEncoding.ts#L62-L84)). It lowers each `Redacted` env value into binding data as `{"type": "secret_text", "text": <plaintext>}` ([`WorkerAsyncBindings.ts` 485–500](https://github.com/alchemy-run/alchemy/blob/v2.0.0-beta.83/packages/alchemy/src/Cloudflare/Workers/WorkerAsyncBindings.ts#L485-L500)), and `ResourceState.bindings` is persisted. Its Worker upload sends `keepBindings: undefined` ([`WorkerProvider.ts` 3808](https://github.com/alchemy-run/alchemy/blob/v2.0.0-beta.83/packages/alchemy/src/Cloudflare/Workers/WorkerProvider.ts#L3808)), so a secret set out of band, for example with `wrangler secret put`, is dropped on the next deploy. The Worker secret has to be an `env` binding.

This stack therefore wraps `localState()` in `withheldState` (`state.ts`). Before each write, every `Redacted` value is replaced with `withheld-by-secret-cell`, and so is every `secret_text` binding's `text`. The encoded record is then scanned again. If any secret survives, for example inside a class instance, the write fails and nothing is persisted. The engine still has the real value in memory, so the upload carries the real secret.

The cost: state never matches the live secret, so every deploy re-uploads the Worker with the KEK from the current environment. The tests compile the real graph with a canary KEK and check that plain `localState()` writes the canary, while `withheldState(localState())` doesn't.

State lives under `.alchemy/` in the directory you deploy from. The stack refuses a directory inside this repository and sets `.alchemy` to mode 0700.

## Private config

The stack reads `~/.config/secret-cell/cloudflare.json`, or the path in `SECRET_CELL_CLOUDFLARE_CONFIG`. The file must be a regular file with no group or other permission bits (`chmod 600`). If it's missing, loose, or the wrong shape, the stack refuses with a What, Why and Next message that names fields but never their values. The example values below are documentation values. The repository holds no others.

```json
{
  "accountId": "0123456789abcdef0123456789abcdef",
  "workerName": "secret-cell",
  "reach": { "kind": "workers.dev" },
  "cellDid": "did:web:cell.example.com",
  "approverDid": "did:web:operator.example.com",
  "setters": ["did:web:caller.example.com"],
  "callerDocuments": [],
  "secrets": { "kek": "LOCKJAW_KEK", "kekNext": "LOCKJAW_KEK_NEXT" },
  "access": { "enabled": false }
}
```

- `reach` is one of the following. A domain or route turns `workers.dev` off.
  - `{"kind": "workers.dev"}`
  - `{"kind": "domain", "name": "cell.example.com"}`
  - `{"kind": "route", "pattern": "cell.example.com/*", "zoneName": "example.com"}`
- `callerDocuments` must pass the Worker's own document schema. A private JWK `d` is refused.
- `secrets` names environment variables. The stack never reads a key from a file. Each value must be JSON `{"kekId": "...", "key": "<base64url of 32 bytes>"}`, and the two `kekId` values must differ.
- `CLOUDFLARE_ACCOUNT_ID` must equal `accountId`, or the stack refuses.

## Deploy (bring your own account)

You need an API token with Workers Scripts edit for the account, plus Access edit if `access` is enabled, and plus Zone edit if you use a route or domain. Run from a private directory outside the repository. `REPO` is your checkout.

```sh
cd "$REPO" && pnpm install --frozen-lockfile && pnpm check

install -d -m 700 ~/.local/state/secret-cell/cloudflare
cd ~/.local/state/secret-cell/cloudflare
umask 077

export CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef
op run --env-file="$HOME/.config/secret-cell/cloudflare.env" -- \
  "$REPO/deploy/cloudflare/node_modules/.bin/alchemy" deploy \
  "$REPO/deploy/cloudflare/alchemy.run.ts" --stage prod
```

`cloudflare.env` holds secret references, not values. Replace `<CLOUDFLARE_TOKEN_VARIABLE>` with the API token variable Alchemy reads (`alchemy/src/Cloudflare/Auth/AuthProvider.ts` 490). For example:

```sh
<CLOUDFLARE_TOKEN_VARIABLE>=op://<vault>/<token-item>/<field>
LOCKJAW_KEK=op://<vault>/<kek-item>/<field>
```

Any secret manager that injects environment variables for one command works the same way. To remove the deployment, run the same command with `destroy` in place of `deploy`. That deletes the Worker that hosts the Durable Objects, so assume it takes every stored credential with it.
