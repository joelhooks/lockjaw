# sc: Lockjaw client

`sc` signs one short-lived ES256 caller JWT per request. It sends credentials to the Worker through stdin, not argv. The Worker approves policy separately and redacts upstream echoes before they reach the client.

## Build and run

Requires the repository's pinned Node 24 and pnpm. The PTY tests also use `python3` and its standard-library `pty` module.

```sh
pnpm install --frozen-lockfile
pnpm --filter @lockjaw/client build
node packages/client/dist/sc.js --help
pnpm --filter @lockjaw/client exec sc --help
```

Set `SC_URL` to the Worker origin and `SC_AUDIENCE` to its configured DID. `--url` and `--audience` override those environment variables. Plain HTTP is accepted only for literal CGNAT addresses (the RFC 6598 shared address range) and loopback (`127.0.0.0/8`, `::1`, or `localhost`). Other origins require HTTPS. User info, paths, query strings and fragments are refused. Requests never follow redirects and are never retried automatically.

For an agent-secrets identity, use the env-injection runner. This is a tool invocation, not a shell command. Replace the secret name and absolute executable path:

```text
secrets_exec {"env":{"SC_IDENTITY_JSON":"<rat king identity name>"},"command":["node","/absolute/path/secret-cell/packages/client/dist/sc.js","list"]}
```

`SC_IDENTITY_JSON` takes `{did, signing, kid?}`. `signing` is a private EC P-256 JWK with `kty`, `crv`, `x`, `y` and `d`. Existing Rat King identities may also contain `agreement`; the client does not use it. `kid` defaults to `#atproto`. The alternative `--identity-file <path>` accepts only a regular, non-symlink file with mode **0600**, checked on the opened descriptor. Identity sources are mutually exclusive. There is no inline identity flag, argv key, config fallback or implicit identity file.

## Save, approve and use

```sh
sc set example/key --kind key < /path/to/value
sc approve example/key \
  --host api.example.com --caller 'fleet/*' --placement fleet-issuer \
  --inject 'Authorization: Bearer {value}'
sc fetch https://api.example.com/resource \
  -H 'Authorization: Bearer {{secret:example/key}}'
sc list
sc describe example/key
sc revoke example/key
```

`set` refuses a terminal stdin. It reads stdin fully without trimming, sends only `{name, value, expiresAt?, githubApp?}`, and zeroes the input buffers after send, including failure paths. JavaScript strings and the serialized HTTP body cannot be reliably zeroed; they live until garbage collection. Neither value nor identity is logged.

`--expires-at` takes an ISO timestamp and becomes milliseconds on the wire. `--kind key|github-app` selects the input contract, not a wire field. For a GitHub App, add `--github-app-file <metadata.json>` containing only `{appId, installations}`. The file must be regular, not a symlink, and mode 0600 or 0644. PEM markers in it are refused. Pipe the App's PKCS#8 PEM key through stdin. Existing credential kinds remain server-owned.

Saving **does not approve hosts or callers**. For a setter, the optional `set` policy flags only construct the printed `sc approve` next command, and the server ignores any policy a setter sends. Run that command as approver. The server enforces `APPROVER_DID`, so a setter identity cannot grant itself access.

The one exception is a **delegated manager**: a desk holding a grant with the `set` op. With `--placement`, `sc set` sends a policy, and the cell refuses it unless every host, route and caller in it lies inside that grant. The refusal names the field that falls outside.

## Delegated grants and worker passes

```sh
op document get lockjaw-approver --vault Private | sc grant acme/desk --identity-stdin \
  --credential 'acme/*' --host api.example.com --op use --op set --op grant --grantee 'acme/*' --exp 2026-10-20T00:00:00Z
sc grant acme/desk --run <run-handle> --credential acme/key --host api.example.com --op use --exp 2026-10-19T18:00:00Z
sc grants
sc grant revoke <grant-id>
sc rotate acme/key < /path/to/new-value
```

- **Root grants** come from approver only.
- **Child grants** are strict sub-scopes of a grant the caller holds that includes `grant`. Each field must be covered (credentials, hosts, routes, ops, grantees), and `--exp` can be no later than the parent's.
- **Chains** stop at three links.
- **Revoking a grant** revokes every descendant at once.
- **Expiry** of any ancestor disables the whole chain.

A desk's worker never holds the desk key:

1. The worker runtime makes an ephemeral P-256 key in memory and keeps it there.
2. The desk mints a worker pass of at most 10 minutes:
   ```sh
   sc pass --desk acme/desk --handle <run> --worker-key <did:key|public-jwk.json> --scope 'sh.secretcell.fetch:acme/*' > pass
   ```
   `--worker-key` refuses any JWK with a private `d`.
3. The worker runs `sc --pass pass fetch …`, with `SC_IDENTITY_JSON={did: <desk DID>, signing: <ephemeral JWK>}` in env, never on disk.

`run-ticket` and `--run-ticket` remain aliases for one release and print a deprecation note to stderr. Pass files contain a JSON `{record, signature}` envelope. The signature covers domain-tagged DAG-CBOR, not a compact JWS. Each request still carries a compact ES256 JWS signed by the worker.

The pass scope must fit the desk's own current grant ceiling. Use `:<credential pattern>` when the desk holds a restricted credential scope. The run grant remains a separate, narrower check.

Under a worker runtime, set `SC_PASS_FILE` instead of `--pass`; giving both is refused. The runtime claims, holds and renews the pass, and it is the only writer of that file; `sc` reads it before every request and never renews. The file must be a regular mode 0600 file owned by the current uid, and is exactly `{"v":1,"pass":<signed pass>,"ticket"?:<signed name ticket>,"run":"<label>:<id>","workerDid":"did:key:…","renewedAt":<unix s>}`. `sc` refuses an unknown `v`, a `workerDid` or `run` that disagrees with the pass, an `SC_IDENTITY_JSON` key other than `workerDid`, and a ticket whose name and DID differ from the pass's `desk` and `deskDid`. With under 30 seconds left on the pass or ticket it exits with `PassStale`, pointing at the worker's blocked item in its desk queue. A present ticket goes out as `x-sc-ticket`. A desk-minted `--pass` is never renewed and is refused once expired. `src/renewal-wire.ts` keeps the renewal request wire (`{run, workerDid, proof: {run, nonce, now, signature}}` over DAG-CBOR `{domain: "sh.ratking.pass.renew.v1", run, workerDid, nonce, now}`) that the runtime mirrors; `sc` itself opens no socket.

A pass caller acts only through grants. It never inherits the desk's setter, approver or policy-caller standing. A pass carries only `sh.secretcell.fetch`, `.describe`, `.list` or `.broker.<name>`, each optionally narrowed with `:<credential pattern>`.

Repeat `--host`, `--caller` and `--placement` for multiple entries. `--placement` is the trusted **issuer** field from the Worker's callers document, not a token claim or a target host. It is required for a usable approval. Ports accept repeated flags or comma-separated integers, such as `--ports 8443 --ports 9443,10443`. Port 443 is implicit and must not be listed.

Each credential has one injection header/template. A repeated `--inject` is refused rather than silently replacing the first. Use another credential name for a second header shape. `--basic-user <literal-user>` sets the optional `inject.basicUser` separately.

`fetch` accepts `-X METHOD`, repeated `-H 'Name: value'`, and `--data @file` or `--data -`. It prints the upstream status line to stderr and body to stdout. A request needs at least one `{{secret:<name>}}` placeholder in its credential's declared header; the Worker refuses anything else as `nothing-to-fill` and makes no upstream call, so send unfilled requests directly. `--json` instead prints `{status, headers, body}` with body as a string. Worker refusal JSON goes to stderr unchanged. `list` and `describe` show metadata only. `revoke` is idempotent, and only setters or approver may use it.

## Approver identity with 1Password

Generate the key directly into the approver's vault:

```sh
sc keygen --public-out ~/approver.did.json | op document create - --vault Private --title lockjaw-approver --file-name identity.json
```

Approve with one stdin read, without a private identity file:

```sh
op document get lockjaw-approver --vault Private | sc approve example/key --identity-stdin --host api.example.com --caller 'fleet/*' --placement fleet-issuer --inject 'Authorization: Bearer {value}'
```

Unset `SC_IDENTITY_JSON` and omit `--identity-file` for stdin approvals. `--identity-stdin` is permitted only for `approve`. It consumes the identity once and signs a fresh token for every approval in that invocation.

The keygen stdout exception is deliberate: it emits the private identity only to a pipe, never to a terminal or disk. `--public-out` is created exclusively, mode 0644; an existing path is never overwritten. Treat a failed downstream `op` write as an unsuccessful import. Delete or move the public document yourself before trying a new key. Do not redirect private stdout into a transcript or a file.

The DID follows the [did:key P-256 method](https://w3c-ccg.github.io/did-key-spec/#p-256): unsigned-varint multicodec `p256-pub` (`0x1200`, bytes `80 24`), compressed SEC1 public key, then base58btc multibase. The key fragment is that multibase fingerprint. The public document includes `authentication`, `verificationMethod.publicKeyJwk`, and two Lockjaw trust fields: **`name: "approver"` and `issuer: "approver"`**. The operator adds this public document to the Worker's trusted callers array and sets `APPROVER_DID` to its `id`. CallerAuth verifies configured documents; it does not fetch or self-register `did:key` documents.

### Batch approvals

```sh
op document get lockjaw-approver --vault Private | sc approve --identity-stdin --batch ./policies.json
```

`policies.json` is a nonempty array of complete policies, not patches:

```json
[
  {
    "name": "example/key",
    "hosts": ["api.example.com"],
    "callers": ["fleet/*"],
    "placements": ["fleet-issuer"],
    "inject": { "header": "authorization", "template": "Bearer {value}" },
    "ports": [8443]
  }
]
```

The entire file is decoded before the first request. Each entry gets a new JWT/jti. Processing stops on the first refusal; earlier approvals are not rolled back. One pipe uses one `op` session for the batch. Review every policy first: approval replaces policy rather than merging it.

## Local git/SDK forwarder

```sh
sc forward --listen 127.0.0.1:8080 --upstream-host api.example.com
```

Point the SDK base URL at that loopback listener and use a placeholder header. A forwarded request without one is refused as `nothing-to-fill`. Each incoming request becomes `/v1/u/api.example.com/<path>` with a freshly signed `x-sc-auth`. Caller-supplied `x-sc-*`, Host and hop-by-hop headers are stripped. The body is buffered; this is not a CONNECT tunnel, WebSocket proxy or an unbounded streaming-upload adapter. Responses stream with backpressure. A literal loopback bind is mandatory; `0.0.0.0`, LAN addresses and DNS bind names are refused.

The listener lifetime is owned by an Effect scope: acquire → listening → interrupted/closed. SIGINT/SIGTERM interrupt that scope and close its connections. Requests have independent ingress runtimes and token generation; there is no shared token or retry state.

## Errors and exit codes

Local failures have three lines: `sc <command> failed: ...`, `Why: ...`, `Next: ...`. Native error messages and schema inputs are never forwarded. Worker error JSON already has `what`, `why` and `next`, so it passes through unchanged. Exit codes: **0** success, **1** Worker refusal, **2** usage/input refusal, **3** transport failure.

## Wire premises and implementation choice

Built on a descendant of `37ffb7a`. The brief's `FetchRequest` is actually named `GatewayRequest` in `packages/gateway-rules/src/placement.ts`. Set and approve schemas live in `packages/worker/src/gateway.ts`. Audience must equal the Worker's `CELL_DID`; operation lxm is `sh.secretcell.<operation>`, including `fetch` for forwarding. Tokens include a signed `sid`, a 16-byte random base64url `jti`, and `iat`/`exp` at most 60 seconds apart.

The client implements the request JWS signing boundary with Node Web Crypto, following Rat King's service-token header and claims contract. It imports a non-extractable sign-only CryptoKey. ES256 signatures use the 64-byte JOSE/P1363 Web Crypto form. Signed passes and name tickets use the pinned Rat King lexicon dependency; see the root README for its review-export publication status.

Desk-authorized Worker additions: `GET /v1/describe?name=...` (`sh.secretcell.describe`) and `POST /v1/revoke {name}` (`sh.secretcell.revoke`). Both retain the authentication, replay and use-log path. Describe exposes an explicit metadata projection, including the value version but no value or ciphertext. Revoke accepts a setter or approver. No new secret unwrap site was added.

## Proof

`pnpm test` builds the CLI and runs the real Worker with Node SQLite/DO fakes, ephemeral P-256 identities, a fake upstream and loopback HTTP only. The spawned-process tests cover stdin set, separate approval, redacted fetch, metadata, non-approver approval refusal, revoke, replay refusal and three forwarded requests with distinct tokens. They scan every 8-byte window of the value and private scalar (text and raw bytes) against captured stdout, stderr and spawn argv. Keygen is tested separately for its deliberate private stdout output; its public file and stderr get the same private-scalar scan. Real PTYs prove terminal refusals.

The replay red proof resubmits a captured fetch token unchanged to the Worker. It must return 401 with `rule: replay`; ordinary client calls immediately return to fresh random tokens. There is no test-only replay switch in production code.
