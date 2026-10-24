# Lockjaw Worker (Phase 1c)

Level 0: this package is not deployed. Node fakes exercise the same DO classes, durable SQL adapter, gateway flow and static-DID signature verifier. No real secret, live upstream or celld process is used.

## Bindings and entry

`src/index.ts` exports the Worker and the plain celld DO classes `Credential`, `Registry` and `Replay`. `wrangler.json` is a fail-closed deployment template, not a ready-to-run deployment. Phase 3 owns rendering it.

- `CREDENTIAL`: namespace keyed by credential name through `idFromName`. RPC methods resolve, set, describe, revoke, rotateBegin, rotateCommit and rotateAbort. approve is the separate policy RPC. Alarm scheduling covers expiry and persisted refresh backoff.
- `REGISTRY`: singleton named `registry`. Stores only metadata, plus gateway attempt rows, including refusals before a credential is resolved. Credential core resolution rows remain in the credential's own SQLite database.
- `REPLAY`: SHA-256 caller-key shards (first two digest bytes), with an atomic key/jti uniqueness check and expiry pruning. Alarms delete only expired entries and re-arm for the next expiry.
- **KEK, exactly one of two modes.** The DO constructor selects the mode with `selectKek`. Both modes set, or neither, is a three-part `rule: kek` refusal; the cell then answers every key operation with 503.
  - _Binding mode_, unchanged: `LOCKJAW_KEK` holds binding file contents as JSON with `kekId` and a base64url-encoded 32-byte `key`. Optional `LOCKJAW_KEK_NEXT` uses the same format and a distinct id. The template declares only the required secret name; it contains no material. celld v0.6.1 persists vars in its bucket manifest, so this mode is for tests and local runs, not the fleet ([source finding](../../.brain/projects/step7-source-blocker.svx)).
  - _URL mode_: `KEK_URL` and `KEK_ACCESS`, both strings. `KEK_URL` must be exactly `http://127.0.0.1:<port>/kek` with a port from 1 to 65535 and no other host, path, query, fragment or user information; `localhost` is refused. `KEK_ACCESS` is an opaque, non-empty bearer token, wrapped in `Redacted` as soon as it is read. Only the token goes into vars; a guest-local key service holds the KEK. `LOCKJAW_KEK_NEXT` with URL mode is refused, because URL mode does not rotate.
  - The URL-mode request is `GET KEK_URL` with `redirect: "error"` and the single header `authorization: Bearer <KEK_ACCESS>`. No caller header, URL or body reaches it. It succeeds only on status 200, `content-type: application/octet-stream` and a body of exactly 32 bytes, read with a 32-byte cap. The bytes are imported as a non-extractable AES-GCM key for encrypt and decrypt, then zeroed.
  - URL mode's `kekId` is `kek-` plus the first 16 hex digits of SHA-256(`secret-cell.v1|kek-id|` ‖ KEK bytes). Binding mode with that id and the same bytes opens the same records. A record sealed under another key fails as a three-part kekId mismatch, not a decrypt error.
  - The KEK is fetched lazily, on the first operation that needs it, and cached once per isolate. A failure is not cached: that request gets a three-part 503 `rule: kek`, and the next one fetches again. Describe, list and policy work never fetch the KEK.
- `CALLER_DOCUMENTS`: static DID-documents file contents, a JSON array. Each document has id, authentication key ids and verificationMethod entries with id, controller and a public JWK. The local binding also supplies the trusted Rat King name and issuing-host name as `name` and `issuer`. Private JWK `d` fields are rejected. No DID resolution fetch is made.
- `CELL_DID`: the exact caller-token audience.
- `SETTERS`: JSON array of caller DIDs allowed to submit values.
- `APPROVER_DID`: the sole policy approver DID. The template's invalid placeholder must be replaced before deployment.

## HTTP contract

All caller tokens require a valid Ed25519 or P-256 JWS, iss, aud, iat, exp, jti and lxm, plus signed sid. The lifetime is at most 60 seconds. Name and issuing-host authority come from the static document, never unsigned headers or display claims.

- POST /v1/fetch: JSON {url, method, headers: [{name, value}], body?}. Authentication is x-sc-auth or Authorization: Bearer. lxm is sh.secretcell.fetch.
- /v1/u/<host>/<path>: base-URL swap; forwards the incoming method, headers and body. Authentication must be x-sc-auth, so caller authentication cannot be confused with the upstream Authorization header. Same fetch lxm.
- **No fill, no forward.** Both fetch routes forward only requests they fill. A request whose placement check yields no fill is refused with 403 `rule: nothing-to-fill` before any upstream call. The refusal says what (no credential placeholder), why (Lockjaw forwards only requests it fills, to hosts declared for those credentials) and next (send it directly, or add `{{secret:<name>}}` in the declared header). `x-sc-resolution: off` disables every fill, so it always ends this way, and the refusal names it. The gateway is not a general HTTPS proxy, including for LAN-literal hosts.
- GET /v1/list: sh.secretcell.list. Returns credential names, kinds and current lifecycle states, never values.
- POST /v1/set: sh.secretcell.set, JSON {name, value, expiresAt?}; requires the setters binding. expiresAt is milliseconds since epoch, or null (the default) for no expiry. It describes the new value, not the old value. New credentials receive empty host, caller and placement policies. Existing policies are preserved; a supplied policy in this body cannot approve anything.
- POST /v1/approve: sh.secretcell.approve, JSON {name, policy}; requires APPROVER_DID. This is separate from saving. No desk-page UI exists yet.
- POST /v1/rotate: sh.secretcell.rotate, JSON {name, value}. The value becomes a new value version. Requires a setter, APPROVER_DID, or a grant with `rotate`.
- POST /v1/grant: sh.secretcell.grant, JSON {grantee: {desk, runHandle?}, scope: {credentials, hosts, routes?, ops, grantees, exp}}.
  - approver creates root grants.
  - Anyone else needs an active grant with `grant` covering the new scope. The parent is set automatically.
  - A refusal names the field that widened.
- POST /v1/grant/revoke: sh.secretcell.grant.revoke, JSON {id}. Revokes the grant and all its descendants in one transaction. approver, or the holder of an ancestor grant.
- GET /v1/grants: sh.secretcell.grant.list. Returns the caller's grants and their descendants, metadata only.

**Grants** live in the single `Grants` DO, migration v2. Effective scope is computed at check time:

- every link must be unrevoked and unexpired;
- every link must be a sub-scope of its parent;
- the chain must be no deeper than 3.

For fetch, set, rotate and revoke, a caller passes either on the credential's own policy (today's path) or on a covering grant chain. All checks run before resolve. Use rows record the grant chain.

A **credential created under a grant** has its policy clipped to that grant. Its own-policy path works only while that grant's chain is active.

**Worker passes.** `x-sc-pass` carries a JSON `{record, signature}` envelope, signed with ES256 over domain-tagged DAG-CBOR and lasting at most 10 minutes. `src/pass.ts` calls the shared `@rat-king/lexicon/passes` verifier, vendored from `6c1e5d8` as compiled JavaScript and declarations:

- The pass must be signed by an authenticated P-256 key of the named desk in the callers file.
- Its scope must fit the desk's own active grant ceiling, not merely the run grant. A desk with no grants cannot issue a usable pass. The cell maps `use` to `fetch` and `describe` to `describe`. Any held grant allows `list` visibility for its credential patterns, matching the existing list filter. Credential restrictions stay in the scope strings.
- The request must be signed by the pass's `worker` did:key.
- `iss` must be the desk.
- `sid` must be the pass's `run`.

The caller is then `{desk name, run}`:

- it is authorised only by grants for that run, intersected with the pass scope;
- it is never authorised by `SETTERS`, `APPROVER_DID` or policy callers.

Pass nonces bind atomically on first use to the worker thumbprint and run in `Replay`, through the closed `exp + 60 s` boundary. Matching presentations cannot shorten retention. Expired bindings remain as tombstones, so an old nonce cannot be reopened. The shared verifier checks the request signature over the exact JWS signing input; the cell still checks audience, lxm, issuer, run, request lifetime and jti replay.

**Name tickets.** `x-sc-ticket` carries a signed ticket envelope. `TICKET_ISSUERS` is JSON containing exactly three distinct `{issuer, key, namespaces}` entries; `key` contains only `{kty: "EC", crv: "P-256", x, y}`. Private key fields and extra binding properties are refused. The shared verifier checks the pinned issuer, namespace boundary, fingerprint, signature and ticket lifetime. Missing or invalid bindings fail closed with a three-part error.

Known callers need no ticket, including for a policy `callers: ["*"]`. If they supply a ticket, its name, DID and key must match their callers entry and request key. An unknown desk can authenticate with a ticket and its own signed request. Such a caller can only fetch or describe a credential whose policy contains an exact `*` entry, on an allowed issuer placement, host and route. Prefix policies, exact-name policies, grants and all management operations confer no authority on ticket-only desks. A ticket-only desk has no grant ceiling for a worker pass.

Rebuild the vendor with `bash tools/vendor-lexicon/build.sh`. It reads a pinned `git archive` without changing the Rat King checkout. The archive build normalizes two byte-return declarations and rewrites relative `.ts` specifiers in both JavaScript and declarations. `vendor/rat-king-lexicon.lock.json` records the full source commit and SHA-256; repeated builds must match.

All policy, placement and lifecycle preflights finish for every fill before any resolve RPC starts. Every x-sc-* header is stripped before upstream. The upstream uses Effect HttpClient, manual redirects and one 10-second deadline including body consumption. Status is passed through, including redirects and errors. The fetch adapter omits status text because Effect's response abstraction does not expose it; injected upstream responses still pass status text through EchoRedactor. Headers, URL and body stream also pass through EchoRedactor. Body errors after HTTP headers have been sent terminate the stream with a sanitized typed error; they cannot retroactively replace that response with JSON.

The gateway logs one allowed/refused attempt, including authentication refusals, in Registry. It stores no body, headers, token, value, raw error or URL query. Path prefix is empty in this gateway-level record; successful credential resolution rows retain the matched policy prefix. A storage failure fails closed rather than pretending an unrecorded use succeeded.

## The reviewed RPC fence

**DO RPC cannot carry WeakMap-backed Redacted; plaintext crosses only the same-node V8 RPC boundary.**

The desk approved one exception to the original no-new-unwrap acceptance rule:

1. `src/credential-do.ts`: Credential.resolve has exactly one new Redacted.value call. Its branded ResolvedForFill payload contains only credential, valueVersion and value.
2. `src/gateway.ts`: decodeResolved immediately wraps that field back in Redacted and feeds Fill. It never logs or returns the payload.

The branded payload is not exported from the package entry. The source fence permits it only in these two internal modules and counts all five production unwrap sites: `Fill.apply`, `Keyring.importKek`, `Keyring.encrypt`, `Keyring.fetchKek` (the URL-mode bearer header) and this one. Fake RPC replies are structured-cloned to catch accidental reliance on shared WeakMap identity.

**Single-node deployment is required.** celld peer tunnels do not encrypt calls. Before any second node or standby is added, its peer tunnel must run over an encrypted overlay. A future hardening option is to move fill and upstream work into the credential's isolate; this packet does not do that.

## Recovery and policy follow-ups

- Policy.ports is optional, unique integer ports 1..65535 excluding 443. Missing means no non-default explicit ports. Placement checks every participating credential's list. WHATWG URL parsing normalizes an explicit :443 to the implicit HTTPS port, as before.
- An interrupted refresh gets one activation retry. Its persisted recoveryAttempt prevents a second crash from starting an unbounded retry chain. invalid_grant, another failed recovery attempt, or another crash goes to needsAuth. Success resets the recovery budget. Normal transient refresh failures retain exponential backoff (1 second to 5 minutes) in durable SQL; set and terminal lifecycle transitions clear stale schedules.
- There is no provider/broker in Phase 1c. The default refresher refuses retryably; Phase 1d injects the GitHub provider.

## Proof

Run pnpm check at the repository root. Tests cover real ephemeral Ed25519/P-256 signatures, structured-cloned DO RPC, Node SQLite files and WAL, all named pre-resolve refusals, setter/approver authority, replay races and TTL alarms, refresh recovery, expiry/backoff, redirect/status pass-through, stream deadlines and the source unwrap fence. The canary crosses set and fetch and is scanned in caller-visible route bodies and headers, errors, list output, use rows and raw SQLite/WAL files. See test/red-proof.md for the deliberate x-sc-auth stripping regression.
