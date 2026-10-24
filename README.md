# Lockjaw

Lockjaw injects credentials at egress. Agents hold placeholders such as `{{secret:example/key}}`, not the credential value. A cell authenticates the caller, checks the approved host and header placement, decrypts the credential, fills the header and sends the HTTPS request. It redacts credential echoes from the upstream response.

This is an explicit gateway, not a transparent network firewall. It does not stop an agent's other network traffic. Decryption and upstream HTTP happen inside the cell's trust boundary; the cell operator and hosting provider belong inside that boundary.

## Identity and approval

Each caller has its own DID and signing key. Every request has a signed, single-use token with a maximum lifetime of 60 seconds. The cell checks configured public caller documents, rather than resolving arbitrary DIDs from the network. Replay protection lives in a Durable Object.

Saving a value is separate from approving its use. The configured `APPROVER_DID` approves credential policies: allowed hosts, caller names, trusted issuer placements and the injection header/template. Setter access alone cannot approve a policy. Credentials are envelope-encrypted at rest; `LOCKJAW_KEK` and optional `LOCKJAW_KEK_NEXT` supply the binding-mode key-encryption keys. URL-mode key loading is an alternative, not a second simultaneous mode.

The approver can issue root grants. A grant holder can delegate only a narrower scope, with no later expiry; chains stop at three links. Revoking a grant revokes its descendants. Worker passes let a desk authorize an ephemeral worker key without handing over the desk's key. Passes last at most ten minutes and must fit the desk's current grant ceiling and the worker's run grant. A worker pass does not inherit setter or approver rights.

Rat King supplies the signed pass and name-ticket protocol. Ticket authentication currently requires **exactly three distinct pinned public issuers**, each with namespaces. This is a current implementation constraint, not a general requirement of the signature protocol.

## Use

Requires Node 24.18.0, pnpm 11.3.0 and `python3` for PTY tests. The publication fence also requires `gitleaks`.

```sh
pnpm install --frozen-lockfile
pnpm --filter @lockjaw/client build
pnpm --filter @lockjaw/client exec sc --help
```

Configure `SC_URL`, `SC_AUDIENCE` and a caller identity through `SC_IDENTITY_JSON` or a mode-0600 identity file. Never put a private key or credential value in command arguments. See the [client guide](packages/client/README.md) for identity custody and approval commands.

```sh
sc set example/key --kind key < /path/to/value
sc approve example/key \
  --host api.example.com --caller 'example/*' --placement example-issuer \
  --inject 'Authorization: Bearer {value}'
sc fetch https://api.example.com/resource \
  -H 'Authorization: Bearer {{secret:example/key}}'
```

Run `approve` with the approver identity, not the setter identity. For SDK base-URL substitution, use `/v1/u/<host>` or the loopback-only `sc forward` adapter. Neither is a CONNECT tunnel. The forwarder buffers request bodies; it is not an unbounded upload adapter.

The CLI remains `sc`, client environment variables remain `SC_*`, and wire operations remain `sh.secretcell.*`. Package names are `@lockjaw/*`. Existing Durable Object class names, the deployed cell name and `CELL_DID` are unchanged to preserve live state and client compatibility.

## Refusals

The cell refuses invalid signatures, expired or replayed tokens, unknown callers, disallowed hosts, callers or placements, and requests outside a delegated grant. `isPublicHost` rejects IP literals and special-use hostnames at policy decode and target checks with `host-not-public`. This is a hostname check, not DNS-resolution or upstream-address pinning. The cell also refuses credentials in URLs or request bodies, unsupported header placement, non-HTTPS credential egress and a request that fills no placeholder. It does not forward an unfilled request as a fallback. Missing or conflicting key-encryption-key configuration leaves credentials sealed.

See the [Worker API](packages/worker/README.md), [credential storage](packages/cell/README.md) and [policy rules](packages/gateway-rules/README.md) for the implemented contracts.

## Deployment

- [Cloudflare with Alchemy](deploy/cloudflare/README.md): graph and offline tests exist; **untested on a live account**. Cloudflare holds both the encrypted storage and the Worker KEK.
- [celld with Alchemy](deploy/celld/README.md): public deployment layer coming. No deployment is performed by an export or by the checks.

## Compared with other egress proxies

All three approaches keep real credentials out of the agent and substitute them for approved destinations. Their identity and routing boundaries differ.

| | Lockjaw | [varlock proxy](https://varlock.dev/guides/proxy/) | [iron-proxy](https://github.com/paradigmxyz/iron-proxy) |
| --- | --- | --- | --- |
| Routing | Explicit signed gateway, base-URL swap or loopback forwarder | Transparent local proxy with `HTTPS_PROXY` and CA trust | Transparent MITM with DNS and a proxy CA |
| Identity | Per-caller DID, delegated grants and worker passes | Parent process | Network position |
| Approval | Approver-signed requests that set credential policy | Proxy rule annotations | Proxy configuration |
| Substitution | Headers only; HTTPS only; nothing-to-fill refusal | Headers by default; optional query/body substitution | Headers and other protocol surfaces |
| Other egress | Not a firewall for unrelated requests | Optional strict egress rules | Default-deny destination allowlist |

These comparisons describe the documented approaches, not a comparative security audit. Choose the trust boundary deliberately.

## Checks and review-export status

```sh
VITEST_MAX_WORKERS=4 pnpm check
pnpm typecheck:tsc
```

`pnpm fence` additionally uses an operator-owned private inventory; [fence setup](tools/fence/README.md) explains the schema and permissions. `pnpm fence:check` runs generic rules without that inventory.

The review export retains a SHA-256-pinned tarball built from the public MIT Rat King lexicon source. **`@rat-king/lexicon` is unpublished: it needs publication or Joel's OK before public release.** The celld layer separately awaits a decision on the unpublished `@rat-king/alchemy-nest` package. Neither package's publication is implied by this review copy.

## License

[MIT](LICENSE).
