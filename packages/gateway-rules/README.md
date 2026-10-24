# Gateway rules

Level 0. This package does not fetch, decrypt, deploy, or use real credentials.

## Flow

1. Decode caller input with `GatewayRequest` and credential policies with the domain schemas.
2. Call `Policy.authorize` for **each** credential named by a placeholder. Caller identity verification belongs to a later adapter.
3. Call `Placement.check`. Its Layer takes a map of credential names to policies, never a resolver.
4. Pass the same request and its returned fills to `Fill.apply`. Keep both inside the gateway boundary. Never serialize the filled request.
5. Send the filled request with manual redirects. Give the returned opaque redaction plan to `EchoRedactor` before exposing any response surface.
6. Rebuild upstream errors through `EchoRedactor.error`. Do not retain the upstream cause or stack. Body-stream failures keep their typed error channel; the transport adapter must sanitize those errors too.

`Fill.apply` is the only plaintext unwrap. It returns the request, the substituted values as a `ReadonlySet<Redacted<string>>`, and a closure-backed plan. The plan contains no serializable patterns. Callers own the returned Redacted values and their lifetime. This packet adds no retention or cache.

Both live and test Layers run the same deterministic rules. Nothing needs a service stub that silently skips policy.

## Redaction contract

The plan matches raw, URI, form and JSON-escaped values. It also matches the whole injected header and the complete base64 Basic credential. It matches eight-byte windows of these forms as well, so overlapping echoes cannot leave a long fragment behind.

Body streams hold back at most `longestPattern - 1` unprocessed bytes between input elements. Each subscription gets its own state. Matches become equal-length NUL bytes for all bodies, including range bodies. NUL cannot occur in an accepted header credential. Masking prevents removal from joining fragments into another secret. These are redacted bytes, not necessarily valid JSON or text.

Metadata text uses repeated deletion until no match remains. This also prevents deletion from reassembling a secret. Redacted responses drop `content-length`. The adapter must not reuse a body's original integrity digest or validator after redaction.

## Host and route limits

Hosts use lowercase ASCII DNS names. Normalize Unicode host input to its ASCII form before asking for policy approval. Exact host rules have no scheme, port, trailing dot, or path. Request matching lowercases the parsed hostname and removes its trailing dot. Non-default ports and URL user info are refused for credential-bearing requests.

A wildcard matches one label below its registrable base, never the base itself or a deeper descendant. The small built-in public-suffix list is **not the Public Suffix List**. It includes common multi-label and private suffixes such as `co.uk`, `github.io`, `pages.dev` and `vercel.app`. Unknown suffixes fall back to their final label. Review that limit before any live host approval; this packet is not a general public-suffix verifier.

Routes compare method and path prefix after URL normalization. When routes are declared, ambiguous encoded slash, backslash and nested percent escapes are refused. Both the original and decoded normalized path must match. Duplicate headers and credential-bearing upgrade requests are refused. `Placement.check` never returns an empty fill list. A request with no credential placeholder fails with a three-part `NothingToFill` (`rule: nothing-to-fill`): Lockjaw forwards only requests it fills, to hosts declared for those credentials, so the caller should send the request directly or add `{{secret:<name>}}` in the declared header. `x-sc-resolution: off` is still parsed, but it disables every fill, so it always ends as `NothingToFill`, whose `what` and `next` name the header. Placeholders in the URL are refused before that check.

## Checks and provenance

Run `pnpm check` at the root. Property tests use `@effect/vitest` 4.0.5's native Effect Arbitrary implementation, not fast-check. The suite includes a canary across all 18 domain error constructors, metadata serialization, real fill/redaction failures, and a scoped plaintext-unwrap test. [The planted query bug failed the property](test/red-proof.md).

The TypeScript strictness and lint fence come from rat-stack. The base diagnostic severity map is unchanged. Each package's own tsconfig permits exactly `@effect/vitest#it`, the unstable test API this brief requires. Root typecheck checks root configuration and both packages with their own configs. Tool copies live under `tools/` to keep this packet inside its allowed package scope. The patterns plugin's source-regex-policy import points at its local copied module. The app-specific Foldkit overrides do not apply here. Anti-slop's upstream notices and licenses remain beside the vendored source.

Dependencies use the brief's runtime pins and rat-stack's installed lint/test tool pins. `pnpm-lock.yaml` is generated by pnpm, without manual edits. There is no remote and nothing is pushed.
