# Desk-pass packet 2 proof

## Source and package

The build reads `packages/lexicon` with `git archive 6c1e5d8`. It does not modify the source checkout. The full commit is recorded in `vendor/rat-king-lexicon.lock.json`.

Rat King `6c1e5d8` carries the explicit `Uint8Array` return annotations on `signingBytes` and `fingerprintBytes`, so the build no longer patches any source. Both JavaScript and declaration imports use `.js`. No verifier behavior is patched.

Two consecutive builds produced SHA-256 `b29a645ac31452c36b0c4303ee6a414cb076244f8b6c4793903daeb3d3c44c5a`. The three pinned dependencies are `@ipld/dag-cbor` 10.0.2, `@atproto/lex-data` 0.1.8 and `@atproto/lexicon` 0.7.16.

The unpacked tarball passed `pnpm fence --root <temporary-extraction>`: 166 blobs, private-instance and generic rules. The temporary root contained the actual package files and the canonical gitleaks config. The repository tree also passed the private-instance fence.

## Verification coverage

- Existing delegation tests use signed DAG-CBOR pass envelopes and the shared verifier. Fixture convenience scopes are narrowed to the desk's credential namespace. The wider-than-run-grant intersection test retains its meaning.
- A revoked desk grant now refuses at authentication with 401, rather than reaching the run-grant 403 check. Expired-pass wording comes from the shared verifier's lifetime clause.
- Vendored plants refuse a desk key used as worker, widened scope, nonce reuse on another run, an expired ticket, a forged signature and altered request bytes.
- Cell-level tests cover an empty desk ceiling, wider-than-desk scope, authenticated key rotation and reuse of another authenticated desk key as worker.
- Replay reconstruction preserves binding identity, cannot shorten retention, accepts the closed `exp + 60` boundary.
- Ticket tests cover fleet-wide fetch/describe, exact-name and prefix-policy refusal, refusal despite a stored grant, management refusal, forged/expired/unpinned tickets, known-desk key mismatch and missing/invalid/public-key-only issuer bindings. Ticket headers are stripped before upstream.
- Superseded by the sc pass file packet: `sc` no longer renews over `RK_PASS_SOCKET`. `packages/client/test/renewal-wire.test.ts` pins the renewal wire the worker runtime mirrors, and `packages/client/test/pass-file.test.ts` covers `SC_PASS_FILE`.

## Red proof

Temporarily replaced the production `NonceBinding` adapter with one that always returns `new`. Ran:

```sh
pnpm exec vitest run packages/worker/test/pass-swap.test.ts -t 'Replay NonceBinding refuses'
```

It exited 1: the other-run presentation was accepted, so `expect(Result.isFailure(result)).toBe(true)` failed. Restored the real adapter and reran the same command: one passed, three skipped. The unsafe adapter is not committed.

## Nonce tombstone pruning

The Replay DO alarm now also deletes `pass_nonces` rows whose retention (`exp + 60`, stored in ms) is in the past, at most 500 per alarm, and re-arms while rows remain. One alarm serves both tables, set to the earliest moment either has rows to drop. Tests: a retained binding survives the alarm, an expired one goes, 501 expired rows take two alarms, and an expired pass is still refused after its nonce is pruned.

Red proof for the last test. With the pass lifetime check (`now > exp + 60` in the verifier) disabled, the pruned stale pass is **still refused** with "nonce is already bound", because `bind` refuses any `expires < now` even when no row exists. With `bind`'s `expires < now` guard disabled as well, the same test fails: the stale pass is accepted. So the tombstone is not the guard. Expiry is, first at the pass check and second at `bind`. Both temporary edits were reverted and are not committed.

## Patched compiler compatibility

The patched compiler initially rejected three existing `effect/http` unstable-API warnings when the deployment project imported `worker/src/upstream.ts`. The worker tsconfig already allows these pinned HTTP APIs, but the importing deployment config does not inherit that list. A source-local `unstableApiUsage:off` directive preserves that existing allowance without changing runtime behavior or deployment configuration.

## Delivery boundary

Deploy level 0. No live bindings, production state, push or deployment changed. The launcher socket server and `RunBinding` remain packet 3. Deployment needs the operator's three public `TICKET_ISSUERS` pins and separate approval.
