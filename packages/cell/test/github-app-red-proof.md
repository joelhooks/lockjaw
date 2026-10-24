# GitHub App single-flight red proof

Date: 2026-10-18. Base: `036a8d5`, above Phase 1c `8b952c8`.

## Intentional mutation

Temporarily changed the GitHub App resolve path from:

```ts
Cache.get(installationTokens, op.subkey);
```

to invalidating the cache immediately before every lookup:

```ts
Cache.invalidateAll(installationTokens).pipe(
  Effect.andThen(Cache.get(installationTokens, op.subkey))
);
```

This removes sharing across the twenty concurrently admitted gateway calls. Each call carries its own single-use caller token. All calls hit a real Node HTTPS fake through the injected Upstream; no GitHub network access or real App key is involved.

Command:

```sh
pnpm exec vitest run --config packages/gateway-rules/vitest.config.ts \
  packages/worker/test/github-app.test.ts -t '20 concurrent'
```

Observed exit: **1**. The intended assertion failed with `expected 20 to be 1`: twenty HTTPS mint requests instead of one. One test failed and five were skipped. The assertion prints only counts, never the PEM, JWT or installation token.

## Restored green

Restored the original `Cache.get` path. The same concurrent test passes. Its first twenty calls mint once; advancing the injected clock to five minutes before expiry causes precisely one more mint for the next twenty calls. A second approved owner has a separate cache entry.

The full added test set then passed: **11 tests across 3 files**. It also covers API and git Basic echo redaction, every eight-byte PEM/token/encoded-Basic window on caller and persistence surfaces, captured logs, 401/403 lifecycle transitions, one 5xx retry, PKCS#1 refusal, malformed PEM, approval-only map changes, key non-extractability, cache clearing on rotation/revoke, and fresh activation re-minting. The final repository-wide check is reported in the packet receipt, not inferred from this focused run.
