# Red proof: caller authentication must not reach upstream

Ran 2026-10-18 under Node, with the fake signer, fake DO namespaces and fake upstream.

Command:

```sh
pnpm exec vitest run --config packages/gateway-rules/vitest.config.ts packages/worker/test/gateway.test.ts
```

Mutation in `src/gateway.ts`: permit `x-sc-auth` through the outgoing header filter while continuing to strip other `x-sc-*` headers.

Observed exit 1: **2 failed, 2 passed**, 504 ms total.

- The canary end-to-end test failed because the upstream received an extra `x-sc-auth` header in addition to the declared Authorization fill.
- The base-URL swap test failed its assertion that no `x-sc-*` header reached upstream.

Restored the filter that removes every `x-sc-*` header. The committed tree contains only the restored implementation. The final heavy gate runs `pnpm check`, including both regression tests, after the commit.

# Red proof: base URL swap must not forward edge or transport headers

Ran 2026-10-19 under Node, with the same fakes as above.

Command, once per mutation, with the source restored after each run:

```sh
pnpm exec vitest run --config vitest.config.ts packages/worker/test/forwarding.test.ts
```

| Mutation in `src/gateway.ts` | Failed (of 6) | Failing test |
| --- | --- | --- |
| None | 0 |  |
| Drop the hop-by-hop set | 1 | hop-by-hop |
| Drop names listed in `Connection` | 1 | hop-by-hop |
| Drop the edge-only set | 2 | client address and host; cookie |
| Drop only `cookie` | 1 | cookie |
| Drop the `cf-` prefix | 2 | Cloudflare edge; Cloudflare Access |
| Drop the `x-forwarded-` prefix | 1 | client address and host |

The committed tree contains only the unmutated implementation.

# Red proof: a worker pass binds the request key (packet 1f)

Ran 2026-10-19 under Node, with the fakes in `test/fixtures.ts`.

Mutation in `src/caller-auth.ts` (`authenticatePass`): skip verifying the request token against the pass's `worker` did:key.

```sh
pnpm exec vitest run --config vitest.config.ts packages/worker/test/delegation.test.ts
```

Observed: **2 failed, 6 passed**.

- "a stolen worker pass presented with the thief's own key is refused before resolve": expected 401, got 302, and the credential resolved.
- The pass refusal table, at its "wrong signing key" row.

A second mutation, in `src/replay-do.ts` (`bind`), accepted any existing nonce binding. "pass nonces bind on first use to worker key and run" failed (1 failed, 7 passed).

Both mutations were restored. The committed tree contains only the restored implementation.
