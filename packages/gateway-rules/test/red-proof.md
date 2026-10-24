# Placement red proof

2026-10-18. No real credentials were used.

Deliberate mutation in `Placement.check`:

```diff
- yield* refuseOutside(request.url);
+ yield* refuseOutside(request.url.split("?")[0] ?? request.url);
```

This ignored query placeholders while retaining the rest of the placement checks.

Command: `pnpm test -- -t 'refuses every outside placeholder before resolution'`. The script's extra `--` caused Vitest to run the whole suite. Exit status: **1**. The property and two related regression tests failed.

```text
Property falsified after 1 run(s) and 2 shrink(s)
Shrunk input: {
  "encoding": 0,
  "location": "query",
  "name": "-"
}
Failure: AssertionError: expected 'Success' to be 'Failure'
Replay: [0,"5647487706685963",0,0,[0,0],"PropertyError"]
```

The mutation was removed immediately. The committed placement scans the full URL. The green proof is the post-restoration `pnpm test` and committed heavy gate receipt in the packet report.

To run only this property: `pnpm exec vitest run --config packages/gateway-rules/vitest.config.ts -t 'refuses every outside placeholder before resolution'`.

# Red proof: delegated scopes must not widen hosts (packet 1f)

Ran 2026-10-19 under Node.

Mutation in `src/delegation.ts`: `widened` returns `undefined` instead of `"hosts"` when a child host is not covered by the parent, so `isSubScope` ignores hosts.

```sh
pnpm exec vitest run --config vitest.config.ts packages/gateway-rules/test/delegation.test.ts packages/worker/test/delegation.test.ts
```

Observed: **6 failed, 25 passed**.

- Table row "extra host".
- Property "any single widening is refused and named" (the hosts case).
- Property "isSubScope is transitive" (a constructed narrowing no longer implies the subset).
- "a widened stored link is not effective".
- "admission refuses … widening, naming the field".
- Worker end to end: a desk's grant to its run with `evil.example.net` was accepted.

Restored the hosts check. The committed tree contains only the restored implementation.
