# Single-flight red proof

Run: 2026-10-18, local Node 24.18.0. No celld and no real credentials.

## Mutation

In `Credential.refreshDue`, replace the existing no-op for a credential already in `refreshing`:

```ts
if (state === "refreshing") {
  return yield * Effect.void;
}
```

with a second, scoped refresh:

```ts
if (state === "refreshing") {
  yield * refresh().pipe(Effect.forkScoped);
  return yield * Effect.void;
}
```

Command:

```sh
pnpm exec vitest run --config packages/gateway-rules/vitest.config.ts packages/cell/test/credential.model.test.ts --testTimeout 4000
```

Observed red result, exit 1:

```text
Property falsified after 1 run(s) and 1 shrink(s)
Shrunk input: {
  "concurrency": 2,
  "events": []
}
Failure: AssertionError: expected 2 to be 1 // Object.is equality
expect(yield* Ref.get(maximum)).toBe(1);
Replay: [0,"-8145866298846011",0,0,[0],"PropertyError"]
Tests 1 failed (1)
Duration 318ms
```

The empty random tail still executes the model's mandatory SET/REFRESH prefix. Concurrent requests start a second provider call, so maximum in-flight refreshes reaches 2 instead of 1. This is an invariant failure, not a timeout.

## Restored

Restored the original branch before further checks. The complete cell suite then passed: 12 tests across 6 files, including 75 generated model traces and 30 generated rotation races, in 1.25 seconds. The required post-commit heavy gate verifies the final candidate again; its receipt is supplied in the packet report.
