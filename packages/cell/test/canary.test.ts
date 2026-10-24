import { existsSync, readFileSync } from "node:fs";

import { expect, it } from "@effect/vitest";
import { Effect, Redacted, Result } from "effect";

import { CredentialStore } from "../src/credential-store.js";
import { Credential } from "../src/credential.js";
import { NodeSqlite } from "../src/node-sqlite.js";
import { caller, canary, credentialLayer, metadata, op } from "./fixtures.js";

const assertNoWindow = (bytes: Uint8Array) => {
  const source = new TextEncoder().encode(canary);

  for (let start = 0; start <= source.length - 8; start += 1) {
    expect(
      Buffer.from(bytes).includes(Buffer.from(source.slice(start, start + 8)))
    ).toBe(false);
  }
};

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- Acceptance probe intentionally serializes arbitrary public outputs and errors without extracting their values.
const inspect = (output: unknown) => {
  assertNoWindow(new TextEncoder().encode(JSON.stringify(output)));

  if (Result.isResult(output) && Result.isFailure(output)) {
    assertNoWindow(new TextEncoder().encode(String(output.failure)));
  }
};

it.effect(
  "canary: every operation, log, error, metadata output and raw SQLite/WAL/SHM stays sealed",
  () =>
    Effect.gen(function* atRestTest() {
      const credential = yield* Credential;
      const store = yield* CredentialStore;
      const sqlite = yield* NodeSqlite;

      const capture = Effect.fn("Canary.capture")(function* captureTest() {
        inspect(yield* credential.describe());
        inspect(yield* store.uses());
        inspect(yield* store.value());
        inspect(yield* store.value("previous"));
        inspect(yield* store.value("refresh"));

        for (const suffix of ["", "-wal", "-shm"]) {
          const file = sqlite.path + suffix;

          if (existsSync(file)) {
            assertNoWindow(readFileSync(file));
          }
        }
      });

      inspect(yield* credential.resolve(caller, op).pipe(Effect.result));
      yield* credential.set(Redacted.make(canary), {
        ...metadata,
        refreshToken: Redacted.make(canary),
      });
      inspect(yield* credential.resolve(caller, op));
      inspect(
        yield* credential
          .resolve({ ...caller, name: "denied" }, op)
          .pipe(Effect.result)
      );
      yield* capture();
      yield* credential.rotateBegin(Redacted.make(`new-${canary}`));
      inspect(yield* credential.resolve(caller, op));
      yield* capture();
      yield* credential.rotateAbort();
      yield* credential.rotateBegin(Redacted.make(`new-${canary}`));
      yield* credential.rotateCommit();
      yield* capture();
      yield* credential.refreshDue();
      inspect(yield* credential.resolve(caller, op));
      yield* credential.set(Redacted.make(canary), {
        ...metadata,
        expiresAt: -1,
      });
      yield* credential.expire();
      inspect(yield* credential.resolve(caller, op).pipe(Effect.result));
      yield* capture();
      yield* credential.set(Redacted.make(canary), metadata);
      yield* credential.revoke();
      inspect(yield* credential.resolve(caller, op).pipe(Effect.result));
      inspect(
        yield* credential
          .set(Redacted.make(canary), metadata)
          .pipe(Effect.result)
      );
      inspect(
        yield* credential.rotateBegin(Redacted.make(canary)).pipe(Effect.result)
      );
      yield* capture();
      sqlite.close();

      for (const suffix of ["", "-wal", "-shm"]) {
        const file = sqlite.path + suffix;

        if (existsSync(file)) {
          assertNoWindow(readFileSync(file));
        }
      }
    }).pipe(Effect.provide(credentialLayer()))
);
