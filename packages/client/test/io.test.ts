import { writeFile } from "node:fs/promises";
import path from "node:path";

import { expect, it } from "@effect/vitest";
import { Effect } from "effect";

import { canary, name, target } from "../../worker/test/fixtures.js";
import {
  audience,
  identity,
  runProcess,
  serve,
  startWorker,
  temporary,
} from "./harness.js";

it.live(
  "request data accepts stdin or a file, expiry is milliseconds and transport failures are three-part",
  () =>
    Effect.gen(function* test() {
      const actor = yield* identity("did:web:caller.invalid");

      const worker = yield* startWorker(
        JSON.stringify([actor.document]),
        actor.document.id
      );

      const url = yield* serve(worker.dispatch);

      const env = {
        ...process.env,
        SC_AUDIENCE: audience,
        SC_IDENTITY_JSON: actor.json,
        SC_URL: url,
      };

      const run = (args: string[], input = "") =>
        Effect.promise(async () => await runProcess(args, input, env));

      const expiry = "2099-01-01T00:00:00.000Z";
      expect(
        (yield* run(
          ["set", name, "--kind", "key", "--expires-at", expiry],
          canary
        )).code
      ).toBe(0);
      const described = yield* run(["describe", name]);
      expect(described.stdout).toContain(`"expiresAt":${Date.parse(expiry)}`);
      expect(
        (yield* run([
          "approve",
          name,
          "--host",
          "api.example.com",
          "--host",
          "other.example.com",
          "--caller",
          "test/*",
          "--caller",
          "another/*",
          "--placement",
          "test-host",
          "--ports",
          "8443",
          "--ports",
          "9443",
          "--inject",
          "authorization: Bearer {value}",
          "--basic-user",
          "literal",
        ])).code
      ).toBe(0);

      const args = [
        "fetch",
        target.url,
        "-X",
        "PATCH",
        "-H",
        `authorization: Bearer {{secret:${name}}}`,
        "-H",
        "x-extra: example",
      ];

      expect((yield* run([...args, "--data", "-"], "stdin-body")).code).toBe(0);
      expect(worker.fixture.received.at(-1)?.body).toBe("stdin-body");
      expect(worker.fixture.received.at(-1)?.method).toBe("PATCH");
      const dir = yield* temporary;
      const file = path.join(dir, "body.txt");
      yield* Effect.promise(async () => {
        await writeFile(file, "file-body");
      });
      expect((yield* run([...args, "--data", `@${file}`])).code).toBe(0);
      expect(worker.fixture.received.at(-1)?.body).toBe("file-body");
      const failed = yield* run(["--url", "http://127.0.0.1:0", "list"]);
      expect(failed.code).toBe(3);
      expect(failed.stderr.split("\n").filter(Boolean)).toHaveLength(3);
      expect(failed.stdout).toBe("");
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);
