import { writeFile } from "node:fs/promises";
import path from "node:path";

import { expect, it } from "@effect/vitest";
import { encodeDidKeyP256 } from "@lockjaw/domain";
import { Clock, DateTime, Effect, Schema } from "effect";

import { canary, name, target } from "../../worker/test/fixtures.js";
import { parseOptions } from "../src/options.js";
import {
  audience,
  identity,
  runProcess,
  serve,
  startWorker,
  temporary,
} from "./harness.js";

const iso = (offset: number) =>
  Clock.currentTimeMillis.pipe(
    Effect.map((now) => DateTime.formatIso(DateTime.makeUnsafe(now + offset)))
  );

const fetchArgs = [
  "fetch",
  target.url,
  "-H",
  `authorization: Bearer {{secret:${name}}}`,
];

it.live(
  "sc grant, grants, delegated set, run-ticket, --run-ticket fetch, grant revoke and rotate drive the real Worker",
  () =>
    Effect.gen(function* delegated() {
      const approver = yield* identity("did:web:caller.invalid", "approver");
      const desk = yield* identity("did:web:desk.invalid", "test/desk");
      const worker = yield* identity("did:web:desk.invalid", "test/desk");

      const started = yield* startWorker(
        JSON.stringify([approver.document, desk.document]),
        approver.document.id
      );

      const url = yield* serve(started.dispatch);
      const dir = yield* temporary;
      const base = { ...process.env, SC_AUDIENCE: audience, SC_URL: url };
      const outputs: string[] = [];

      const run = (args: string[], input: string, json?: string) =>
        Effect.promise(async () => {
          const environment: NodeJS.ProcessEnv = { ...base };

          if (json !== undefined) {
            environment.SC_IDENTITY_JSON = json;
          }

          const result = await runProcess(args, input, environment);
          outputs.push(result.stdout, result.stderr);

          return result;
        });

      const root = yield* run(
        [
          "grant",
          "test/desk",
          "--credential",
          "canary/*",
          "--host",
          "api.example.com",
          "--op",
          "use",
          "--op",
          "set",
          "--op",
          "grant",
          "--grantee",
          "test/*",
          "--exp",
          yield* iso(3_600_000),
          "--identity-stdin",
        ],
        approver.json
      );

      expect(root.code).toBe(0);
      expect(started.claims.at(-1)?.lxm).toBe("sh.secretcell.grant");

      const saved = yield* run(
        [
          "set",
          name,
          "--kind",
          "key",
          "--host",
          "api.example.com",
          "--placement",
          "test-host",
          "--inject",
          "authorization: Bearer {value}",
        ],
        canary,
        desk.json
      );

      expect(saved.code).toBe(0);

      const runGrant = yield* run(
        [
          "grant",
          "test/desk",
          "--run",
          "run-1",
          "--credential",
          name,
          "--host",
          "api.example.com",
          "--op",
          "use",
          "--exp",
          yield* iso(2_700_000),
        ],
        "",
        desk.json
      );

      expect(runGrant.code).toBe(0);

      const runId = (yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(
          Schema.Struct({ grant: Schema.Struct({ id: Schema.String }) })
        )
      )(runGrant.stdout)).grant.id;

      const listed = yield* run(["grants"], "", desk.json);
      expect(listed.code).toBe(0);
      expect(listed.stdout).toContain(runId);

      const publicKey = path.join(dir, "worker.jwk.json");
      const privateKey = path.join(dir, "worker-private.jwk.json");
      const passFile = path.join(dir, "pass.txt");

      yield* Effect.promise(async () => {
        await writeFile(
          publicKey,
          JSON.stringify({
            crv: worker.publicJwk.crv,
            kty: worker.publicJwk.kty,
            x: worker.publicJwk.x,
            y: worker.publicJwk.y,
          }),
          { mode: 0o644 }
        );
        await writeFile(privateKey, JSON.stringify(worker.signing), {
          mode: 0o600,
        });
      });

      const passArgs = [
        "pass",
        "--desk",
        "test/desk",
        "--handle",
        "run-1",
        "--scope",
        "sh.secretcell.fetch:canary/*",
      ];

      const refusedPrivate = yield* run(
        [...passArgs, "--worker-key", privateKey],
        "",
        desk.json
      );

      expect(refusedPrivate.code).toBe(2);
      expect(refusedPrivate.stderr).toContain(
        "a private key component was supplied"
      );
      expect(refusedPrivate.stderr).toContain(
        "Next: Export only {kty, crv, x, y}"
      );

      const refusedDid = yield* run(
        [
          ...passArgs,
          "--worker-key",
          (
            encodeDidKeyP256({
              crv: "P-256",
              kty: "EC",
              x: worker.publicJwk.x ?? "",
              y: worker.publicJwk.y ?? "",
            }) ?? ""
          ).replace("did:key:zDn", "did:key:zDm"),
        ],
        "",
        desk.json
      );

      expect(refusedDid.code).toBe(2);
      expect(refusedDid.stderr).toContain("not a valid P-256 did:key");

      const pass = yield* run(
        [...passArgs, "--worker-key", publicKey],
        "",
        desk.json
      );

      expect(pass.code).toBe(0);

      yield* Effect.promise(async () => {
        await writeFile(passFile, pass.stdout, { mode: 0o600 });
      });

      const used = yield* run(
        ["--pass", passFile, ...fetchArgs],
        "",
        worker.json
      );

      expect(used.stderr).toContain("HTTP 200");
      expect(started.claims.at(-1)?.sid).toBe("run-1");

      const withoutTicket = yield* run(fetchArgs, "", worker.json);
      expect(withoutTicket.code).toBe(1);

      const revoked = yield* run(["grant", "revoke", runId], "", desk.json);
      expect(revoked.code).toBe(0);

      const afterRevoke = yield* run(
        ["--run-ticket", passFile, ...fetchArgs],
        "",
        worker.json
      );

      expect(afterRevoke.stderr).toContain("Deprecated");
      expect(afterRevoke.code).toBe(1);
      expect(afterRevoke.stderr).toContain('"rule":"grant"');

      const rotated = yield* run(
        ["rotate", name],
        `${canary}-next`,
        approver.json
      );

      expect(rotated.code).toBe(0);
      expect(rotated.stdout).toContain('"version":2');

      for (const output of outputs) {
        expect(output).not.toContain(canary);
      }
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);

it("parses grant revoke, rotate and run-ticket, and keeps identity-stdin to approve and grant", () => {
  expect(parseOptions(["grant", "revoke", "g_1"]).command).toBe("grant-revoke");
  expect(parseOptions(["grant", "revoke", "g_1"]).operand).toBe("g_1");
  expect(parseOptions(["rotate", "a/b"]).command).toBe("rotate");
  expect(() => parseOptions(["grants", "extra"])).toThrow();
  expect(() => parseOptions(["rotate", "a/b", "--identity-stdin"])).toThrow();
  expect(
    parseOptions(["run-ticket", "--handle", "run-1", "--worker-key", "k.json"])
      .command
  ).toBe("run-ticket");
});
