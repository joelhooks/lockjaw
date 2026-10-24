import { chmod, readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

import { expect, it } from "@effect/vitest";
import { Effect, Schema } from "effect";

import { canary, grants, name, target } from "../../worker/test/fixtures.js";
import { loadSigner } from "../src/identity.js";
import { parseOptions, workerUrl } from "../src/options.js";
import {
  audience,
  decodeClaims,
  identity,
  loopbackFetch,
  runProcess,
  serve,
  startWorker,
  temporary,
} from "./harness.js";
import { forwardProcess, ttyProcess } from "./process.js";

const scan = (privateScalar: string, output: string) => {
  for (const secret of [
    Buffer.from(canary),
    Buffer.from(privateScalar),
    Buffer.from(privateScalar, "base64url"),
  ]) {
    for (let offset = 0; offset <= secret.length - 8; offset += 1) {
      expect(
        Buffer.from(output).includes(secret.subarray(offset, offset + 8))
      ).toBe(false);
    }
  }
};

const setup = Effect.gen(function* setup() {
  const approver = yield* identity("did:web:caller.invalid");
  const other = yield* identity("did:web:other.invalid");

  const worker = yield* startWorker(
    JSON.stringify([approver.document, other.document]),
    approver.document.id
  );

  const url = yield* serve(worker.dispatch);

  const env = {
    ...process.env,
    SC_AUDIENCE: audience,
    SC_IDENTITY_JSON: approver.json,
    SC_URL: url,
  };

  const run = (args: string[], input = "", override: NodeJS.ProcessEnv = env) =>
    Effect.promise(async () => {
      const result = await runProcess(args, input, override);
      scan(approver.d, `${result.stdout}${result.stderr}${result.argv}`);

      return result;
    });

  return { ...worker, approver, env, other, run, url };
});

const approve = [
  "approve",
  name,
  "--host",
  "api.example.com",
  "--caller",
  "test/*",
  "--placement",
  "test-host",
  "--inject",
  "authorization: Bearer {value}",
];

const fetchArgs = [
  "fetch",
  target.url,
  "-H",
  `authorization: Bearer {{secret:${name}}}`,
];

it.live(
  "spawned sc set, approve, fetch, metadata, replay red proof and revoke use the real Worker",
  () =>
    Effect.gen(function* test() {
      const f = yield* setup;

      const saved = yield* f.run(
        [
          "set",
          name,
          "--kind",
          "key",
          "--host",
          "api.example.com",
          "--caller",
          "test/*",
        ],
        canary
      );

      expect(saved.code).toBe(0);
      expect(saved.stderr).toContain("Next: sc approve");
      expect(f.claims.at(-1)?.lxm).toBe("sh.secretcell.set");
      const deniedBeforeApproval = yield* f.run(fetchArgs);
      expect(deniedBeforeApproval.code).toBe(1);
      expect(f.fixture.resolves()).toBe(0);

      const nonApprover = yield* f.run(approve, "", {
        ...f.env,
        SC_IDENTITY_JSON: f.other.json,
      });

      expect(nonApprover.code).toBe(1);
      expect(nonApprover.stderr).toContain('"rule":"approver"');
      expect((yield* f.run(approve)).code).toBe(0);
      const first = yield* f.run(fetchArgs);
      expect(first.code).toBe(0);
      expect(first.stderr).toContain("HTTP 200");
      expect(first.stdout === "\0".repeat(canary.length)).toBe(true);
      const second = yield* f.run([...fetchArgs, "--json"]);
      expect(second.code).toBe(0);
      expect(second.stdout).toContain('"status":200');

      const fetchClaims = f.claims.filter(
        (claims) => claims.lxm === "sh.secretcell.fetch"
      );

      expect(new Set(fetchClaims.map((claims) => claims.jti)).size).toBe(
        fetchClaims.length
      );
      expect(
        f.fixture.received[0]?.headers.find(
          (header) => header.name === "authorization"
        )?.value === `Bearer ${canary}`
      ).toBe(true);
      expect((yield* f.run(["list"])).stdout).toContain(name);
      const description = yield* f.run(["describe", name]);
      expect(description.code).toBe(0);
      expect(description.stdout).toContain('"version":1');
      expect(description.stdout).not.toContain("ciphertext");
      const missing = yield* f.run(["describe", "missing"]);
      expect(missing.code).toBe(1);
      expect(missing.stderr).toContain('"next":"sc list"');

      const replay = yield* Effect.promise(
        async () =>
          await f.dispatch(
            new Request(`${f.url}/v1/fetch`, {
              body: JSON.stringify(target),
              headers: {
                "x-sc-auth":
                  f.tokens.find(
                    (token) =>
                      decodeClaims(token).jti === fetchClaims.at(-1)?.jti
                  ) ?? "",
              },
              method: "POST",
            })
          )
      );

      expect(replay.status).toBe(401);
      expect(yield* Effect.promise(async () => await replay.text())).toContain(
        '"rule":"replay"'
      );

      const deniedRevoke = yield* f.run(["revoke", name], "", {
        ...f.env,
        SC_IDENTITY_JSON: f.other.json,
      });

      expect(deniedRevoke.code).toBe(1);
      expect((yield* f.run(["revoke", name])).code).toBe(0);
      expect((yield* f.run(["revoke", name])).code).toBe(0);
      const resolves = f.fixture.resolves();
      const refused = yield* f.run(fetchArgs);
      expect(refused.code).toBe(1);
      expect(refused.stderr).toContain('"what":');
      expect(refused.stderr).toContain('"why":');
      expect(refused.stderr).toContain('"next":');
      expect(f.fixture.resolves()).toBe(resolves);

      const rows = [
        ...(f.fixture.contexts
          .get("registry")
          ?.storage.sql.exec("SELECT json FROM attempts") ?? []),
      ];

      expect(rows.length).toBe(f.tokens.length);
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);

it.live(
  "forward serves three requests using three fresh single-use tokens",
  () =>
    Effect.gen(function* test() {
      const f = yield* setup;
      expect((yield* f.run(["set", name, "--kind", "key"], canary)).code).toBe(
        0
      );
      expect((yield* f.run(approve)).code).toBe(0);
      const forward = yield* forwardProcess(f.env);
      const start = f.claims.length;

      for (let count = 0; count < 3; count += 1) {
        const response = yield* Effect.promise(
          async () =>
            await loopbackFetch(`${forward.url}/resource?sequence=${count}`, {
              headers: {
                authorization: `Bearer {{secret:${name}}}`,
                "x-sc-auth": "must-be-replaced",
              },
            })
        );

        expect(response.status).toBe(200);
        const text = yield* Effect.promise(async () => await response.text());
        scan(f.approver.d, text);
      }

      scan(f.approver.d, `${forward.text()}${forward.argv}`);
      const claims = f.claims.slice(start);
      expect(claims).toHaveLength(3);
      expect(new Set(claims.map((claim) => claim.jti)).size).toBe(3);
      expect(claims.every((claim) => claim.lxm === "sh.secretcell.fetch")).toBe(
        true
      );
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);

it.live(
  "refuses unsafe URLs, binds, identity files, TTY set, and duplicate inject",
  () =>
    Effect.gen(function* test() {
      const f = yield* setup;
      const dir = yield* temporary;
      const file = path.join(dir, "identity.json");
      yield* Effect.promise(async () => {
        await writeFile(file, f.approver.json, { mode: 0o644 });
      });

      const noEnv: NodeJS.ProcessEnv = {
        ...f.env,
        SC_IDENTITY_JSON: undefined,
      };

      const refusal = yield* f.run(
        ["--identity-file", file, "list"],
        "",
        noEnv
      );

      expect(refusal.code).toBe(2);
      expect(refusal.stderr.split("\n").filter(Boolean)).toHaveLength(3);
      yield* Effect.promise(async () => {
        await chmod(file, 0o600);
      });
      expect(
        (yield* f.run(["--identity-file", file, "list"], "", noEnv)).code
      ).toBe(0);
      expect((yield* f.run(["--url", "http://example.com", "list"])).code).toBe(
        2
      );
      expect(
        (yield* f.run([
          "forward",
          "--listen",
          "0.0.0.0:8080",
          "--upstream-host",
          "api.example.com",
        ])).code
      ).toBe(2);
      expect(
        (yield* f.run([...approve, "--inject", "x-other: {value}"])).code
      ).toBe(2);

      const tty = yield* Effect.promise(
        async () => await ttyProcess(["set", name, "--kind", "key"], f.env)
      );

      scan(f.approver.d, tty);
      expect(tty).toContain("pipe the value in");
      const badMetadata = path.join(dir, "metadata.json");
      yield* Effect.promise(async () => {
        await writeFile(badMetadata, "-----BEGIN PRIVATE KEY-----", {
          mode: 0o644,
        });
      });
      expect(
        (yield* f.run(
          [
            "set",
            name,
            "--kind",
            "github-app",
            "--github-app-file",
            badMetadata,
          ],
          canary
        )).code
      ).toBe(2);

      for (const url of [
        `http://${[100, 64, 0, 1].join(".")}`,
        `http://${[100, 127, 255, 254].join(".")}`,
        "http://127.1.2.3",
        "http://[::1]",
      ]) {
        expect(workerUrl(url)).toBe(new URL(url).origin);
      }

      for (const url of [
        "http://100.63.255.255",
        "http://100.128.0.1",
        "http://localhost.example",
        `http://${[100, 64, 0, 1].join(".")}.example`,
        "http://192.0.2.1",
        "https://user:pass@example.com",
      ]) {
        expect(() => workerUrl(url)).toThrow();
      }

      expect(() =>
        parseOptions(["fetch", target.url, "--identity-stdin"])
      ).toThrow();
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);

const GeneratedIdentity = Schema.Struct({
  did: Schema.String,
  kid: Schema.String,
  signing: Schema.Struct({ d: Schema.String }),
});

it.live(
  "spawned keygen produces a public-only did:key document and stdin approvals batch with fresh tokens",
  () =>
    Effect.gen(function* test() {
      const dir = yield* temporary;
      const file = path.join(dir, "approver.did.json");

      const generated = yield* Effect.promise(
        async () =>
          await runProcess(["keygen", "--public-out", file], "", process.env)
      );

      expect(generated.code).toBe(0);

      const parsed = yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(GeneratedIdentity)
      )(generated.stdout);

      expect(parsed.did.startsWith("did:key:zDna")).toBe(true);

      const documentText = yield* Effect.promise(
        async () => await readFile(file, "utf-8")
      );

      scan(parsed.signing.d, `${documentText}${generated.stderr}`);
      expect(
        (yield* Effect.promise(async () => await stat(file))).mode % 0o1000
      ).toBe(0o644);

      const document = yield* Schema.decodeUnknownEffect(
        Schema.fromJsonString(Schema.Json)
      )(documentText);

      const worker = yield* startWorker(JSON.stringify([document]), parsed.did);
      worker.env.SETTERS = JSON.stringify([parsed.did]);
      const url = yield* serve(worker.dispatch);

      const env: NodeJS.ProcessEnv = {
        ...process.env,
        SC_AUDIENCE: audience,
        SC_IDENTITY_JSON: undefined,
        SC_URL: url,
      };

      const set = yield* Effect.promise(
        async () =>
          await runProcess(["set", name, "--kind", "key"], canary, {
            ...env,
            SC_IDENTITY_JSON: generated.stdout,
          })
      );

      expect(set.code).toBe(0);
      scan(parsed.signing.d, `${set.stdout}${set.stderr}${set.argv}`);
      const start = worker.claims.length;
      const batch = path.join(dir, "batch.json");
      yield* Effect.promise(async () => {
        await writeFile(
          batch,
          JSON.stringify([
            {
              name,
              ...grants,
              callers: ["approver"],
              placements: ["approver"],
            },
            {
              name,
              ...grants,
              callers: ["approver"],
              placements: ["approver"],
              ports: [8443],
            },
          ])
        );
      });

      const approved = yield* Effect.promise(
        async () =>
          await runProcess(
            ["approve", "--batch", batch, "--identity-stdin"],
            generated.stdout,
            env
          )
      );

      expect(approved.code).toBe(0);
      scan(
        parsed.signing.d,
        `${approved.stdout}${approved.stderr}${approved.argv}`
      );
      expect(
        new Set(worker.claims.slice(start).map((claims) => claims.jti)).size
      ).toBe(2);

      const fetched = yield* Effect.promise(
        async () =>
          await runProcess(fetchArgs, "", {
            ...env,
            SC_IDENTITY_JSON: generated.stdout,
          })
      );

      expect(fetched.code).toBe(0);
      scan(
        parsed.signing.d,
        `${fetched.stdout}${fetched.stderr}${fetched.argv}`
      );

      const again = yield* Effect.promise(
        async () => await runProcess(["keygen", "--public-out", file], "", env)
      );

      expect(again.code).toBe(2);
      expect(again.stdout).toBe("");

      const tty = yield* Effect.promise(
        async () =>
          await ttyProcess(
            ["keygen", "--public-out", path.join(dir, "tty.json")],
            env
          )
      );

      expect(tty).toContain("pipe it into op document create -");
      expect(tty).not.toContain('"signing":');

      const conflict = yield* Effect.promise(
        async () =>
          await runProcess([...approve, "--identity-stdin"], generated.stdout, {
            ...env,
            SC_IDENTITY_JSON: generated.stdout,
          })
      );

      expect(conflict.code).toBe(2);
      scan(parsed.signing.d, `${conflict.stdout}${conflict.stderr}`);
    }).pipe(Effect.scoped),
  { timeout: 30_000 }
);

it.live(
  "signer tokens have 16-byte random jti, sid, bounded lifetime and ES256 header",
  () =>
    Effect.gen(function* test() {
      const actor = yield* identity("did:web:caller.invalid");
      const sign = yield* loadSigner(undefined, actor.json, audience);
      const a = yield* sign("fetch");
      const b = yield* sign("fetch");
      const first = decodeClaims(a);
      expect(first.jti).not.toBe(decodeClaims(b).jti);
      expect(Buffer.from(first.jti, "base64url")).toHaveLength(16);
      expect(first.exp - first.iat).toBe(60);
      expect(first.sid.length).toBeGreaterThan(0);
      expect(
        Buffer.from(a.split(".")[0] ?? "", "base64url").toString()
      ).toContain('"alg":"ES256"');
    })
);
