import { once } from "node:events";
import { chmod, readdir, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import path from "node:path";

import { expect, it } from "@effect/vitest";
import { encodeDidKeyP256 } from "@lockjaw/domain";
import { signingKey } from "@rat-king/lexicon/pass-webcrypto";
import { SignedPass, SignedTicket, signTicket } from "@rat-king/lexicon/passes";
import {
  PublicKey,
  Signatures,
  fingerprintBytes,
} from "@rat-king/lexicon/trust";
import { signatures } from "@rat-king/lexicon/webcrypto";
import { Clock, Effect, Schema } from "effect";

import { canary } from "../../worker/test/fixtures.js";
import { signPass } from "../src/identity.js";
import {
  audience,
  decodeClaims,
  identity,
  runProcess,
  serve,
  temporary,
} from "./harness.js";

interface PassFileBody {
  readonly pass: typeof SignedPass.Type;
  readonly renewedAt: number;
  readonly run: string;
  readonly ticket?: typeof SignedTicket.Type;
  readonly token?: string;
  readonly v: number;
  readonly workerDid: string | undefined;
}

const runTokenPrefixes = [
  "RK_RUN",
  "RK_PASS_RUN",
  "SC_RUN",
  "RATKING_RUN",
  "PI_RUN",
];

const runToken = "RK_RUN_TOKEN_CANARY_q8Zt3Wn5Xc1Vb7Mp";

const importSigner = (jwk: JsonWebKey) =>
  Effect.promise(
    async () =>
      await crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign"]
      )
  );

const refused = (
  result: Awaited<ReturnType<typeof runProcess>>,
  what: string,
  code = 2
) => {
  expect([what, result.code]).toEqual([what, code]);
  expect(result.stderr).toContain(`failed: ${what}`);
  expect(result.stderr).toContain("\nWhy: ");
  expect(result.stderr).toContain("\nNext: ");
};

const scenario = Effect.gen(function* scenario() {
  const desk = yield* identity("did:web:desk.invalid", "acme/desk");
  const worker = yield* identity("did:web:desk.invalid", "acme/desk");
  const host = yield* identity("did:web:host.invalid", "host");

  const workerKey = yield* Schema.decodeUnknownEffect(PublicKey)(
    worker.publicJwk
  );

  const deskKey = yield* Schema.decodeUnknownEffect(PublicKey)(desk.publicJwk);
  const hostKey = yield* Schema.decodeUnknownEffect(PublicKey)(host.publicJwk);
  const workerDid = encodeDidKeyP256(workerKey) ?? "";
  const issuer = signingKey(hostKey, yield* importSigner(host.signing));
  const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

  const fingerprint = yield* Signatures.use((signer) =>
    signer.digest(fingerprintBytes(deskKey))
  ).pipe(Effect.provide(signatures));

  const pass = (seconds = 300, run = "run-1") =>
    signPass(undefined, desk.json, {
      desk: "acme/desk",
      run,
      scope: ["sh.secretcell.list:acme/*"],
      seconds,
      worker: workerDid,
    }).pipe(
      Effect.flatMap(
        Schema.decodeUnknownEffect(Schema.fromJsonString(SignedPass))
      )
    );

  const ticket = (overrides: Record<string, string | number> = {}) =>
    signTicket(
      issuer,
      {
        $type: "sh.ratking.ticket",
        did: "did:web:desk.invalid",
        exp: now + 300,
        fingerprint,
        iat: now,
        issuer: "test-host",
        name: "acme/desk",
        namespace: "acme",
        ...overrides,
      },
      deskKey
    );

  return { desk, host, now, pass, ticket, worker, workerDid };
});

it.live(
  "sc reads SC_PASS_FILE, sends the pass and its ticket, refuses every mismatch three-part, and never renews, dials a socket or reads a run token",
  () =>
    Effect.gen(function* passFile() {
      const { desk, host, now, pass, ticket, worker, workerDid } =
        yield* scenario;

      const dir = yield* temporary;
      const file = path.join(dir, "pass.json");
      const direct = path.join(dir, "direct-pass.json");
      const socketPath = path.join(dir, "renew.sock");
      let connections = 0;

      const socket = createServer((client) => {
        connections += 1;
        client.destroy();
      });

      yield* Effect.acquireRelease(
        Effect.promise(async () => {
          socket.listen(socketPath);
          await once(socket, "listening");

          return socket;
        }),
        (owned) =>
          Effect.promise(async () => {
            await owned[Symbol.asyncDispose]();
          })
      );

      const received: { headers: Headers; body: string }[] = [];

      const url = yield* serve(async (request) => {
        received.push({
          body: await request.text(),
          headers: new Headers(request.headers),
        });

        return Response.json({ credentials: [] });
      });

      const env: NodeJS.ProcessEnv = {
        ...process.env,
        RK_PASS_SOCKET: socketPath,
        SC_AUDIENCE: audience,
        SC_IDENTITY_JSON: worker.json,
        SC_PASS_FILE: file,
        SC_URL: url,
        ...Object.fromEntries(
          runTokenPrefixes.map((prefix) => [`${prefix}_TOKEN`, runToken])
        ),
        RK_PASS_CLAIM: runToken,
      };

      const good = yield* pass();
      const goodTicket = yield* ticket();

      const contents = {
        pass: good,
        renewedAt: now,
        run: "run-1",
        ticket: goodTicket,
        v: 1,
        workerDid,
      };

      const outputs: string[] = [];

      const run = (
        body: PassFileBody,
        options: {
          readonly mode?: number;
          readonly args?: string[];
          readonly env?: NodeJS.ProcessEnv;
        } = {}
      ) =>
        Effect.promise(async () => {
          await writeFile(file, JSON.stringify(body));
          await chmod(file, options.mode ?? 0o600);

          const result = await runProcess(
            [...(options.args ?? []), "list"],
            "",
            { ...env, ...options.env }
          );

          outputs.push(result.stdout + result.stderr);

          return result;
        });

      const valid = yield* run(contents);

      expect(valid.code).toBe(0);
      expect(received).toHaveLength(1);

      const sent = received[0]?.headers;

      expect(
        yield* Schema.decodeUnknownEffect(Schema.fromJsonString(SignedPass))(
          sent?.get("x-sc-pass") ?? ""
        )
      ).toEqual(good);
      expect(
        yield* Schema.decodeUnknownEffect(Schema.fromJsonString(SignedTicket))(
          sent?.get("x-sc-ticket") ?? ""
        )
      ).toEqual(goodTicket);
      expect(decodeClaims(sent?.get("x-sc-auth") ?? "").sid).toBe("run-1");

      const { ticket: _ticket, ...withoutTicket } = contents;
      const passOnly = yield* run(withoutTicket);

      expect(passOnly.code).toBe(0);
      expect(received).toHaveLength(2);
      expect(received[1]?.headers.has("x-sc-ticket")).toBe(false);
      expect(received[1]?.headers.has("x-sc-pass")).toBe(true);

      const foreignUid = path.join(dir, "foreign-uid.mjs");

      yield* Effect.promise(async () => {
        await writeFile(
          foreignUid,
          "process.getuid = () => (process.geteuid?.() ?? 0) + 4242;\n"
        );
      });

      const refusals = [
        [
          "wrong mode",
          yield* run(contents, { mode: 0o644 }),
          "SC_PASS_FILE is not a private file owned by this user",
        ],
        [
          "wrong owner",
          yield* run(contents, {
            env: { NODE_OPTIONS: `--import=${foreignUid}` },
          }),
          "SC_PASS_FILE is not a private file owned by this user",
        ],
        [
          "unknown v",
          yield* run({ ...contents, v: 2 }),
          "SC_PASS_FILE has an unknown version",
        ],
        [
          "extra field",
          yield* run({ ...contents, token: runToken }),
          "SC_PASS_FILE does not match the version 1 shape",
        ],
        [
          "key mismatch",
          yield* run(contents, { env: { SC_IDENTITY_JSON: desk.json } }),
          "SC_IDENTITY_JSON does not hold this pass's worker key",
        ],
        [
          "workerDid mismatch",
          yield* run({
            ...contents,
            workerDid: encodeDidKeyP256(
              yield* Schema.decodeUnknownEffect(PublicKey)(desk.publicJwk)
            ),
          }),
          "SC_PASS_FILE workerDid does not match its pass",
        ],
        [
          "run mismatch",
          yield* run({ ...contents, run: "run-2" }),
          "SC_PASS_FILE run does not match its pass",
        ],
        [
          "ticket names another desk",
          yield* run({
            ...contents,
            ticket: yield* ticket({ name: "acme/other" }),
          }),
          "SC_PASS_FILE ticket names another desk",
        ],
        [
          "ticket names another desk DID",
          yield* run({
            ...contents,
            ticket: yield* ticket({ did: "did:web:other.invalid" }),
          }),
          "SC_PASS_FILE ticket names another desk",
        ],
        [
          "both pass sources",
          yield* run(contents, { args: ["--pass", file] }),
          "SC_PASS_FILE and --pass were both given",
        ],
      ] as const;

      for (const [label, result, what] of refusals) {
        expect(label).toBeTruthy();
        refused(result, what);
      }

      const stalePass = yield* run({ ...contents, pass: yield* pass(20) });

      refused(stalePass, "PassStale", 1);
      expect(stalePass.stderr).toContain("worker pass");
      expect(stalePass.stderr).toContain("desk queue");

      const staleTicket = yield* run({
        ...contents,
        ticket: yield* ticket({
          exp: now + 20,
        }),
      });

      refused(staleTicket, "PassStale", 1);
      expect(staleTicket.stderr).toContain("name ticket");
      expect(received).toHaveLength(2);

      const nearExpiry = yield* signPass(undefined, desk.json, {
        desk: "acme/desk",
        run: "run-1",
        scope: ["sh.secretcell.list:acme/*"],
        seconds: 60,
        worker: workerDid,
      });

      const expired = yield* signPass(undefined, desk.json, {
        desk: "acme/desk",
        run: "run-1",
        scope: ["sh.secretcell.list:acme/*"],
        seconds: -1,
        worker: workerDid,
      });

      const directRun = (text: string) =>
        Effect.promise(async () => {
          await writeFile(direct, text, { mode: 0o600 });
          await chmod(direct, 0o600);

          const result = await runProcess(["--pass", direct, "list"], "", {
            ...env,
            SC_PASS_FILE: undefined,
          });

          outputs.push(result.stdout + result.stderr);

          return result;
        });

      const directOk = yield* directRun(nearExpiry);

      expect(directOk.code).toBe(0);
      expect(received).toHaveLength(3);
      expect(received[2]?.headers.get("x-sc-pass")).toBe(nearExpiry);
      expect(received[2]?.headers.has("x-sc-ticket")).toBe(false);

      refused(yield* directRun(expired), "worker pass expired", 1);
      expect(received).toHaveLength(3);

      expect(connections).toBe(0);
      expect(
        yield* Effect.promise(async () => await readFile(file, "utf-8"))
      ).not.toContain(runToken);
      expect(
        (yield* Effect.promise(async () => await readdir(dir))).toSorted()
      ).toEqual(
        [
          "direct-pass.json",
          "foreign-uid.mjs",
          "pass.json",
          "renew.sock",
        ].toSorted()
      );

      for (const request of received) {
        const wire = `${request.body}\n${[...request.headers].join("\n")}`;
        expect(wire).not.toContain(runToken);
        expect(wire).not.toContain(worker.d);
      }

      for (const output of outputs) {
        for (const secret of [canary, runToken, worker.d, desk.d, host.d]) {
          expect(output).not.toContain(secret);
        }
      }
    }).pipe(Effect.scoped),
  { timeout: 60_000 }
);

it.effect(
  "sc reads only its own SC_* settings and has no socket client, so a run token or renewal socket in env is never touched",
  () =>
    Effect.gen(function* sourceScan() {
      const dir = path.resolve("packages/client/src");

      const sources = yield* Effect.promise(async () => {
        const names = await readdir(dir);

        return await Promise.all(
          names
            .filter((entry) => entry.endsWith(".ts"))
            .map(async (entry) => ({
              entry,
              text: await readFile(path.join(dir, entry), "utf-8"),
            }))
        );
      });

      const allowed = new Set([
        "SC_AUDIENCE",
        "SC_IDENTITY_JSON",
        "SC_PASS_FILE",
        "SC_URL",
      ]);

      for (const { entry, text } of sources) {
        const reads = [...text.matchAll(/\benv\.(?<name>[A-Za-z_]\w*)/gu)].map(
          (match) => match.groups?.name
        );

        for (const read of reads) {
          expect([entry, allowed.has(read ?? "")]).toEqual([entry, true]);
        }

        expect([entry, /\benv\s*\[/u.test(text)]).toEqual([entry, false]);
        expect([entry, text.includes("RK_")]).toEqual([entry, false]);
        expect([
          entry,
          /\b(?:connect|createConnection|createServer)\s*\(/u.test(text) &&
            entry !== "forward.ts",
        ]).toEqual([entry, false]);
        expect([
          entry,
          /from "node:net"/u.test(text) &&
            !/import \{ isIP \} from "node:net"/u.test(text),
        ]).toEqual([entry, false]);
      }
    })
);
