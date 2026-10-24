// oxlint-disable typescript/promise-function-async -- RPC and Web Crypto callbacks are lazy Promise boundaries; Effect owns the workflow.
import { existsSync, readFileSync } from "node:fs";

import { encode } from "@ipld/dag-cbor";
import type { KekLoader } from "@lockjaw/cell";
import { NodeSqlite } from "@lockjaw/cell/node-sqlite";
import { CredentialName, Host, encodeDidKeyP256 } from "@lockjaw/domain";
import { EchoRedactor, Fill, Policy } from "@lockjaw/gateway-rules";
import type { GatewayRequest } from "@lockjaw/gateway-rules";
import { Clock, Context, Effect, Layer, Logger, Stream } from "effect";

import { CallerAuth, base64url } from "../src/caller-auth.js";
import type { Claims } from "../src/caller-auth.js";
import { Credential } from "../src/credential-do.js";
import type { CellBindings, CellContext } from "../src/credential-do.js";
import { Registry } from "../src/directory-do.js";
import { boundaryFault as cryptoFailure } from "../src/fault.js";
import { handle } from "../src/gateway.js";
import type {
  Bindings,
  CredentialMethods,
  GrantMethods,
  Namespace,
  RpcStub,
} from "../src/gateway.js";
import { Grants } from "../src/grants-do.js";
import { Replay } from "../src/replay-do.js";
import { Upstream } from "../src/upstream.js";

interface AlarmSlot {
  at?: number;
}

const namespace = <T>(stub: RpcStub<T>): Namespace<T> => ({
  get: () => stub,
  idFromName: (key) => ({ toString: () => key }),
});

export const canary = "SC_CANARY_h6Nw7Qj9Ta4Fy8Rx2Cu5Vp3Mz0Ls1Eb";

export const name = CredentialName.make("canary/key");

export const did = "did:web:caller.invalid";

export const grants = {
  callers: ["test/*"],
  hosts: [Host.make("api.example.com")],
  inject: { header: "authorization", template: "Bearer {value}" },
  placements: ["test-host"],
};

export const target: GatewayRequest = {
  headers: [
    { name: "authorization", value: "Bearer {{secret:canary/key}}" },
    { name: "x-sc-auth", value: "caller-token-must-not-leak" },
    { name: "x-sc-resolution", value: "headers-only" },
  ],
  method: "GET",
  url: "https://api.example.com/resource",
};

export interface PassOptions {
  readonly lifetime?: number | undefined;
  readonly nonce?: string | undefined;
  readonly scope?: readonly string[] | undefined;
  readonly signer?: CryptoKeyPair | undefined;
  readonly worker?: string | undefined;
}

export interface Identity {
  readonly did: string;
  readonly name: string;
  readonly issuer?: string;
}

const signWith = (
  signer: CryptoKeyPair,
  alg: "EdDSA" | "ES256",
  text: string
) =>
  Effect.tryPromise({
    catch: cryptoFailure,
    try: async () =>
      await crypto.subtle.sign(
        alg === "ES256"
          ? { hash: "SHA-256", name: "ECDSA" }
          : { name: "Ed25519" },
        signer.privateKey,
        new TextEncoder().encode(text)
      ),
  });

export const p256 = () =>
  Effect.tryPromise({
    catch: cryptoFailure,
    try: async () =>
      await crypto.subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        true,
        ["sign", "verify"]
      ),
  });

export const publicJwk = (pair: CryptoKeyPair) =>
  Effect.tryPromise({
    catch: cryptoFailure,
    try: async () => await crypto.subtle.exportKey("jwk", pair.publicKey),
  });

export const setupWith = (
  options: {
    readonly credentialName?: CredentialName;
    readonly upstream?: Layer.Layer<Upstream>;
    readonly clock?: Clock.Clock;
    readonly logger?: Logger.Logger<unknown, unknown>;
    readonly identities?: readonly Identity[];
    readonly approver?: string;
    readonly kek?: {
      readonly bindings: CellBindings;
      readonly loader: KekLoader;
    };
  } = {}
) =>
  Effect.gen(function* setup() {
    const scope = yield* Effect.scope;
    const files: string[] = [];
    const contexts = new Map<string, CellContext>();
    const alarmTimes = new Map<string, AlarmSlot>();

    const allocate = (key: string) =>
      Effect.gen(function* allocateCell() {
        const context = yield* Layer.buildWithScope(NodeSqlite.layer, scope);
        const sqlite = Context.get(context, NodeSqlite);
        files.push(sqlite.path);
        const alarms: AlarmSlot = {};
        alarmTimes.set(key, alarms);

        const ctx: CellContext = {
          id: { name: key },
          storage: {
            deleteAlarm: () => {
              delete alarms.at;

              return Promise.resolve();
            },
            setAlarm: (at) => {
              alarms.at = at;

              return Promise.resolve();
            },
            sql: sqlite.sql,
            transactionSync: sqlite.sql.transactionSync,
          },
        };

        contexts.set(key, ctx);

        return ctx;
      });

    const { kek, ...runtime } = options;

    const credential = new Credential(
      yield* allocate(options.credentialName ?? name),
      kek?.bindings ?? {
        LOCKJAW_KEK: JSON.stringify({
          kekId: "test-kek",
          key: base64url(new Uint8Array(32).fill(42)),
        }),
      },
      undefined,
      options.upstream,
      kek === undefined ? runtime : { ...runtime, kek: kek.loader }
    );

    yield* Effect.addFinalizer(() =>
      Effect.promise(async () => {
        await credential.dispose();
      })
    );
    const registry = new Registry(yield* allocate("registry"));
    const grantStore = new Grants(yield* allocate("grants"));
    const replay = new Replay(yield* allocate("replay"));
    let resolves = 0;

    const env: Bindings = {
      APPROVER_DID: options.approver ?? did,
      CREDENTIAL: namespace<CredentialMethods>({
        approve: async (...args) =>
          structuredClone(await credential.approve(...args)),
        describe: async () => structuredClone(await credential.describe()),
        resolve: async (...args) => {
          resolves += 1;

          return structuredClone(await credential.resolve(...args));
        },
        revoke: async () => structuredClone(await credential.revoke()),
        rotate: async (...args) =>
          structuredClone(await credential.rotate(...args)),
        set: async (...args) => structuredClone(await credential.set(...args)),
      }),
      GRANTS: namespace<GrantMethods>({
        insert: (grant) =>
          Promise.resolve(
            structuredClone(grantStore.insert(structuredClone(grant)))
          ),
        list: () => Promise.resolve(structuredClone(grantStore.list())),
        own: (credentialName, grant) => {
          grantStore.own(credentialName, grant);

          return Promise.resolve();
        },
        owner: (credentialName) =>
          Promise.resolve(grantStore.owner(credentialName)),
        revoke: (id, at) => Promise.resolve(grantStore.revoke(id, at)),
      }),
      REGISTRY: namespace<Pick<Registry, "list" | "register" | "record">>({
        list: () => Promise.resolve(structuredClone(registry.list())),
        record: (entry) => {
          registry.record(structuredClone(entry));

          return Promise.resolve();
        },
        register: (key) => {
          registry.register(key);

          return Promise.resolve();
        },
      }),
      REPLAY: namespace<Pick<Replay, "consume" | "bind">>({
        bind: async (key, nonce, binding, expires, now) =>
          await replay.bind(key, nonce, binding, expires, now),
        consume: async (key, jti, expires, now) =>
          await replay.consume(key, jti, expires, now),
      }),
      SETTERS: JSON.stringify([did]),
    };

    const pair = yield* Effect.tryPromise({
      catch: cryptoFailure,
      try: async () =>
        await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
          "sign",
          "verify",
        ]),
    });

    const publicKeyJwk = yield* Effect.tryPromise({
      catch: cryptoFailure,
      try: async () => await crypto.subtle.exportKey("jwk", pair.publicKey),
    });

    const keys = new Map<string, CryptoKeyPair>();

    for (const entry of options.identities ?? []) {
      keys.set(entry.did, yield* p256());
    }

    const extra = [];

    for (const entry of options.identities ?? []) {
      const pairFor = keys.get(entry.did);

      if (pairFor !== undefined) {
        extra.push({
          authentication: [`${entry.did}#key`],
          id: entry.did,
          issuer: entry.issuer ?? "test-host",
          name: entry.name,
          verificationMethod: [
            {
              controller: entry.did,
              id: `${entry.did}#key`,
              publicKeyJwk: yield* publicJwk(pairFor),
            },
          ],
        });
      }
    }

    const documents = JSON.stringify([
      {
        authentication: [`${did}#key`],
        id: did,
        issuer: "test-host",
        name: "test/agent",
        verificationMethod: [
          { controller: did, id: `${did}#key`, publicKeyJwk },
        ],
      },
      ...extra,
    ]);

    let sequence = 0;

    const compact = (
      signer: CryptoKeyPair,
      alg: "EdDSA" | "ES256",
      header: Readonly<Record<string, string>>,
      payload: string
    ) =>
      Effect.gen(function* compactJws() {
        const head = base64url(
          new TextEncoder().encode(JSON.stringify({ alg, ...header }))
        );

        const body = base64url(new TextEncoder().encode(payload));
        const signature = yield* signWith(signer, alg, `${head}.${body}`);

        return `${head}.${body}.${base64url(new Uint8Array(signature))}`;
      });

    const tokenAs = (
      as: string,
      lxm = "sh.secretcell.fetch",
      overrides: Partial<Claims> = {},
      signer?: CryptoKeyPair
    ) =>
      Effect.gen(function* signTokenAs() {
        sequence += 1;
        const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);
        const key = signer ?? keys.get(as);

        if (key === undefined) {
          return yield* cryptoFailure();
        }

        return yield* compact(
          key,
          "ES256",
          { kid: "#key", typ: "JWT" },
          JSON.stringify({
            aud: "did:web:cell.invalid",
            exp: now + 60,
            iat: now,
            iss: as,
            jti: `test-jti-unique-${sequence}`,
            lxm,
            sid: "pi-session-test",
            ...overrides,
          })
        );
      });

    const pass = (
      deskDid: string,
      deskName: string,
      run: string,
      workerKey: JsonWebKey,
      passOptions: PassOptions = {}
    ) =>
      Effect.gen(function* signPass() {
        sequence += 1;
        const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);
        const key = passOptions.signer ?? keys.get(deskDid);

        const worker =
          passOptions.worker ??
          encodeDidKeyP256({
            crv: "P-256",
            kty: "EC",
            x: workerKey.x ?? "",
            y: workerKey.y ?? "",
          });

        if (key === undefined || worker === undefined) {
          return yield* cryptoFailure();
        }

        const record = {
          $type: "sh.ratking.pass",
          desk: deskName,
          deskDid,
          exp: now + (passOptions.lifetime ?? 300),
          iat: now,
          nonce: passOptions.nonce ?? `nonce-${sequence}-0123456789abcdef`,
          run,
          scope: (passOptions.scope ?? ["sh.secretcell.fetch"]).map((entry) =>
            [
              "sh.secretcell.fetch",
              "sh.secretcell.describe",
              "sh.secretcell.list",
            ].includes(entry)
              ? `${entry}:${deskName.split("/")[0]}/*`
              : entry
          ),
          v: 1,
          worker,
        };

        const signed = yield* Effect.tryPromise({
          catch: cryptoFailure,
          try: async () =>
            await crypto.subtle.sign(
              { hash: "SHA-256", name: "ECDSA" },
              key.privateKey,
              Uint8Array.from(
                encode({ domain: "sh.ratking.delegation.v1", record })
              )
            ),
        });

        return JSON.stringify({
          record,
          signature: base64url(new Uint8Array(signed)),
        });
      });

    const token = (
      lxm = "sh.secretcell.fetch",
      overrides: Partial<Claims> = {}
    ) =>
      Effect.gen(function* signToken() {
        sequence += 1;
        const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

        const header = base64url(
          new TextEncoder().encode(
            JSON.stringify({ alg: "EdDSA", kid: "#key", typ: "JWT" })
          )
        );

        const payload = base64url(
          new TextEncoder().encode(
            JSON.stringify({
              aud: "did:web:cell.invalid",
              exp: now + 60,
              iat: now,
              iss: did,
              jti: `test-jti-unique-${sequence}`,
              lxm,
              sid: "pi-session-test",
              ...overrides,
            })
          )
        );

        const signature = yield* Effect.tryPromise({
          catch: cryptoFailure,
          try: async () =>
            await crypto.subtle.sign(
              "Ed25519",
              pair.privateKey,
              new TextEncoder().encode(`${header}.${payload}`)
            ),
        });

        return `${header}.${payload}.${base64url(new Uint8Array(signature))}`;
      });

    const received: GatewayRequest[] = [];

    const upstream = Upstream.testLayer({
      send: (request) =>
        Effect.sync(() => {
          received.push(request);

          return {
            body: Stream.fromIterable([
              canary.slice(0, 13),
              canary.slice(13),
              encodeURIComponent(canary),
            ]).pipe(Stream.map((chunk) => new TextEncoder().encode(chunk))),
            headers: [
              { name: "x-echo", value: canary },
              { name: "location", value: `https://evil.example/${canary}` },
            ],
            status: 302,
            statusText: `echo ${canary}`,
            url: `${request.url}/${canary}`,
          };
        }),
    });

    const layers = Layer.mergeAll(
      CallerAuth.layer(documents, "did:web:cell.invalid"),
      options.upstream ?? upstream,
      Fill.layer,
      EchoRedactor.layer,
      Policy.layer,
      options.logger ? Logger.layer([options.logger]) : Layer.empty
    );

    const call = (
      path: string,
      body: string | undefined,
      signed: string,
      method = "POST",
      extraHeaders: HeadersInit = {},
      bindings = env
    ) => {
      const headers = new Headers(extraHeaders);
      headers.set("x-sc-auth", signed);
      const init: RequestInit = { headers, method };

      if (body !== undefined) {
        init.body = body;
      }

      return handle(
        new Request(`https://cell.invalid${path}`, init),
        bindings
      ).pipe(Effect.provide(layers));
    };

    const disk = () =>
      files.flatMap((file) =>
        [file, `${file}-wal`, `${file}-shm`].flatMap((diskPath) =>
          existsSync(diskPath) ? [readFileSync(diskPath)] : []
        )
      );

    return {
      alarmTimes,
      call,
      contexts,
      credential,
      disk,
      env,
      grantStore,
      keys,
      pass,
      received,
      registry,
      replay,
      resolves: () => resolves,
      token,
      tokenAs,
    };
  });

export const setup = setupWith();
