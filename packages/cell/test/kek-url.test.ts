// oxlint-disable typescript/promise-function-async -- The fake key service returns native Promises, as fetch does.
import { expect, it } from "@effect/vitest";
import type { KeyUnavailable } from "@lockjaw/domain/errors";
import { Effect, Logger, Redacted, Result, Schema } from "effect";

import { KekUnavailable } from "../src/kek-unavailable.js";
import {
  Keyring,
  deriveKekId,
  makeKekLoader,
  selectKek,
} from "../src/keyring.js";
import type { KekFetch, KekUrlConfig } from "../src/keyring.js";
import { canary, name, sameValue } from "./fixtures.js";

const access = "SC_KEK_ACCESS_CANARY_q7Vd2Lw9Xp4Rt8Hn3Ks6Mb0Fj5";

const url = "http://127.0.0.1:8080/kek";

const material = (fill: number) => new Uint8Array(32).fill(fill);

interface Served {
  readonly status?: number;
  readonly type?: string | null;
  readonly body?: Uint8Array<ArrayBuffer> | null;
  readonly headers?: Readonly<Record<string, string>>;
}

const respond = (served: Served) => {
  const headers = new Headers(served.headers);

  const type =
    served.type === undefined ? "application/octet-stream" : served.type;

  if (type !== null) {
    headers.set("content-type", type);
  }

  return new Response(served.body === undefined ? material(9) : served.body, {
    headers,
    status: served.status ?? 200,
  });
};

const keyService = (...answers: readonly (Served | "redirect")[]) => {
  const calls: { readonly url: string; readonly init: unknown }[] = [];

  const fetcher: KekFetch = (target, init) => {
    calls.push({ init: structuredClone(init), url: target });
    const answer = answers[Math.min(calls.length, answers.length) - 1] ?? {};

    if (answer === "redirect") {
      return init.redirect === "error"
        ? Promise.reject(new TypeError(`redirect refused for ${target}`))
        : Promise.resolve(
            respond({
              headers: { location: "http://127.0.0.1:1/kek" },
              status: 302,
            })
          );
    }

    return Promise.resolve(respond(answer));
  };

  return { calls, fetcher };
};

const urlConfig = () => {
  const selected = selectKek({ KEK_ACCESS: access, KEK_URL: url });

  if (selected.mode !== "url") {
    throw new Error("URL mode was not selected");
  }

  return selected.config;
};

const refusalText = (error: KekUnavailable) =>
  [JSON.stringify(error), String(error), error.message].join("\n");

const isKekRefusal = Schema.is(KekUnavailable);

const expectRefusal = (error: KekUnavailable | KeyUnavailable) => {
  expect(error._tag).toBe("KekUnavailable");

  if (isKekRefusal(error)) {
    expect(error.rule).toBe("kek");
    expect(error.what.length).toBeGreaterThan(0);
    expect(error.why.length).toBeGreaterThan(0);
    expect(error.next.length).toBeGreaterThan(0);
    expect(refusalText(error)).not.toContain(access);
  }
};

const sealWith = (config: KekUrlConfig, fetcher: KekFetch) =>
  Effect.gen(function* sealUnderUrl() {
    const ring = yield* Keyring;
    const dek = yield* ring.newDek();
    const wrapped = yield* ring.wrap(dek, name);
    const sealed = yield* ring.encrypt(Redacted.make(canary), dek, name, 1);

    return { sealed, wrapped };
  }).pipe(Effect.provide(Keyring.urlLayer(config, makeKekLoader(fetcher))));

it.effect("the derived kekId is stable for the same bytes", () =>
  Effect.gen(function* derivedId() {
    const first = yield* deriveKekId(material(9));
    expect(first).toMatch(/^kek-[0-9a-f]{16}$/u);
    expect(yield* deriveKekId(material(9))).toBe(first);
    expect(yield* deriveKekId(material(8))).not.toBe(first);
  })
);

it.effect(
  "the key service request is a fixed GET with only the bearer header",
  () =>
    Effect.gen(function* request() {
      const service = keyService({});
      const set = yield* makeKekLoader(service.fetcher).load(urlConfig());

      expect(service.calls).toEqual([
        {
          init: {
            headers: { authorization: `Bearer ${access}` },
            method: "GET",
            redirect: "error",
          },
          url,
        },
      ]);
      expect(set.current.extractable).toBe(false);
      expect(set.current.usages.toSorted()).toEqual(["decrypt", "encrypt"]);
      expect(set.currentId).toBe(yield* deriveKekId(material(9)));
    })
);

it.effect(
  "URL mode and binding mode round-trip on the same bytes and kekId",
  () =>
    Effect.gen(function* roundTrip() {
      const kekId = yield* deriveKekId(material(9));
      const binding = Keyring.layer({ kekId, key: Redacted.make(material(9)) });
      const fromUrl = yield* sealWith(urlConfig(), keyService({}).fetcher);
      expect(fromUrl.wrapped.kekId).toBe(kekId);

      const fromBinding = yield* Effect.gen(function* sealUnderBinding() {
        const ring = yield* Keyring;
        const dek = yield* ring.unwrap(fromUrl.wrapped, name, kekId);

        expect(
          sameValue(
            yield* ring.decrypt(fromUrl.sealed, dek, name, 1),
            Redacted.make(canary)
          )
        ).toBe(true);

        const next = yield* ring.newDek();
        const wrapped = yield* ring.wrap(next, name);

        const sealed = yield* ring.encrypt(
          Redacted.make(canary),
          next,
          name,
          1
        );

        return { sealed, wrapped };
      }).pipe(Effect.provide(binding));

      yield* Effect.gen(function* openUnderUrl() {
        const ring = yield* Keyring;
        const dek = yield* ring.unwrap(fromBinding.wrapped, name, kekId);

        expect(
          sameValue(
            yield* ring.decrypt(fromBinding.sealed, dek, name, 1),
            Redacted.make(canary)
          )
        ).toBe(true);
      }).pipe(
        Effect.provide(
          Keyring.urlLayer(urlConfig(), makeKekLoader(keyService({}).fetcher))
        )
      );
    })
);

it.effect(
  "a DEK sealed under one URL-mode key is refused as a kekId mismatch under another",
  () =>
    Effect.gen(function* mismatch() {
      const sealed = yield* sealWith(urlConfig(), keyService({}).fetcher);
      const other = keyService({ body: material(4) });

      const error = yield* Keyring.use((ring) =>
        ring.unwrap(sealed.wrapped, name, sealed.wrapped.kekId)
      ).pipe(
        Effect.provide(
          Keyring.urlLayer(urlConfig(), makeKekLoader(other.fetcher))
        ),
        Effect.flip
      );

      expectRefusal(error);

      if (isKekRefusal(error)) {
        expect(error.what).toBe(
          "The credential is sealed under a different KEK"
        );
        expect(error.why).toContain(sealed.wrapped.kekId);
        expect(error.why).toContain(yield* deriveKekId(material(4)));
        expect(error.credential).toBe(name);
      }
    })
);

it.effect(
  "success is cached per loader, a failure is not, and the next load retries",
  () =>
    Effect.gen(function* caching() {
      const service = keyService({ status: 503 }, {});
      const loader = makeKekLoader(service.fetcher);

      expectRefusal(yield* loader.load(urlConfig()).pipe(Effect.flip));
      expect(service.calls).toHaveLength(1);

      const first = yield* loader.load(urlConfig());
      const second = yield* loader.load(urlConfig());
      expect(second).toBe(first);
      expect(service.calls).toHaveLength(2);
    })
);

it.effect(
  "key service failures and wrong bodies are refused without the access value",
  () =>
    Effect.gen(function* refusals() {
      const answers: readonly (Served | "redirect")[] = [
        { status: 401 },
        { headers: { location: "http://127.0.0.1:1/kek" }, status: 302 },
        "redirect",
        { body: new Uint8Array(31) },
        { body: new Uint8Array(33) },
        { body: new Uint8Array(0) },
        { body: null },
        { type: "text/plain" },
        { type: null },
      ];

      const lines: string[] = [];

      const logger = Logger.make(({ message }) => {
        lines.push(JSON.stringify(message));
      });

      for (const answer of answers) {
        const service = keyService(answer);

        const result = yield* Keyring.use((ring) =>
          ring.newDek().pipe(Effect.flatMap((dek) => ring.wrap(dek, name)))
        ).pipe(
          Effect.provide(
            Keyring.urlLayer(urlConfig(), makeKekLoader(service.fetcher))
          ),
          Effect.tapCause(Effect.logError),
          Effect.result,
          Effect.provide(Logger.layer([logger]))
        );

        expect(Result.isFailure(result)).toBe(true);

        if (Result.isFailure(result)) {
          expectRefusal(result.failure);
        }

        expect(service.calls).toHaveLength(1);
      }

      expect(lines.length).toBe(answers.length);
      expect(lines.join("\n")).not.toContain(access);
    })
);

it("KEK_URL must be exactly http://127.0.0.1:<port>/kek", () => {
  for (const port of ["1", "8080", "65535"]) {
    expect(
      selectKek({
        KEK_ACCESS: access,
        KEK_URL: `http://127.0.0.1:${port}/kek`,
      }).mode
    ).toBe("url");
  }

  for (const candidate of [
    "http://192.0.2.1:8080/kek",
    "http://localhost:8080/kek",
    "http://127.0.0.2:8080/kek",
    "http://[::1]:8080/kek",
    "http://127.0.0.1:8080/kek/extra",
    "http://127.0.0.1:8080/kek/",
    "http://127.0.0.1:8080/other",
    "http://127.0.0.1:8080/kek?x=1",
    "http://127.0.0.1:8080/kek#x",
    "http://user:pass@127.0.0.1:8080/kek",
    "http://user@127.0.0.1:8080/kek",
    "https://127.0.0.1:8080/kek",
    "HTTP://127.0.0.1:8080/kek",
    "http://127.0.0.1/kek",
    "http://127.0.0.1:0/kek",
    "http://127.0.0.1:08080/kek",
    "http://127.0.0.1:65536/kek",
    " http://127.0.0.1:8080/kek",
    "",
  ]) {
    const selected = selectKek({ KEK_ACCESS: access, KEK_URL: candidate });
    expect(selected.mode).toBe("refused");

    if (selected.mode === "refused") {
      expectRefusal(selected.error);
      expect(selected.error.why).toContain("http://127.0.0.1:<port>/kek");
    }
  }
});

it("exactly one KEK mode may be configured", () => {
  const binding = JSON.stringify({ kekId: "binding", key: "AAAA" });

  for (const bindings of [
    { KEK_ACCESS: access, KEK_URL: url, LOCKJAW_KEK: binding },
    { KEK_URL: url, LOCKJAW_KEK: binding },
    { KEK_ACCESS: access, LOCKJAW_KEK: binding },
    {},
    { LOCKJAW_KEK_NEXT: binding },
    { KEK_URL: url },
    { KEK_ACCESS: access },
    { KEK_ACCESS: access, KEK_URL: url, LOCKJAW_KEK_NEXT: binding },
    { KEK_ACCESS: "", KEK_URL: url },
  ]) {
    const selected = selectKek(bindings);
    expect(selected.mode).toBe("refused");

    if (selected.mode === "refused") {
      expectRefusal(selected.error);
      expect(selected.error.what).toBe(
        "Lockjaw has no usable KEK configuration"
      );
    }
  }

  expect(selectKek({ LOCKJAW_KEK: binding })).toEqual({
    current: binding,
    mode: "binding",
    next: undefined,
  });
});

it.effect("a refused configuration fails every key operation", () =>
  Effect.gen(function* refusedLayer() {
    const selected = selectKek({});
    expect(selected.mode).toBe("refused");

    if (selected.mode === "refused") {
      const error = yield* Keyring.use((ring) =>
        ring.newDek().pipe(Effect.flatMap((dek) => ring.wrap(dek, name)))
      ).pipe(Effect.provide(Keyring.refusedLayer(selected.error)), Effect.flip);

      expect(error).toBe(selected.error);
    }
  })
);
