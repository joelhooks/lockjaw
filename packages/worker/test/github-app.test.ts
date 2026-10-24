import { expect, it } from "@effect/vitest";
import { Clock, Effect } from "effect";
import { TestClock } from "effect/testing";

import { base64url } from "../src/caller-auth.js";
import { Credential } from "../src/credential-do.js";
import { githubMetadata, githubName, githubSetup } from "./github-fixture.js";

const noWindows = (value: string, surfaces: readonly string[]) => {
  for (let offset = 0; offset + 8 <= value.length; offset += 1) {
    expect(
      surfaces.every(
        (surface) => !surface.includes(value.slice(offset, offset + 8))
      )
    ).toBe(true);
  }
};

it.effect(
  "GitHub App API and git Basic calls use minted tokens and redact echoed credentials",
  () =>
    Effect.gen(function* scenario1() {
      const fixture = yield* githubSetup;
      expect((yield* fixture.set()).status).toBe(200);
      expect((yield* fixture.approve()).status).toBe(200);
      const api = yield* fixture.fetch();
      const git = yield* fixture.fetch(true);
      expect(api.status).toBe(200);
      expect(git.status).toBe(200);
      expect(fixture.mints()).toBe(1);
      expect(
        fixture.received[0]?.authorization === `Bearer ${fixture.tokens[0]}`
      ).toBe(true);
      expect(
        fixture.received[1]?.authorization ===
          `Basic ${btoa(`x-access-token:${fixture.tokens[0]}`)}`
      ).toBe(true);
      expect(fixture.received.map((entry) => entry.host)).toEqual([
        "api.github.com",
        "github.com",
      ]);
      expect(fixture.signaturesValid()).toBe(true);
      expect(fixture.claims).toEqual([{ exp: 540, iat: -60, iss: "12345" }]);
      expect(fixture.installationPaths).toEqual([
        "POST /app/installations/9876/access_tokens",
      ]);

      const listed = yield* fixture.call(
        "/v1/list",
        undefined,
        yield* fixture.token("sh.secretcell.list"),
        "GET"
      );

      const description = yield* Effect.promise(
        async () => await fixture.credential.describe()
      );

      const surfaces = [
        api.text,
        api.headers,
        git.text,
        git.headers,
        yield* Effect.promise(async () => await listed.text()),
        JSON.stringify(description),
        ...fixture.logs,
        JSON.stringify([
          ...(fixture.contexts
            .get(githubName)
            ?.storage.sql.exec("SELECT json FROM uses") ?? []),
        ]),
        JSON.stringify(fixture.registry.list()),
        ...fixture.disk().map((bytes) => bytes.toString()),
      ];

      noWindows(fixture.pem, surfaces);

      for (const token of fixture.tokens) {
        noWindows(token, surfaces);
        noWindows(btoa(`x-access-token:${token}`), surfaces);
      }

      expect(api.text !== fixture.received[0]?.authorization).toBe(true);
      expect(git.text !== fixture.received[1]?.authorization).toBe(true);
    })
);

it.effect(
  "20 concurrent owner resolves single-flight, including one re-mint five minutes before expiry",
  () =>
    Effect.gen(function* scenario2() {
      const fixture = yield* githubSetup;
      yield* fixture.set();
      yield* fixture.approve();

      const burst = () =>
        Effect.forEach(Array.from({ length: 20 }), () => fixture.fetch(), {
          concurrency: "unbounded",
        });

      expect((yield* burst()).every((result) => result.status === 200)).toBe(
        true
      );
      expect(fixture.mints()).toBe(1);
      yield* TestClock.adjust("55 minutes");
      expect((yield* burst()).every((result) => result.status === 200)).toBe(
        true
      );
      expect(fixture.mints()).toBe(2);
      expect((yield* fixture.fetch(false, "other")).status).toBe(200);
      expect(fixture.mints()).toBe(3);
      expect(fixture.installationPaths.at(-1)).toBe(
        "POST /app/installations/5432/access_tokens"
      );
    })
);

it.effect(
  "mint 401 and 403 require auth, never echo upstream bodies, and remain fenced after retry",
  () =>
    Effect.gen(function* scenario3() {
      for (const status of [401, 403]) {
        const fixture = yield* githubSetup;
        yield* fixture.set();
        yield* fixture.approve();
        fixture.setStatus(status);
        const result = yield* fixture.fetch();
        expect(result.status).toBe(403);
        expect(result.text.includes("needs-auth")).toBe(true);
        expect(result.text.includes("what")).toBe(true);
        expect(result.text.includes("why")).toBe(true);
        expect(result.text.includes("next")).toBe(true);
        noWindows(fixture.pem, [result.text]);
        const again = yield* fixture.fetch();
        expect(again.status).toBe(403);
        expect(fixture.mints()).toBe(1);

        const description = yield* Effect.promise(
          async () => await fixture.credential.describe()
        );

        expect(
          description.ok && description.value.lifecycle?.state === "needsAuth"
        ).toBe(true);
      }
    })
);

it.effect(
  "mint retries a 5xx exactly once and leaves no failed body in the caller response",
  () =>
    Effect.gen(function* scenario4() {
      const fixture = yield* githubSetup;
      yield* fixture.set();
      yield* fixture.approve();
      fixture.failOnce();
      expect((yield* fixture.fetch()).status).toBe(200);
      expect(fixture.mints()).toBe(2);
      yield* TestClock.adjust("55 minutes");
      fixture.setStatus(503);
      const failed = yield* fixture.fetch();
      expect(failed.status).toBe(403);
      expect(fixture.mints()).toBe(4);
      noWindows(fixture.pem, [failed.text, ...fixture.logs]);

      for (const token of fixture.tokens) {
        noWindows(token, [failed.text, ...fixture.logs]);
      }
    })
);

it.effect(
  "PKCS1 and malformed keys are refused before storing; installation changes require approve",
  () =>
    Effect.gen(function* scenario5() {
      const fixture = yield* githubSetup;
      const rejected = yield* fixture.set(fixture.pkcs1);
      expect(rejected.status).toBe(403);
      expect(rejected.text.includes("PKCS#1")).toBe(true);
      expect(
        rejected.text.includes(
          "openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pk8.pem"
        )
      ).toBe(true);

      const malformed = yield* fixture.set(
        "-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"
      );

      expect(malformed.status).toBe(403);

      const before = yield* Effect.promise(
        async () => await fixture.credential.describe()
      );

      expect(before.ok && before.value.meta === undefined).toBe(true);
      yield* fixture.set();
      yield* fixture.approve();
      yield* fixture.fetch();

      const changed = {
        ...githubMetadata,
        installations: { "example-org": 9999, other: 5432 },
      };

      expect((yield* fixture.set(fixture.pem, changed)).status).toBe(403);
      expect((yield* fixture.approve(changed)).status).toBe(200);
      expect((yield* fixture.fetch()).status).toBe(200);
      expect(fixture.installationPaths.at(-1)).toBe(
        "POST /app/installations/9999/access_tokens"
      );
      expect(fixture.mints()).toBe(2);
      expect((yield* fixture.set(fixture.pem, changed)).status).toBe(200);
      expect(
        (yield* fixture.set(fixture.pem, {
          appId: changed.appId,
          installations: { "example-org": 9999, other: 5432 },
        })).status
      ).toBe(200);
      noWindows(fixture.pkcs1, [rejected.text]);
      noWindows(fixture.pem, [
        rejected.text,
        malformed.text,
        ...fixture.disk().map((bytes) => bytes.toString()),
      ]);
    })
);

it.effect(
  "unknown owner is refused without minting, and revoke or rotate discards cached tokens",
  () =>
    Effect.gen(function* scenario6() {
      const fixture = yield* githubSetup;
      yield* fixture.set();
      yield* fixture.approve();
      const unknown = yield* fixture.fetch(false, "unknown");
      expect(unknown.status).toBe(403);
      expect(unknown.text.includes("/v1/approve")).toBe(true);
      expect(fixture.mints()).toBe(0);
      yield* fixture.fetch();
      expect(
        (yield* Effect.promise(
          async () => await fixture.credential.rotateBegin(fixture.pem)
        )).ok
      ).toBe(true);
      yield* fixture.fetch();
      expect(fixture.mints()).toBe(2);
      yield* Effect.promise(async () => await fixture.credential.rotateAbort());
      yield* fixture.fetch();
      expect(fixture.mints()).toBe(3);
      yield* Effect.promise(async () => await fixture.credential.revoke());
      expect((yield* fixture.fetch()).status).toBe(403);
      expect(fixture.mints()).toBe(3);
    })
);

it.effect(
  "a fresh DO activation re-mints rather than restoring an installation token from SQLite",
  () =>
    Effect.gen(function* restart() {
      const fixture = yield* githubSetup;
      yield* fixture.set();
      yield* fixture.approve();
      yield* fixture.fetch();
      expect(fixture.mints()).toBe(1);
      yield* Effect.promise(async () => {
        await fixture.credential.dispose();
      });
      const context = fixture.contexts.get(githubName);

      if (!context) {
        return yield* Effect.die("Missing GitHub credential context");
      }

      const credential = new Credential(
        context,
        {
          LOCKJAW_KEK: JSON.stringify({
            kekId: "test-kek",
            key: base64url(new Uint8Array(32).fill(42)),
          }),
        },
        undefined,
        fixture.upstream,
        { clock: yield* Clock.clockWith(Effect.succeed) }
      );

      yield* Effect.addFinalizer(() =>
        Effect.promise(async () => {
          await credential.dispose();
        })
      );

      const result = yield* Effect.promise(
        async () =>
          await credential.resolve(
            {
              did: "did:web:caller.invalid",
              issuer: "test-host",
              name: "test/agent",
              sid: "session",
            },
            {
              credential: githubName,
              host: "api.github.com",
              method: "GET",
              path: "/user",
              subkey: "example-org",
            }
          )
      );

      expect(result.ok).toBe(true);
      expect(fixture.mints()).toBe(2);
      const surfaces = fixture.disk().map((bytes) => bytes.toString());
      noWindows(fixture.pem, surfaces);

      for (const token of fixture.tokens) {
        noWindows(token, surfaces);
      }

      return yield* Effect.void;
    })
);
