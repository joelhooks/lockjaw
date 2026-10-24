import { NodeServices } from "@effect/platform-node";
import { it } from "@effect/vitest";
import { Effect, Exit, FileSystem } from "effect";
import { expect } from "vitest";

import example from "../config.example.json" with { type: "json" };
import { CelldRefusal, decodeSettings, loadSettings } from "../config.ts";
import { resolveInputs } from "../inputs.ts";
import { CANARY, chosenSettings, environment, kekText } from "./fixture.ts";

it.effect("decodes the example and enforces file permissions", () =>
  Effect.gen(function* valid() {
    const chosen = yield* chosenSettings;

    expect(chosen.host.tailnetIPv4).toBe("192.0.2.10");

    const fs = yield* FileSystem.FileSystem;
    const directory = yield* fs.makeTempDirectoryScoped();
    const file = `${directory}/celld.json`;

    yield* fs.writeFileString(file, JSON.stringify(example));
    yield* fs.chmod(file, 0o600);
    expect(yield* loadSettings(file)).toEqual(chosen);
    yield* fs.chmod(file, 0o644);

    const denied = yield* loadSettings(file).pipe(Effect.flip);

    expect(denied).toBeInstanceOf(CelldRefusal);
    expect(denied.message).toMatch(/What: .*Why: .*Next: /u);
    expect(yield* loadSettings(directory).pipe(Effect.exit)).toSatisfy(
      Exit.isFailure
    );
    expect(
      yield* loadSettings(`${directory}/missing`).pipe(Effect.exit)
    ).toSatisfy(Exit.isFailure);
  }).pipe(Effect.scoped, Effect.provide(NodeServices.layer))
);

it.effect(
  "refuses invalid fields, overlapping paths and ports, private documents and non-origin readback URLs",
  () =>
    Effect.gen(function* invalid() {
      const cases = [
        { ...example, portBase: 65_527 },
        { ...example, portBase: 18_333 },
        { ...example, dataRoot: example.host.dataRoot },
        { ...example, dataRoot: `${example.host.home}/.config/lockjaw` },
        { ...example, host: { ...example.host, tailnetIPv4: "999.0.2.1" } },
        { ...example, host: { ...example.host, ssh: "-oProxyCommand=bad" } },
        { ...example, dataRoot: "/srv/../etc" },
        { ...example, workerUrl: "http://user:password@example.com" },
        { ...example, workerUrl: "not-a-url" },
        {
          ...example,
          kek: {
            access: "ACCESS",
            kind: "url",
            url: "https://kek.example.com/key",
          },
        },
        { ...example, workerUrl: "https://example.com/path" },
        { ...example, workerUrl: "https://example.com?query=secret" },
        { ...example, unexpected: "must-not-echo" },
        {
          ...example,
          callerDocuments: [
            { ...example.callerDocuments[0], privateKey: "must-not-echo" },
          ],
        },
        { ...example, kek: { kek: "bad-variable", kind: "binding" } },
        { ...example, kek: { access: "ACCESS", kind: "url", url: "http://[" } },
      ];

      for (const document of cases) {
        const denied = yield* decodeSettings(JSON.stringify(document)).pipe(
          Effect.flip
        );

        expect(denied.message).toMatch(/What: .*Why: .*Next: /u);
        expect(denied.message).not.toContain("must-not-echo");
      }

      expect(yield* decodeSettings("{").pipe(Effect.exit)).toSatisfy(
        Exit.isFailure
      );
    })
);

it.effect(
  "validates current and next KEKs and URL mode access without leaking inputs",
  () =>
    Effect.gen(function* secrets() {
      const chosen = yield* chosenSettings;

      expect(yield* resolveInputs(chosen)).toEqual(chosen);

      const next = {
        ...chosen,
        kek: {
          kek: "EXAMPLE_LOCKJAW_KEK",
          kekNext: "NEXT_KEK",
          kind: "binding" as const,
        },
      };

      expect(
        yield* resolveInputs(next).pipe(
          Effect.provide(environment({ NEXT_KEK: kekText("example-kek-2") }))
        )
      ).toEqual(next);

      const same = yield* resolveInputs(next).pipe(
        Effect.provide(environment({ NEXT_KEK: kekText("example-kek-1") })),
        Effect.flip
      );

      expect(same.message).toContain("share one kekId");

      const malformed = yield* resolveInputs(chosen).pipe(
        Effect.provide(
          environment({ EXAMPLE_LOCKJAW_KEK: `{"key":"${CANARY}!"}` })
        ),
        Effect.flip
      );

      expect(malformed.message).not.toContain(CANARY);
      expect(malformed.message).toMatch(/What: .*Why: .*Next: /u);

      const missing = yield* resolveInputs({
        ...chosen,
        kek: { kek: "MISSING", kind: "binding" },
      }).pipe(Effect.flip);

      expect(missing.message).toContain("missing");

      const url = {
        ...chosen,
        kek: {
          access: "ACCESS",
          kind: "url" as const,
          url: "http://127.0.0.1:32100/kek",
        },
      };

      expect(
        yield* resolveInputs(url).pipe(
          Effect.provide(environment({ ACCESS: "example-access" }))
        )
      ).toEqual(url);
      expect(
        yield* resolveInputs(url).pipe(
          Effect.provide(environment({ ACCESS: " " })),
          Effect.exit
        )
      ).toSatisfy(Exit.isFailure);
    }).pipe(Effect.provide(environment()))
);
