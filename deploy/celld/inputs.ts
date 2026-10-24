import { HostError, SecretSource } from "@rat-king/alchemy-nest";
import { Config, Effect, Layer, Redacted, Schema } from "effect";

import { refusal, settings } from "./config.ts";
import type { Settings } from "./config.ts";

const KeyBinding = Schema.Struct({
  kekId: Schema.NonEmptyString,
  key: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}=?$/u)),
});

const secret = (name: string) =>
  Config.Redacted(name).pipe(
    Effect.mapError(() =>
      refusal(
        `Secret input ${name} is missing.`,
        "The stack only reads secrets from the deploy process environment.",
        "Inject the named variable from your secret manager, then rerun."
      )
    )
  );

const keyBinding = Effect.fn("Lockjaw.celldKeyBinding")(function* keyBinding(
  name: string
) {
  const value = yield* secret(name);

  return yield* Schema.decodeUnknownEffect(Schema.fromJsonString(KeyBinding))(
    Redacted.value(value)
  ).pipe(
    Effect.mapError(() =>
      refusal(
        `Secret input ${name} is not a KEK binding.`,
        "Expected JSON with kekId and a base64url-encoded 32-byte key; values are withheld.",
        "Correct the secret manager value, then rerun."
      )
    )
  );
});

export const resolveInputs = Effect.fn("Lockjaw.celldInputs")(
  function* resolveInputs(chosen: Settings) {
    if (chosen.kek.kind === "binding") {
      const current = yield* keyBinding(chosen.kek.kek);

      if (chosen.kek.kekNext !== undefined) {
        const next = yield* keyBinding(chosen.kek.kekNext);

        if (current.kekId === next.kekId) {
          return yield* refusal(
            "The current and next KEKs share one kekId.",
            "The Worker cannot distinguish two keys with the same id.",
            "Give the next KEK a distinct kekId, or remove kekNext."
          );
        }
      }
    } else {
      const access = yield* secret(chosen.kek.access);

      if (Redacted.value(access).trim().length === 0) {
        return yield* refusal(
          "KEK access is empty.",
          "URL mode requires a bearer credential.",
          "Inject a nonempty access credential, then rerun."
        );
      }
    }

    return chosen;
  }
);

export const environmentSecrets = Layer.succeed(SecretSource, {
  resolve: (ref) =>
    secret(ref.secret).pipe(
      Effect.mapError(
        () =>
          new HostError({
            operation: "secret input",
            reason: "Named environment secret is unavailable; values withheld.",
          })
      )
    ),
});

export const inputs = settings.pipe(Effect.flatMap(resolveInputs));

export const bindingSource = (chosen: Settings["kek"]) => {
  if (chosen.kind === "url") {
    return {
      format: "json" as const,
      secrets: { ACCESS: chosen.access },
      template: '{"KEK_ACCESS":{{ACCESS}}}',
    };
  }

  if (chosen.kekNext === undefined) {
    return {
      format: "json" as const,
      secrets: { KEK: chosen.kek },
      template: '{"LOCKJAW_KEK":{{KEK}}}',
    };
  }

  return {
    format: "json" as const,
    secrets: { KEK: chosen.kek, NEXT: chosen.kekNext },
    template: '{"LOCKJAW_KEK":{{KEK}},"LOCKJAW_KEK_NEXT":{{NEXT}}}',
  };
};

export const secretNames = (chosen: Settings["kek"]) => {
  if (chosen.kind === "url") {
    return ["KEK_ACCESS"];
  }

  return chosen.kekNext === undefined
    ? ["LOCKJAW_KEK"]
    : ["LOCKJAW_KEK", "LOCKJAW_KEK_NEXT"];
};
