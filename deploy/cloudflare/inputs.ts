import { Config, Effect, Option, Redacted, Schema } from "effect";

import { CloudflareRefusal, settings } from "./config.ts";
import type { Settings } from "./config.ts";

const KeyBinding = Schema.Struct({
  kekId: Schema.NonEmptyString,
  key: Schema.String.check(Schema.isPattern(/^[A-Za-z0-9_-]{43}=?$/u)),
});

export interface SecretInput {
  readonly kekId: string;
  readonly value: Redacted.Redacted;
}

export interface Inputs {
  readonly settings: Settings;
  readonly kek: SecretInput;
  readonly kekNext: SecretInput | undefined;
}

const refusal = (what: string, why: string, next: string) =>
  new CloudflareRefusal({ next, what, why });

export const secretInput = Effect.fn("SecretCell.cloudflareSecretInput")(
  function* secretInput(name: string) {
    const value = yield* Config.Redacted(name).pipe(
      Effect.mapError(() =>
        refusal(
          `Secret input ${name} is not set.`,
          "The KEK is read from the deploy process environment, by the name in the private config file. The stack never reads it from a file or a default.",
          `Inject ${name} from your secret manager for this one command, for example with op run or a secrets exec wrapper, then rerun.`
        )
      )
    );

    const binding = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(KeyBinding)
    )(Redacted.value(value)).pipe(
      Effect.mapError(() =>
        refusal(
          `Secret input ${name} is not a KEK binding.`,
          'The Worker expects JSON {"kekId": "...", "key": "<base64url of 32 bytes>"}. The value itself is not shown.',
          `Check the escrowed KEK behind ${name} and re-export it in that shape, then rerun.`
        )
      )
    );

    return { kekId: binding.kekId, value };
  }
);

export const resolveInputs = Effect.fn("SecretCell.cloudflareInputs")(
  function* resolveInputs(chosen: Settings) {
    const account = yield* Config.String("CLOUDFLARE_ACCOUNT_ID").pipe(
      Config.option
    );

    if (Option.getOrUndefined(account) !== chosen.accountId) {
      return yield* refusal(
        "CLOUDFLARE_ACCOUNT_ID does not match the private config's accountId.",
        "Alchemy deploys to the account its credentials resolve to. The stack only deploys to the account named in the private file.",
        "Export CLOUDFLARE_ACCOUNT_ID with the accountId from the config file, with an API token for that account, then rerun."
      );
    }

    const kek = yield* secretInput(chosen.secrets.kek);

    const kekNext =
      chosen.secrets.kekNext === undefined
        ? undefined
        : yield* secretInput(chosen.secrets.kekNext);

    if (kekNext?.kekId === kek.kekId) {
      return yield* refusal(
        "LOCKJAW_KEK and LOCKJAW_KEK_NEXT share one kekId.",
        "The Worker picks the key by kekId, so two bindings with one id are ambiguous.",
        "Give the next KEK its own kekId, or drop secrets.kekNext from the config, then rerun."
      );
    }

    return { kek, kekNext, settings: chosen };
  }
);

export const inputs = settings.pipe(Effect.flatMap(resolveInputs));
