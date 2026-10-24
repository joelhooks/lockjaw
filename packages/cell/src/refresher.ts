import type { CredentialName } from "@lockjaw/domain";
import { Context, Effect, Layer } from "effect";
import type { Redacted } from "effect";

import { RefreshFailure } from "./refresh-failure.js";

export { RefreshFailure } from "./refresh-failure.js";

export interface RefreshTokens {
  readonly value: Redacted.Redacted;
  readonly refreshToken?: Redacted.Redacted;
}

export interface RefreshedTokens extends RefreshTokens {
  readonly expiresAt: number | null;
}

export class Refresher extends Context.Service<
  Refresher,
  {
    readonly refresh: (
      credential: CredentialName,
      tokens: RefreshTokens
    ) => Effect.Effect<RefreshedTokens, RefreshFailure>;
  }
>()("secret-cell/Refresher") {
  static readonly layer = (service: Refresher["Service"]) =>
    Layer.succeed(Refresher, service);
  static readonly testLayer = Layer.succeed(
    Refresher,
    Refresher.of({
      refresh: () => Effect.fail(new RefreshFailure({ reason: "retryable" })),
    })
  );
}
