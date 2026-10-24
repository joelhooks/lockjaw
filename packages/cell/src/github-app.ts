import type { CredentialName } from "@lockjaw/domain";
import type { Redacted } from "effect";
import { Context, Effect, Layer } from "effect";

import { GitHubMintFailed } from "./github-mint-failed.js";
import { SigningKeyInvalid } from "./signing-key-invalid.js";

export { SigningKeyInvalid } from "./signing-key-invalid.js";

export { GitHubMintFailed } from "./github-mint-failed.js";

export { CredentialReferenceInvalid } from "./credential-reference-invalid.js";

export type SigningAlgorithm = "RSASSA-PKCS1-v1_5/SHA-256";

export interface InstallationToken {
  readonly value: Redacted.Redacted;
  readonly expiresAt: number;
}

export class GitHubApp extends Context.Service<
  GitHubApp,
  {
    readonly mint: (input: {
      readonly credential: CredentialName;
      readonly key: CryptoKey;
      readonly appId: string;
      readonly installationId: number;
    }) => Effect.Effect<InstallationToken, GitHubMintFailed>;
  }
>()("secret-cell/GitHubApp") {
  static readonly layer = (service: GitHubApp["Service"]) =>
    Layer.succeed(GitHubApp, service);
  static readonly unavailableLayer = GitHubApp.layer({
    mint: () => Effect.fail(new GitHubMintFailed({ reason: "retryable" })),
  });
}

export const signingKeyInvalid = (credential: CredentialName, pkcs1 = false) =>
  new SigningKeyInvalid({
    credential,
    next: pkcs1
      ? "Run openssl pkcs8 -topk8 -nocrypt -in app.pem -out app.pk8.pem, then set again."
      : "Generate or convert a PKCS#8 RSA key, then POST /v1/set with the replacement.",
    rule: "signing-key",
    what: pkcs1 ? "The key is PKCS#1" : "The signing key is invalid",
    why: pkcs1
      ? "celld's Web Crypto imports PKCS#8 only"
      : "A valid PKCS#8 RSA private key is required",
  });
