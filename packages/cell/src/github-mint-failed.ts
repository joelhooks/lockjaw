import { Schema } from "effect";

export class GitHubMintFailed extends Schema.TaggedError<GitHubMintFailed>()(
  "GitHubMintFailed",
  { reason: Schema.Literals(["auth", "retryable"]) }
) {}
