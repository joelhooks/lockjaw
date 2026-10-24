import { CredentialName } from "@lockjaw/domain";
import { Schema } from "effect";

export class NothingToFill extends Schema.TaggedError<NothingToFill>()(
  "NothingToFill",
  {
    credential: CredentialName,
    next: Schema.String,
    rule: Schema.Literal("nothing-to-fill"),
    what: Schema.String,
    why: Schema.String,
  }
) {}

export const nothingToFill = (resolutionOff: boolean) =>
  new NothingToFill({
    credential: CredentialName.make("request"),
    next: resolutionOff
      ? "Send this request directly, or remove x-sc-resolution: off and put {{secret:<name>}} in the credential's declared header."
      : "Send this request directly, or put {{secret:<name>}} in the credential's declared header.",
    rule: "nothing-to-fill",
    what: resolutionOff
      ? "The request sets x-sc-resolution: off, so it carries no credential placeholder to fill"
      : "The request carries no credential placeholder",
    why: "Lockjaw forwards only requests it fills, to hosts declared for those credentials.",
  });
