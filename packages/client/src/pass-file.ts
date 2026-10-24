import { constants } from "node:fs";
import { open } from "node:fs/promises";

import { SignedPass, SignedTicket } from "@rat-king/lexicon/passes";
import { Clock, Effect, Schema } from "effect";

import { ClientFailure } from "./failure.js";
import { passStale } from "./pass-stale.js";

const PassFile = Schema.Struct({
  pass: SignedPass,
  renewedAt: Schema.Int,
  run: Schema.String,
  ticket: Schema.optionalKey(SignedTicket),
  v: Schema.Literal(1),
  workerDid: Schema.String.check(Schema.isPattern(/^did:key:z/u)),
});

const Version = Schema.Struct({ v: Schema.Unknown });

export const staleSeconds = 30;

const runtimeNext =
  "Check the worker's blocked item in its desk queue; the worker runtime owns SC_PASS_FILE.";

const refused = (what: string, why: string, next = runtimeNext) =>
  new ClientFailure({ code: 2, next, what, why });

export const bothPassSources = () =>
  refused(
    "SC_PASS_FILE and --pass were both given",
    "sc takes its worker pass from exactly one place, so it will not guess which one is current.",
    "Unset SC_PASS_FILE to use a desk-minted --pass file, or drop --pass to use the worker runtime's pass file."
  );

const readOwned = (path: string) =>
  Effect.tryPromise({
    catch: () =>
      refused(
        "SC_PASS_FILE is not a private file owned by this user",
        "The pass file must be a regular mode 0600 file owned by the current uid, so no other account can plant or read a pass.",
        "Check SC_PASS_FILE points at the worker runtime's pass file; the runtime writes it 0600 as this user."
      ),
    try: async () => {
      // oxlint-disable-next-line eslint/no-bitwise -- Combine OS open flags to refuse symlinks.
      const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);

      try {
        const stat = await file.stat();

        if (
          !stat.isFile() ||
          // oxlint-disable-next-line eslint/no-bitwise -- Only the POSIX mode bits participate in the permission check.
          (stat.mode & 0o7777) !== 0o600 ||
          stat.uid !== process.getuid?.()
        ) {
          throw new Error("unsafe pass file");
        }

        return await file.readFile("utf-8");
      } finally {
        await file.close();
      }
    },
  });

export interface CurrentPass {
  readonly pass: string;
  readonly run: string;
  readonly ticket: string | undefined;
}

export const readPassFile = Effect.fn("Client.readPassFile")(
  function* readPassFile(path: string, identityDid: string, run?: string) {
    const text = yield* readOwned(path);

    const version = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(Version)
    )(text).pipe(
      Effect.mapError(() =>
        refused(
          "SC_PASS_FILE is not JSON",
          "The worker runtime writes the pass file as one JSON object."
        )
      )
    );

    if (version.v !== 1) {
      return yield* refused(
        "SC_PASS_FILE has an unknown version",
        "This sc reads pass file version 1 only, and will not guess at another shape.",
        "Run an sc that matches the worker runtime, or check the worker's blocked item in its desk queue."
      );
    }

    const file = yield* Schema.decodeUnknownEffect(
      Schema.fromJsonString(PassFile),
      { onExcessProperty: "error" }
    )(text).pipe(
      Effect.mapError(() =>
        refused(
          "SC_PASS_FILE does not match the version 1 shape",
          "Version 1 is exactly {v, pass, ticket?, run, workerDid, renewedAt}, with a signed pass and an optional signed name ticket."
        )
      )
    );

    const { pass, ticket } = file;

    if (file.workerDid !== pass.record.worker) {
      return yield* refused(
        "SC_PASS_FILE workerDid does not match its pass",
        "The pass was issued to a different worker key than the file names."
      );
    }

    if (
      file.run !== pass.record.run ||
      (run !== undefined && run !== file.run)
    ) {
      return yield* refused(
        "SC_PASS_FILE run does not match its pass",
        "The file's run label, its pass and this sc process must all name the same run."
      );
    }

    if (identityDid !== file.workerDid) {
      return yield* refused(
        "SC_IDENTITY_JSON does not hold this pass's worker key",
        "The request would be signed by a key the pass was not issued to.",
        "Run sc with the SC_IDENTITY_JSON the worker runtime gave this run."
      );
    }

    if (
      ticket !== undefined &&
      (ticket.record.name !== pass.record.desk ||
        ticket.record.did !== pass.record.deskDid)
    ) {
      return yield* refused(
        "SC_PASS_FILE ticket names another desk",
        "The name ticket's name and DID must equal the pass's desk and deskDid.",
        "Check the worker's blocked item in its desk queue; the runtime must pair the pass with its own desk's ticket."
      );
    }

    const now = Math.floor((yield* Clock.currentTimeMillis) / 1000);

    if (pass.record.exp - now < staleSeconds) {
      return yield* passStale("worker pass");
    }

    if (ticket !== undefined && ticket.record.exp - now < staleSeconds) {
      return yield* passStale("name ticket");
    }

    const current: CurrentPass = {
      pass: yield* Schema.encodeEffect(Schema.fromJsonString(SignedPass))(
        pass
      ).pipe(Effect.orDie),
      run: file.run,
      ticket:
        ticket === undefined
          ? undefined
          : yield* Schema.encodeEffect(Schema.fromJsonString(SignedTicket))(
              ticket
            ).pipe(Effect.orDie),
    };

    return current;
  }
);
