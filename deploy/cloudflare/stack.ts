import { localState, Stack } from "alchemy";
import { dotAlchemyDirectory } from "alchemy/AlchemyContext";
import * as Cloudflare from "alchemy/Cloudflare";
import { Effect, Match, Path } from "effect";
import type { FileSystem } from "effect";

import wrangler from "../../packages/worker/wrangler.json" with { type: "json" };
import { CloudflareRefusal } from "./config.ts";
import type { Inputs } from "./inputs.ts";
import { prepareState, withheldState } from "./state.ts";

export const STACK = "secret-cell-cloudflare";

export const WORKER = "cell";

export const durableObjects = wrangler.durable_objects.bindings;

const sqliteClasses = new Set(
  wrangler.migrations.flatMap((migration) => migration.new_sqlite_classes)
);

const reach = (chosen: Inputs["settings"]["reach"]) =>
  Match.value(chosen).pipe(
    Match.discriminatorsExhaustive("kind")({
      domain: (domain) => ({ domain: domain.name, workersDev: false }),
      route: (route) => ({
        routes: [{ pattern: route.pattern, zoneName: route.zoneName }],
        workersDev: false,
      }),
      "workers.dev": () => ({ workersDev: true }),
    })
  );

const access = (chosen: Inputs["settings"]["access"]) =>
  chosen?.enabled === true
    ? {
        access: {
          policies: [
            {
              decision: "non_identity" as const,
              include: [{ serviceToken: chosen.serviceTokenId }],
            },
          ],
          previews: true,
        },
      }
    : {};

const secrets = (chosen: Inputs) =>
  chosen.kekNext === undefined
    ? { LOCKJAW_KEK: chosen.kek.value }
    : {
        LOCKJAW_KEK: chosen.kek.value,
        LOCKJAW_KEK_NEXT: chosen.kekNext.value,
      };

export const workerProps = (main: string, chosen: Inputs) => ({
  compatibility: { date: wrangler.compatibility_date },
  env: {
    ...Object.fromEntries(
      durableObjects.map((binding) => [
        binding.name,
        Cloudflare.DurableObject(binding.name, {
          className: binding.class_name,
        }),
      ])
    ),
    APPROVER_DID: chosen.settings.approverDid,
    CALLER_DOCUMENTS: JSON.stringify(chosen.settings.callerDocuments),
    CELL_DID: chosen.settings.cellDid,
    SETTERS: JSON.stringify(chosen.settings.setters),
    ...secrets(chosen),
  },
  main,
  name: chosen.settings.workerName,
  ...reach(chosen.settings.reach),
  ...access(chosen.settings.access),
});

const unmigrated = durableObjects.filter(
  (binding) => !sqliteClasses.has(binding.class_name)
);

export const cloudflareStack = <E, R extends FileSystem.FileSystem | Path.Path>(
  load: Effect.Effect<Inputs, E, R>
) =>
  Stack(
    STACK,
    {
      providers: Cloudflare.providers(),
      state: withheldState(localState()),
    },
    Effect.gen(function* secretCellCloudflare() {
      const path = yield* Path.Path;
      const root = path.resolve(import.meta.dirname, "../..");

      yield* prepareState(root, path.resolve(yield* dotAlchemyDirectory));

      if (unmigrated.length > 0) {
        return yield* new CloudflareRefusal({
          next: "Add the class to a new_sqlite_classes migration in packages/worker/wrangler.json, then rerun.",
          what: `Durable Object classes ${unmigrated.map((binding) => binding.class_name).join(", ")} are not SQLite-backed in wrangler.json.`,
          why: "Alchemy creates every new class with SQLite storage, and the cell relies on ctx.storage.sql and transactionSync.",
        });
      }

      const chosen = yield* load;

      const worker = yield* Cloudflare.Worker(
        WORKER,
        workerProps(
          path.resolve(root, "packages/worker", wrangler.main),
          chosen
        )
      );

      return { url: worker.url };
    }).pipe(Effect.orDie)
  );
