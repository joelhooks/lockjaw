import { it } from "@effect/vitest";
import { Celld, HostShell } from "@rat-king/alchemy-nest";
import type { DeploymentProps } from "@rat-king/alchemy-nest";
import { noopSession } from "alchemy/Report";
import { Effect, Exit, Layer } from "effect";
import { HttpClient, HttpClientResponse } from "effect/http";
import { expect } from "vitest";

const forbidden = () => Effect.die(new Error("OFFLINE_DELETE_REFUSED"));

const props: DeploymentProps = {
  binary: "/home/example/.local/share/lockjaw/bin/celld",
  bindingsFile: "/home/example/.config/lockjaw/worker-bindings.json",
  bundle: "export default {};",
  commit: "example-commit",
  configuration: JSON.stringify({
    compatibility_date: "2026-01-01",
    compatibility_flags: [],
    durable_objects: { bindings: [] },
    main: "worker.mjs",
    migrations: [],
    name: "example-lockjaw",
    no_bundle: true,
    vars: {},
  }),
  directory: "/home/example/.config/lockjaw/deploy",
  environmentFile: "/home/example/.config/lockjaw/celld.env",
  internalUrl: "http://127.0.0.1:32001",
  secretNames: ["LOCKJAW_KEK"],
  version: "example-version",
  workerUrl: "http://192.0.2.10:32000",
};

it.effect(
  "fake host deploy uses private bindings, reloads, and verifies version and commit at the operator URL",
  () =>
    Effect.gen(function* readback() {
      const files = new Map<string, Uint8Array>();
      const directories = new Set<string>();
      const calls: (readonly string[])[] = [];
      const requests: string[] = [];

      const shell: HostShell["Service"] = {
        exec: (argv) =>
          Effect.sync(() => {
            calls.push(argv);

            return { code: 0, stdout: "" };
          }),
        mkdir: ({ path }) =>
          Effect.sync(() => {
            directories.add(path);
          }),
        purgeRoots: [],
        read: (path) => Effect.succeed(files.get(path)),
        remove: forbidden,
        rmdir: forbidden,
        stat: (path) => {
          if (directories.has(path)) {
            return Effect.succeed({ kind: "directory" as const, mode: 0o700 });
          }

          return Effect.succeed(
            files.has(path) ? { kind: "file" as const, mode: 0o600 } : undefined
          );
        },
        write: ({ path, bytes, mode }) =>
          Effect.sync(() => {
            expect(mode).toBe(0o600);
            files.set(path, bytes);
          }),
      };

      let identity = { commit: props.commit, version: props.version };

      const http = HttpClient.make((request) =>
        Effect.sync(() => {
          requests.push(request.url);

          return HttpClientResponse.fromWeb(request, Response.json(identity));
        })
      );

      yield* Effect.gen(function* exercise() {
        const provider = yield* Celld.Deployment.Provider;

        const args = {
          bindings: [],
          fqn: "deployment",
          id: "deployment",
          instanceId: "example",
          news: props,
          olds: undefined,
          output: undefined,
          session: { ...noopSession, note: () => Effect.void },
        };

        const reconcile: (
          input: Parameters<typeof provider.reconcile>[0]
        ) => Effect.Effect<
          DeploymentProps & { readonly sha256: string },
          Error
        > = provider.reconcile.bind(provider);

        const deployed = yield* reconcile(args).pipe(Effect.orDie);

        expect(requests).toEqual([
          `${props.workerUrl}/.well-known/rat-king/version`,
        ]);
        expect(calls.map((argv) => argv[0])).toEqual(["python3", "sh", "curl"]);
        expect(calls[0]?.[2]).toContain("LOCKJAW_KEK");
        expect(calls[2]).toContain("http://127.0.0.1:32001/reload");
        expect(files.has(`${props.directory}/wrangler.public.json`)).toBe(true);
        expect(files.has(`${props.directory}/wrangler.json`)).toBe(false);

        if (provider.read === undefined) {
          return yield* Effect.die(new Error("Missing deployment read port"));
        }

        identity = { commit: "foreign-commit", version: props.version };

        const read: (
          input: Parameters<NonNullable<typeof provider.read>>[0]
        ) => Effect.Effect<
          (DeploymentProps & { readonly sha256: string }) | undefined,
          Error
        > = provider.read.bind(provider);

        const mismatch = yield* read({
          fqn: "deployment",
          id: "deployment",
          instanceId: "example",
          olds: props,
          output: deployed,
        }).pipe(Effect.exit);

        expect(mismatch).toSatisfy(Exit.isFailure);

        return yield* Effect.void;
      }).pipe(
        Effect.provide(
          Celld.deploymentProvider().pipe(
            Layer.provide(Layer.succeed(HostShell, shell)),
            Layer.provide(Layer.succeed(HttpClient.HttpClient, http))
          )
        )
      );
    })
);
