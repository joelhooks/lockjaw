import {
  createEffectActor,
  fromEffect,
  setupEffect,
  send,
  waitFor,
} from "@xstate/effect";
import type { EffectActor } from "@xstate/effect";
import { Context, Effect, Schema } from "effect";
import { types } from "xstate";

import { LifecycleSnapshot } from "./credential-store.js";
import type { State } from "./credential-store.js";

export type RefreshResult = "ok" | "invalid_grant" | "retryable";

export class LifecycleWork extends Context.Service<
  LifecycleWork,
  {
    readonly persist: (state: State, revision: number) => Effect.Effect<void>;
    readonly refresh: () => Effect.Effect<RefreshResult>;
  }
>()("secret-cell/LifecycleWork") {}

interface MachineContext {
  readonly restored: State;
  readonly recoveryAttempt: number;
  readonly revision: number;
  readonly ready: boolean;
}

export interface LifecycleEvent {
  readonly type:
    | "AUTH_FAILED"
    | "SET_VALUE"
    | "REFRESH_DUE"
    | "ROTATE_BEGIN"
    | "ROTATE_COMMIT"
    | "ROTATE_ABORT"
    | "EXPIRE"
    | "REVOKE";
}

const persist = fromEffect({
  effect: ({ input }) =>
    LifecycleWork.use((work) => work.persist(input.state, input.revision)),
  schemas: { input: types<{ state: State; revision: number }>() },
});

const refresh = fromEffect({
  effect: ({ input }) =>
    LifecycleWork.use((work) =>
      Effect.gen(function* effect() {
        yield* work.persist("refreshing", input.revision);

        return yield* work.refresh();
      })
    ),
  schemas: { input: types<{ revision: number }>() },
});

const next = (context: MachineContext) => ({
  ready: false,
  revision: context.revision + 1,
});

const persisted = (state: State) => ({
  input: ({ context }: { context: MachineContext }) => ({
    revision: context.revision,
    state,
  }),
  onDone: { context: { ready: true } },
  src: "persist" as const,
});

export const lifecycleMachine = setupEffect({
  actors: { persist, refresh },
  schemas: {
    context: types<MachineContext>(),
    events: {
      AUTH_FAILED: Schema.Struct({}),
      EXPIRE: Schema.Struct({}),
      REFRESH_DUE: Schema.Struct({}),
      REVOKE: Schema.Struct({}),
      ROTATE_ABORT: Schema.Struct({}),
      ROTATE_BEGIN: Schema.Struct({}),
      ROTATE_COMMIT: Schema.Struct({}),
      SET_VALUE: Schema.Struct({}),
    },
    input: LifecycleSnapshot,
  },
}).createMachine({
  context: ({ input }) => ({
    ready: false,
    recoveryAttempt:
      input.state === "refreshing" ? (input.recoveryAttempt ?? 0) + 1 : 0,
    restored: input.state,
    revision: input.revision,
  }),
  initial: "restoring",
  on: {
    REVOKE: ({ context }) => ({ context: next(context), target: ".revoked" }),
  },
  states: {
    active: {
      invoke: persisted("active"),
      on: {
        AUTH_FAILED: ({ context }) => ({
          context: next(context),
          target: "needsAuth",
        }),
        EXPIRE: ({ context }) => ({
          context: next(context),
          target: "expired",
        }),
        REFRESH_DUE: ({ context }) => ({
          context: next(context),
          target: "refreshing",
        }),
        ROTATE_BEGIN: ({ context }) => ({
          context: next(context),
          target: "rotating",
        }),
        SET_VALUE: ({ context }) => ({
          context: next(context),
          reenter: true,
          target: "active",
        }),
      },
    },
    empty: {
      invoke: persisted("empty"),
      on: {
        SET_VALUE: ({ context }) => ({
          context: next(context),
          target: "active",
        }),
      },
    },
    expired: {
      invoke: persisted("expired"),
      on: {
        SET_VALUE: ({ context }) => ({
          context: next(context),
          target: "active",
        }),
      },
    },
    needsAuth: {
      invoke: persisted("needsAuth"),
      on: {
        SET_VALUE: ({ context }) => ({
          context: next(context),
          target: "active",
        }),
      },
    },
    refreshing: {
      invoke: {
        input: ({ context }) => ({ revision: context.revision }),
        onDone: ({ context, event }) => ({
          context: { ...next(context), recoveryAttempt: 0 },
          target:
            event.output === "invalid_grant" ||
            (context.recoveryAttempt > 0 && event.output !== "ok")
              ? "needsAuth"
              : "active",
        }),
        src: "refresh",
      },
      on: {
        EXPIRE: ({ context }) => ({
          context: next(context),
          target: "expired",
        }),
      },
    },
    restoring: {
      always: ({ context }) => ({
        target:
          context.restored === "refreshing" && context.recoveryAttempt > 1
            ? "needsAuth"
            : context.restored,
      }),
    },
    revoked: { invoke: persisted("revoked"), on: { REVOKE: {} } },
    rotating: {
      invoke: persisted("rotating"),
      on: {
        AUTH_FAILED: ({ context }) => ({
          context: next(context),
          target: "needsAuth",
        }),
        EXPIRE: ({ context }) => ({
          context: next(context),
          target: "expired",
        }),
        ROTATE_ABORT: ({ context }) => ({
          context: next(context),
          target: "active",
        }),
        ROTATE_COMMIT: ({ context }) => ({
          context: next(context),
          target: "active",
        }),
      },
    },
  },
});

export const startLifecycle = Effect.fn("Lifecycle.start")(
  function* startLifecycleOperation(
    input: LifecycleSnapshot,
    installed: (
      actor: EffectActor<typeof lifecycleMachine>
    ) => Effect.Effect<void>
  ) {
    // oxlint-disable-next-line rat-stack-patterns/watch-effect-actors -- No devtools dependency in this core. Every actor outcome is observed by waitFor; invocation failures become defects, never ignored.
    const actor = yield* createEffectActor(lifecycleMachine, { input });

    const settled = () =>
      waitFor(actor, (snapshot) => snapshot.context.ready).pipe(Effect.orDie);

    yield* installed(actor);
    yield* settled();

    return {
      actor,
      send: (event: LifecycleEvent) => send(actor, event),
      settled,
    };
  }
);
