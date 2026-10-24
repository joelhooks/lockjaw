import {
  encodeState,
  REDACTED_MARKER,
  State,
  StateStoreError,
} from "alchemy/State";
import type { StateService } from "alchemy/State";
import {
  Effect,
  FileSystem,
  Layer,
  Path,
  Predicate,
  Redacted,
  Schema,
} from "effect";

export const WITHHELD = "withheld-by-secret-cell";

const refuse = () =>
  Effect.die(new Error("Alchemy state must resolve outside the repository."));

export const prepareState = Effect.fn("SecretCell.prepareCloudflareState")(
  function* prepareState(root: string, directory: string) {
    const fs = yield* FileSystem.FileSystem;
    const path = yield* Path.Path;
    const repository = yield* fs.realPath(root);
    const target = path.resolve(directory);

    const inside = (location: string) =>
      location === repository || location.startsWith(`${repository}/`);

    if (inside(target)) {
      return yield* refuse();
    }

    let ancestor = target;

    while (!(yield* fs.exists(ancestor))) {
      ancestor = path.dirname(ancestor);
    }

    if (inside(yield* fs.realPath(ancestor))) {
      return yield* refuse();
    }

    yield* fs.makeDirectory(target, { mode: 0o700, recursive: true });
    const resolved = yield* fs.realPath(target);

    if (inside(resolved)) {
      return yield* refuse();
    }

    yield* fs.chmod(resolved, 0o700);

    return resolved;
  }
);

const SecretText = Schema.Struct({
  text: Schema.Unknown,
  type: Schema.Literal("secret_text"),
});

const isSecretText = Schema.is(SecretText);

const isList = Schema.is(Schema.Array(Schema.Unknown));

const isRecord = Schema.is(Schema.Record(Schema.String, Schema.Unknown));

// oxlint-disable-next-line anti-slop/no-unknown-parameters, anti-slop/no-unknown-returns -- Alchemy persists untyped state trees; this walk only replaces secret leaves.
const withheldTree = (value: unknown): unknown => {
  if (Redacted.isRedacted(value)) {
    return Redacted.make(WITHHELD);
  }

  if (isList(value)) {
    return value.map((entry) => withheldTree(entry));
  }

  if (!isRecord(value)) {
    return value;
  }

  const prototype: unknown = Object.getPrototypeOf(value);

  if (prototype !== Object.prototype && prototype !== null) {
    return value;
  }

  const copy = Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, withheldTree(entry)])
  );

  return isSecretText(value) ? { ...copy, text: WITHHELD } : copy;
};

export const withhold = <A>(value: A) =>
  // SAFETY: the walk keeps every key and array slot; only secret leaves change.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- The engine's record type is opaque here; the shape is preserved.
  withheldTree(value) as A;

// oxlint-disable-next-line anti-slop/no-unknown-parameters -- Scans the encoded, untyped state tree before it is written.
const leaks = (value: unknown): boolean => {
  if (isList(value)) {
    return value.some((entry) => leaks(entry));
  }

  if (!Predicate.isObject(value)) {
    return false;
  }

  if (
    Predicate.hasProperty(value, REDACTED_MARKER) &&
    value[REDACTED_MARKER] !== WITHHELD
  ) {
    return true;
  }

  if (isSecretText(value) && value.text !== WITHHELD) {
    return true;
  }

  return Object.values(value).some((entry) => leaks(entry));
};

const persistable = Effect.fnUntraced(function* persistable<A>(value: A) {
  const withheld = withhold(value);

  if (leaks(encodeState(withheld))) {
    return yield* new StateStoreError({
      message:
        "What: Alchemy tried to persist a secret value. Why: secret-cell keeps KEK material out of Alchemy state, and this value escaped the withholding walk. Next: Report the resource type to the secret-cell desk; nothing was written.",
    });
  }

  return withheld;
});

const decorate = (service: StateService): StateService => ({
  ...service,
  set: (request) =>
    persistable(request.value).pipe(
      Effect.flatMap((value) => service.set({ ...request, value })),
      Effect.as(request.value)
    ),
  setOutput: (request) =>
    persistable(request.value).pipe(
      Effect.flatMap((value) => service.setOutput({ ...request, value })),
      Effect.as(request.value)
    ),
});

export const withheldState = <E, R>(inner: Layer.Layer<State, E, R>) =>
  Layer.effect(
    State,
    Effect.service(State).pipe(
      Effect.map((service) => service.pipe(Effect.map(decorate)))
    )
  ).pipe(Layer.provide(inner));
