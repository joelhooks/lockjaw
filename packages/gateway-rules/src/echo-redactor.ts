import { Context, Effect, Layer, Stream } from "effect";

import type { RedactionPlan } from "./fill.js";

const redactChunk = (
  plan: RedactionPlan,
  pending: Uint8Array,
  incoming: Uint8Array,
  final: boolean,
  range: boolean
): readonly [Uint8Array, Uint8Array] => {
  const bytes = new Uint8Array(pending.length + incoming.length);
  bytes.set(pending);
  bytes.set(incoming, pending.length);
  const output: number[] = [];

  const limit = final
    ? bytes.length
    : Math.max(0, bytes.length - plan.longest + 1);

  let index = 0;

  while (index < limit) {
    const length = plan.matchAt(bytes, index);

    if (length > 0) {
      if (range) {
        for (let count = 0; count < length; count += 1) {
          output.push(0);
        }
      }

      index += length;
    } else {
      const byte = bytes[index];

      if (byte !== undefined) {
        output.push(byte);
      }

      index += 1;
    }
  }

  return [bytes.slice(index), new Uint8Array(output)];
};

export const redactText = (plan: RedactionPlan, text: string): string => {
  let current = text;

  for (;;) {
    const [, bytes] = redactChunk(
      plan,
      new Uint8Array(),
      new TextEncoder().encode(current),
      true,
      false
    );

    const next = new TextDecoder().decode(bytes);

    if (next === current) {
      return next;
    }

    current = next;
  }
};

export const redactStream = <E, R>(
  plan: RedactionPlan,
  source: Stream.Stream<Uint8Array, E, R>
): Stream.Stream<Uint8Array, E, R> =>
  source.pipe(
    Stream.map((bytes) => ({ bytes, final: false })),
    Stream.concat(Stream.make({ bytes: new Uint8Array(), final: true })),
    Stream.mapAccum(
      (): Uint8Array => new Uint8Array(),
      (pending, chunk) => {
        const [next, output] = redactChunk(
          plan,
          pending,
          chunk.bytes,
          chunk.final,
          true
        );

        return [next, [output]];
      }
    )
  );

export interface EchoResponse<E, R> {
  readonly headers: readonly {
    readonly name: string;
    readonly value: string;
  }[];
  readonly status: number;
  readonly statusText: string;
  readonly url: string;
  readonly body: Stream.Stream<Uint8Array, E, R>;
}

export const redactResponse = <E, R>(
  plan: RedactionPlan,
  response: EchoResponse<E, R>
): EchoResponse<E, R> => ({
  body: redactStream(plan, response.body),
  headers: response.headers.flatMap((header) =>
    header.name.toLowerCase() === "content-length"
      ? []
      : [
          {
            name: redactText(plan, header.name),
            value: redactText(plan, header.value),
          },
        ]
  ),
  status: response.status,
  statusText: redactText(plan, response.statusText),
  url: redactText(plan, response.url),
});

export const redactError = (plan: RedactionPlan, error: Error): Error =>
  new Error(redactText(plan, error.message));

export class EchoRedactor extends Context.Service<
  EchoRedactor,
  {
    readonly text: typeof redactText;
    readonly stream: typeof redactStream;
    readonly response: typeof redactResponse;
    readonly error: typeof redactError;
  }
>()("secret-cell/EchoRedactor") {
  static readonly layer = Layer.effect(
    EchoRedactor,
    Effect.succeed(
      EchoRedactor.of({
        error: redactError,
        response: redactResponse,
        stream: redactStream,
        text: redactText,
      })
    )
  );
  static readonly testLayer = Layer.succeed(
    EchoRedactor,
    EchoRedactor.of({
      error: redactError,
      response: redactResponse,
      stream: redactStream,
      text: redactText,
    })
  );
}
