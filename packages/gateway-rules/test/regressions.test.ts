import { expect, it } from "@effect/vitest";
import { Policy } from "@lockjaw/domain";
import { Effect, Layer, Redacted, Stream } from "effect";

import { base64 } from "../src/fill.js";
import { EchoRedactor, Fill, Placement } from "../src/index.js";
import {
  credential,
  placeholder,
  policies,
  policy,
  request,
  second,
} from "./fixtures.js";

it.effect(
  "all encoding and outside-location combinations refuse both placeholder grammars",
  () =>
    Effect.gen(function* matrix() {
      const check = yield* Placement;

      const tokens = [
        placeholder,
        `{{secret-basic:username=${credential},password=${second}}}`,
      ];

      for (const token of tokens) {
        const forms = [
          token,
          encodeURIComponent(token),
          encodeURIComponent(encodeURIComponent(token)),
          Array.from(
            new TextEncoder().encode(token),
            (byte) => `%${byte.toString(16)}`
          ).join(""),
          base64(token),
          encodeURIComponent(base64(token)),
        ];

        for (const text of forms) {
          const urls = [
            `https://${text}.example.com/allowed/`,
            `https://${text}@api.example.com/allowed/`,
            `https://api.example.com/allowed/${text}`,
            `https://api.example.com/allowed/?q=${text}`,
          ];

          for (const url of urls) {
            const error = yield* check
              .check({ ...request, url })
              .pipe(Effect.flip);

            expect([
              "PlaceholderOutsideHeader",
              "EncodedPlaceholderRefused",
            ]).toContain(error._tag);
          }

          const error = yield* check
            .check({ ...request, body: `prefix:${text}:suffix` })
            .pipe(Effect.flip);

          expect([
            "PlaceholderOutsideHeader",
            "EncodedPlaceholderRefused",
          ]).toContain(error._tag);
        }
      }
    }).pipe(Effect.provide(Placement.testLayer(policies)))
);

it.effect(
  "byte masking and repeated text redaction cannot reassemble a secret",
  () =>
    Effect.gen(function* noReassembly() {
      const fill = yield* Fill;
      const placement = yield* Placement;
      const echo = yield* EchoRedactor;
      const value = "abcdefgh";

      const filled = yield* fill.apply(
        request,
        yield* placement.check(request),
        () => Effect.succeed(Redacted.make(value))
      );

      const reflected = `abcd${value}efgh`;
      expect(echo.text(filled.redaction, reflected)).toBe("");

      const output = yield* echo
        .stream(
          filled.redaction,
          Stream.fromIterable(
            Array.from(
              new TextEncoder().encode(reflected),
              (byte) => new Uint8Array([byte])
            )
          )
        )
        .pipe(Stream.runCollect);

      const bytes = Uint8Array.from(output.flatMap((chunk) => [...chunk]));
      expect(bytes.length).toBe(reflected.length);
      expect(new TextDecoder().decode(bytes)).not.toContain(value);

      const unicode = "中文中文中文中文";

      const unicodeFill = yield* fill.apply(
        request,
        yield* placement.check(request),
        () => Effect.succeed(Redacted.make(unicode))
      );

      const fragment = new TextEncoder().encode(unicode).slice(1, 9);

      const partial = yield* echo
        .stream(
          unicodeFill.redaction,
          Stream.fromIterable(
            Array.from(fragment, (byte) => new Uint8Array([byte]))
          )
        )
        .pipe(Stream.runCollect);

      expect(partial.flatMap((chunk) => [...chunk])).toEqual(
        Array.from({ length: 8 }, () => 0)
      );
    }).pipe(
      Effect.provide(
        Layer.mergeAll(
          Fill.testLayer,
          Placement.testLayer(policies),
          EchoRedactor.testLayer
        )
      )
    )
);

it.effect(
  "duplicate headers, invalid names, authority overrides and undeclared control headers refuse",
  () =>
    Effect.gen(function* headerBoundary() {
      const placement = yield* Placement;

      const dangerous = [
        [...request.headers, { name: "authorization", value: "public" }],
        [
          ...request.headers,
          { name: "x-sc-resolution", value: "off" },
          { name: "X-SC-RESOLUTION", value: "on" },
        ],
        [{ name: "Authorization\r\nInjected", value: `Bearer ${placeholder}` }],
        [
          {
            name: "Authorization",
            value: `Bearer ${placeholder}\r\nInjected: yes`,
          },
        ],
      ];

      for (const headers of dangerous) {
        expect(
          (yield* placement.check({ ...request, headers }).pipe(Effect.flip))
            ._tag
        ).toBe("PlacementNotAllowed");
      }

      for (const url of [
        "https://user:pass@api.example.com/allowed/path",
        "https://api.example.com:8443/allowed/path",
      ]) {
        expect(
          (yield* placement.check({ ...request, url }).pipe(Effect.flip))._tag
        ).toBe("PlacementNotAllowed");
      }

      const noInject = Policy.make({
        callers: policy.callers,
        hosts: policy.hosts,
        placements: policy.placements,
      });

      const alternate = Placement.testLayer(new Map([[credential, noInject]]));
      yield* Effect.gen(function* controlHeaders() {
        const check = yield* Placement;

        for (const name of [
          "Host",
          "Content-Length",
          "Connection",
          "Transfer-Encoding",
          "Upgrade",
          "x-sc-auth",
          "x-sc-resolution",
        ]) {
          expect(
            (yield* check
              .check({ ...request, headers: [{ name, value: placeholder }] })
              .pipe(Effect.flip))._tag
          ).toBe("PlacementNotAllowed");
        }

        const ambiguous = yield* check
          .check({
            ...request,
            headers: [
              { name: "Authorization", value: `{value}${placeholder}` },
            ],
          })
          .pipe(Effect.flip);

        expect(ambiguous._tag).toBe("PlacementNotAllowed");
      }).pipe(Effect.provide(alternate));
    }).pipe(Effect.provide(Placement.testLayer(policies)))
);

it.effect(
  "Basic fails closed if either credential is missing or has a different host",
  () =>
    Effect.gen(function* basicPolicies() {
      const basicPolicy = Policy.make({
        ...policy,
        inject: { header: "Authorization", template: "Basic {value}" },
      });

      const input = {
        ...request,
        headers: [
          {
            name: "Authorization",
            value: `Basic {{secret-basic:username=${credential},password=${second}}}`,
          },
        ],
      };

      for (const secondPolicy of [
        undefined,
        Policy.make({ ...basicPolicy, hosts: [] }),
      ]) {
        const rows = new Map([[credential, basicPolicy]]);

        if (secondPolicy) {
          rows.set(second, secondPolicy);
        }

        yield* Effect.gen(function* refusal() {
          const placement = yield* Placement;
          const error = yield* placement.check(input).pipe(Effect.flip);
          expect(error.credential).toBe(second);
        }).pipe(Effect.provide(Placement.testLayer(rows)));
      }
    })
);
