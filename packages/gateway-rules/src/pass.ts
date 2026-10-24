import { NamePattern } from "@lockjaw/domain";
import type { Op } from "@lockjaw/domain";
import { Schema } from "effect";

import { nameMatches } from "./patterns.js";

export const passLifetimeSeconds = 600;

export const passSkewSeconds = 60;

const passable = new Set([
  "sh.secretcell.fetch",
  "sh.secretcell.describe",
  "sh.secretcell.list",
]);

const brokerLxm =
  /^sh\.secretcell\.broker\.[a-z0-9][a-z0-9-]{0,62}$(?![\s\S])/u;

export interface PassEntry {
  readonly lxm: string;
  readonly pattern?: string;
}

export const passableLxm = (lxm: string): boolean =>
  passable.has(lxm) || brokerLxm.test(lxm);

const parseEntry = (text: string): PassEntry | undefined => {
  const colon = text.indexOf(":");
  const lxm = colon === -1 ? text : text.slice(0, colon);

  if (!passableLxm(lxm)) {
    return undefined;
  }

  if (colon === -1) {
    return { lxm };
  }

  const pattern = text.slice(colon + 1);

  return pattern !== "*" && Schema.is(NamePattern)(pattern)
    ? { lxm, pattern }
    : undefined;
};

export const parsePassScope = (
  entries: readonly string[]
): readonly PassEntry[] | undefined => {
  const parsed: PassEntry[] = [];

  for (const text of entries) {
    const entry = parseEntry(text);

    if (entry === undefined) {
      return undefined;
    }

    parsed.push(entry);
  }

  return parsed.length > 0 ? parsed : undefined;
};

export const lxmFor = (op: Op): string =>
  `sh.secretcell.${op === "use" ? "fetch" : op}`;

export const passAllows = (
  entries: readonly string[],
  lxm: string,
  credential?: string
): boolean =>
  (parsePassScope(entries) ?? []).some(
    (entry) =>
      entry.lxm === lxm &&
      (entry.pattern === undefined ||
        (credential !== undefined && nameMatches(entry.pattern, credential)))
  );
