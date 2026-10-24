import type { Credential } from "./credential-do.js";
import type { Registry } from "./directory-do.js";
import type { Grants } from "./grants-do.js";
import type { Replay } from "./replay-do.js";

export type RpcStub<T> = {
  readonly [K in keyof T]: T[K] extends (...args: infer A) => infer R
    ? (...args: A) => Promise<Awaited<R>>
    : never;
};

export interface CellId {
  readonly toString: () => string;
}

export interface Namespace<T> {
  readonly idFromName: (name: string) => CellId;
  readonly get: (id: CellId) => RpcStub<T>;
}

export type CredentialMethods = Pick<
  Credential,
  "describe" | "resolve" | "set" | "approve" | "revoke" | "rotate"
>;

export type GrantMethods = Pick<
  Grants,
  "list" | "insert" | "revoke" | "own" | "owner"
>;

export interface Bindings {
  readonly CREDENTIAL: Namespace<CredentialMethods>;
  readonly REGISTRY: Namespace<Pick<Registry, "list" | "register" | "record">>;
  readonly REPLAY: Namespace<Pick<Replay, "consume" | "bind">>;
  readonly GRANTS: Namespace<GrantMethods>;
  readonly SETTERS: string;
  readonly APPROVER_DID: string;
  readonly TICKET_ISSUERS?: string;
}

export const named = <T>(namespace: Namespace<T>, name: string) =>
  namespace.get(namespace.idFromName(name));
