import { CredentialName, Host } from "@lockjaw/domain";
import type { Caller, Operation, Policy as Grants } from "@lockjaw/domain";
import { Policy } from "@lockjaw/gateway-rules";
import { Layer, Redacted } from "effect";

import { Credential } from "../src/credential.js";
import type { SetMetadata } from "../src/credential.js";
import { Keyring } from "../src/keyring.js";
import { NodeSqlite, nodeStoreLayer } from "../src/node-sqlite.js";
import { Refresher } from "../src/refresher.js";

export const name = CredentialName.make("canary/key");

export const caller: Caller = {
  did: "did:test:caller",
  issuer: "test-host",
  name: "test/agent",
  sid: "session-test",
};

export const op: Operation = {
  credential: name,
  host: "api.example.com",
  method: "GET",
  path: "/allowed/resource",
};

export const grants: Grants = {
  callers: ["test/*"],
  hosts: [Host.make("api.example.com")],
  placements: ["test-host"],
  routes: [{ method: "GET", pathPrefix: "/allowed/" }],
};

export const metadata: SetMetadata = {
  createdAt: 0,
  description: "test fixture",
  expiresAt: null,
  kind: "oauth",
  name,
  owner: "cell",
  policy: grants,
};

export const canary = "SC_CANARY_u5Jt8nQzF0m4Xw2Lk7c6Ap3R9sV1dE";

export const sameValue = Redacted.makeEquivalence(
  (a: string, b: string) => a === b
);

export const storeLayer = nodeStoreLayer.pipe(
  Layer.provideMerge(NodeSqlite.layer)
);

export const dependencies = (refresh = Refresher.testLayer) =>
  Layer.mergeAll(storeLayer, Keyring.testLayer(), Policy.testLayer, refresh);

export const credentialLayer = (refresh = Refresher.testLayer) =>
  Credential.layer(name).pipe(Layer.provideMerge(dependencies(refresh)));
