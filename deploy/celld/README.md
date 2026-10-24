# Lockjaw on celld (Alchemy)

Deploys the Lockjaw Worker, its four SQLite Durable Object classes, a celld node and an operator-owned object store onto an existing Linux host. **Status: compiled and tested offline, not deployed or live-proven.** Exports and checks do not deploy anything.

You bring the host and its celld prerequisites. See [denoland/celld](https://github.com/denoland/celld). This layer does not provision a VM, container, DNS, TLS termination, firewall or KEK service. The Alchemy provider installs its pinned celld and object-store binaries and declares user-systemd units, storage directories and the Worker deployment. Use a dedicated non-root Linux user with working user-systemd, SSH host-key verification, Python 3 and curl.

## Trust boundary

The operator holds the KEK, the host and the storage. No cloud provider is added to the decryption boundary. Anyone who controls that host or the KEK service can decrypt credentials. This is not protection against a host administrator.

The [Cloudflare layer](../cloudflare/README.md) instead gives Cloudflare both the Worker-secret KEK and the encrypted Durable Object storage. Both layers run the same Worker authorization and envelope-encryption code. Choose who you trust with the runtime and keys, not just where you put the encrypted bytes.

**Known limit:** Worker `fetch()` has no connect-time private-address floor in celld today. Lockjaw refuses IP-literal and internal names at the app layer. That does not pin DNS answers or stop a public hostname from resolving to a private address. Add an egress firewall on the host. This layer does not install one.

## Operator config

Copy [config.example.json](config.example.json) to `~/.config/lockjaw/celld.json`, outside the checkout, and set mode 0600. `LOCKJAW_CELLD_CONFIG` selects another file. The file is validated with Effect Schema. Refusals have What, Why and Next fields; validation errors name fields, not values.

Every value in the example is a placeholder. The address `192.0.2.10` is RFC 5737 documentation space. Replace the example host, paths, bucket, DIDs and public verification key with your own. Keep private keys out of `callerDocuments`. Only public DID documents belong there. The example key is a public test key, not an operator identity.

| Field | Meaning |
| --- | --- |
| `host.ssh` | SSH destination, for example `example@celld.example.com`; no built-in aliases |
| `host.home` | Existing Linux user's home, for example `/home/example` |
| `host.dataRoot` | Existing host's shared/default data root, for example `/srv/example-shared` |
| `host.tailnetIPv4` | Provider field for the Worker's listener IPv4; it need not be a tailnet address |
| `instance`, `portBase` | Isolated lowercase instance name and ten-port block; example `lockjaw`, `32000` |
| `dataRoot` | Dedicated instance storage, disjoint from `host.dataRoot` and configuration/binary roots |
| `bucket` | Operator-owned bucket name, for example `example-lockjaw-cells` |
| `credentials` | Environment variable names for the object store's access and secret keys |
| `workerName` | Worker script name, for example `example-lockjaw` |
| `workerUrl` | Origin reachable from the deploy machine for version readback, for example `http://192.0.2.10:32000` |
| `approverDid`, `cellDid`, `callerDocuments`, `setters` | Worker authority and public caller configuration |
| `kek` | One of the two modes below |

The provider also checks instance isolation and its reserved listeners when acquiring the host. The public listener is `portBase`, the host-only reload listener is `portBase + 1`, and the object store uses the remaining ports. Restrict network access and terminate TLS before exposing a production endpoint. `workerUrl` may be your HTTPS origin; it must not contain credentials, a path, query or fragment.

### KEK binding mode

```json
{
  "kind": "binding",
  "kek": "EXAMPLE_LOCKJAW_KEK",
  "kekNext": "EXAMPLE_LOCKJAW_KEK_NEXT"
}
```

Each named environment variable contains JSON `{"kekId":"operator-chosen-id","key":"<base64url of 32 bytes>"}`. Omit `kekNext` when not rotating. The two IDs must differ. The Worker receives these as `LOCKJAW_KEK` and optional `LOCKJAW_KEK_NEXT`.

### KEK URL mode

```json
{
  "kind": "url",
  "url": "http://127.0.0.1:32100/kek",
  "access": "EXAMPLE_KEK_ACCESS"
}
```

The operator supplies the host-local KEK service. The Worker's existing contract permits only exactly `http://127.0.0.1:<port>/kek`, with an explicit port from 1 to 65535. HTTPS, remote hosts, other paths, queries, fragments and user information are refused. Config validation uses the Worker's own KEK selector. The URL becomes `KEK_URL`; the named environment variable becomes the private `KEK_ACCESS` bearer binding. No KEK service or key-custody arrangement is created or verified by this layer. See the [Worker's KEK contract](../../packages/worker/README.md).

### Secret handling and state

Inject all named variables from your secret manager for one command. The object-store access and secret keys are required too. This stack resolves names from that process environment, not from a fleet secret service.

Secret references, not their values, enter the resource graph. The provider writes private host files with mode 0600. `worker-bindings.json` supplies only the selected KEK binding names. Deployment generates a private `wrangler.json` on the host; Alchemy holds only `wrangler.public.json`. A binding-content revision changes the deployment configuration so a key rotation triggers a reload.

`state.ts` shares the Cloudflare layer's state withholding and external-directory checks. State must resolve outside the checkout and its directory is mode 0700. Keep that state private: it still names your host, paths and public callers. Host files, runtime memory and the operator secret manager are inside the trust boundary.

## Deployment entry point

Alchemy is pinned to `2.0.0-beta.83`, Effect to `4.0.5`, and `@rat-king/alchemy-nest` to the public Git commit `fd780e4d14dd8e5707959a6809d4f702d8cdf43b`, subdirectory `packages/alchemy-nest`. There is no vendored alchemy-nest tarball.

Review the config and the Alchemy plan before using the deploy command. Run from an external private state directory. `REPO` is the checkout path; the example environment file contains your secret-manager references, not secret values.

```sh
cd "$REPO" && pnpm install --frozen-lockfile
install -d -m 700 "$HOME/.local/state/lockjaw/celld"
cd "$HOME/.local/state/lockjaw/celld"
umask 077
op run --env-file="$HOME/.config/lockjaw/celld.env" -- \
  "$REPO/deploy/celld/node_modules/.bin/alchemy" deploy \
  "$REPO/deploy/celld/alchemy.run.ts" --stage prod
```

The deployment bundles `worker.ts` with the source Git commit and the compatibility date, Durable Object declarations and migrations from `packages/worker/wrangler.json`. It reloads celld through the host's loopback operator listener. The provider checks `GET /.well-known/rat-king/version` at `workerUrl` and requires both `commit` and `version` to match the bundle. That path name is the provider's version-readback contract.

Data resources use `purgeOnDelete: false`. This is not a backup or recovery guarantee. Review any destroy plan separately; do not assume removing a runtime leaves a working or recoverable cell.

## Offline checks

```sh
pnpm --filter @lockjaw/celld typecheck
pnpm --filter @lockjaw/celld typecheck:tsc
pnpm --filter @lockjaw/celld test
```

Tests compile and bundle the real graph with a host shell that refuses all operations. A separate fake host and fake HTTP client exercise deployment commands, selected private bindings and version readback, including a mismatched commit. No live account, host or KEK endpoint is contacted.
