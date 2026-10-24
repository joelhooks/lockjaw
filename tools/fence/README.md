# Publication fence

The tracked code is intended to be public. Operations and project memory stay private. This fence does not make the repository public or clean its history.

## Commands

- `pnpm fence`: scan tracked working-tree files and nonignored untracked files with the private inventory and generic rules.
- `pnpm fence:check`: typecheck and test this tooling, then scan with generic rules only. No inventory required. Included in `pnpm check`.
- `node tools/fence/red-test.ts`: plant an inventory literal in a scoped temporary file, prove rejection with a redacted diagnostic, then remove the file.
- `pnpm fence:history`: scan every reachable commit, without the temporary tree exclusion. Do not run as part of the public-split packet. The owner prepares fresh public history separately.

Install `gitleaks` on PATH. Missing tools, Git errors and invalid inventory fail closed. Findings report path, line and rule, followed by why and the next action. Matched values and subprocess output never reach diagnostics. A sensitive filename is redacted as well.

## Private inventory

Default: `~/.config/rats-nest/instance.json`. Override with `RATS_NEST_INSTANCE`. Symlinks resolve to a regular file owned by the current user with mode `0600`. The inventory is read only. Generic mode does not access it.

Literal categories include domains, hosts, addresses, sites, secret names, node aliases and fields, and S3 credential-reference names. Whole reserved documentation names and addresses are not private inventory: loopback names, RFC 2606 domains and their subdomains, RFC 5737 addresses and RFC 3849 addresses. Neighboring real-looking literals still fail. Generic email detection permits only reserved domains and the bot commit identity. The agent-secrets prose rule requires a colon or slash, rather than ordinary words following the product name; exact inventory name matching remains enabled.

There are no content/hash exemptions. `tree-exemption.ts` holds one path exclusion, `infra/`, for an operator's private deployment code kept beside the public tree. It applies only to tree mode, not staged or history mode.

## Provenance

Ported from `rat-king/tools/fence` at `ecc773173db0a128fbf064d0bab26eb153ccfc03`, with local tests and redacted file/line diagnostics. The vendored `@rat-king/alchemy-nest` package does not export its inventory schema. `inventory-schema.ts` copies its Effect schema, and `instance.schema.json` copies the upstream JSON Schema with the optional S3 credential-reference fields added to match the Effect schema. Keep both aligned when updating the vendor. Neither contains instance data.
