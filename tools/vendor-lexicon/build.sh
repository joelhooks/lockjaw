#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
source_repo="${RAT_KING_SOURCE:?Set RAT_KING_SOURCE to the public rat-king checkout}"
revision=6c1e5d8
work="$(mktemp -d "$root/vendor-build.XXXXXX")"
trap 'rm -r "$work"' EXIT
mkdir -p "$root/vendor" "$work/source" "$work/package"
git -C "$source_repo" archive "$revision" packages/lexicon | tar -xf - -C "$work/source" --strip-components=2
mkdir "$work/source/node_modules"
ln -s "$root/packages/worker/node_modules/@atproto" "$work/source/node_modules/@atproto"
ln -s "$root/packages/worker/node_modules/@ipld" "$work/source/node_modules/@ipld"
ln -s "$root/node_modules/effect" "$work/source/node_modules/effect"
ln -s "$root/node_modules/@types" "$work/source/node_modules/@types"
node --input-type=module - "$work" <<'JS'
import { readFileSync, writeFileSync } from 'node:fs';
const work = process.argv[2];
const pkg = JSON.parse(readFileSync(`${work}/source/package.json`, 'utf8'));
for (const [name, version] of Object.entries({'@ipld/dag-cbor':'10.0.2','@atproto/lex-data':'0.1.8','@atproto/lexicon':'0.7.16'})) {
  if (pkg.dependencies[name] !== version) throw new Error(`Dependency pin changed: ${name}`);
}
pkg.private = false;
for (const name of Object.keys(pkg.exports)) pkg.exports[name] = pkg.exports[name].replace(/\.ts$/, '.js');
pkg.files = ['*.js', '*.d.ts', 'src', 'adapters', 'PASSES.md', 'README.md'];
writeFileSync(`${work}/package/package.json`, `${JSON.stringify(pkg, null, 2)}\n`);
writeFileSync(`${work}/source/tsconfig.json`, JSON.stringify({compilerOptions:{target:'ES2023',module:'NodeNext',moduleResolution:'NodeNext',strict:true,noUncheckedIndexedAccess:true,exactOptionalPropertyTypes:true,skipLibCheck:true,declaration:true,rewriteRelativeImportExtensions:true,outDir:'../package',types:['node']},include:['*.ts','src/**/*.ts','adapters/**/*.ts']}));
JS
"$root/node_modules/.bin/tsc" -p "$work/source/tsconfig.json"
node --input-type=module - "$work/package" <<'JS'
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const rewrite = (dir) => {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) rewrite(path);
    else if (entry.name.endsWith('.d.ts')) writeFileSync(path, readFileSync(path, 'utf8').replace(/(["'])(\.{1,2}\/[^"']+)\.ts\1/g, '$1$2.js$1'));
  }
};
rewrite(process.argv[2]);
JS
cp "$work/source/PASSES.md" "$work/source/README.md" "$work/package/"
(cd "$work/package" && npm pack --ignore-scripts --pack-destination "$work" >/dev/null 2>&1)
cp "$work/rat-king-lexicon-0.1.0.tgz" "$root/vendor/rat-king-lexicon-$revision.tgz"
sha="$(shasum -a 256 "$root/vendor/rat-king-lexicon-$revision.tgz" | cut -d ' ' -f 1)"
source_sha="$(git -C "$source_repo" rev-parse "$revision^{commit}")"
printf '{\n  "source": "rat-king/packages/lexicon",\n  "commit": "%s",\n  "tarball": "rat-king-lexicon-%s.tgz",\n  "sha256": "%s"\n}\n' "$source_sha" "$revision" "$sha" > "$root/vendor/rat-king-lexicon.lock.json"
printf '%s\n' "$sha"
