// Tiny dependency-only bundler for the panel Worker.
// No third-party bundler is available in this offline environment, and the
// module graph here is small and entirely first-party, so a purpose-built
// bundler is simpler and easier to audit than vendoring one.
//
// Rules this bundler relies on (true for every file under panel/src):
//   - only `import { a, b } from './x.js'`, `import * as ns from './x.js'`,
//     or external imports like `import { connect } from 'cloudflare:sockets'`
//   - only `export const/function/class NAME` or `export default {...}` (entry only)
//   - no re-exports, no dynamic import()
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
// Usage: node scripts/bundle-worker.mjs [entryFile] [outFile]
// Defaults to bundling the panel Worker, for `npm run build` and CI.
const entry = resolve(here, '..', process.argv[2] || 'panel/src/worker.js');
const srcDir = dirname(entry);

const IMPORT_LINE = /^import\s+(.+?)\s+from\s+['"](.+?)['"];?\s*$/gm;
const EXPORT_CONST = /^export\s+const\s+([A-Za-z_$][\w$]*)/;
const EXPORT_FN = /^export\s+(async\s+function|function)\s+([A-Za-z_$][\w$]*)/;
const EXPORT_DEFAULT = /^export\s+default\s+/;

function varNameFor(path) {
  return '__mod_' + path.replace(/[^A-Za-z0-9]/g, '_');
}

function transform(source, filePath, isEntry) {
  const externalImports = [];
  const exportedNames = [];
  let body = source.replace(IMPORT_LINE, (line, clause, spec) => {
    if (!spec.startsWith('.')) {
      externalImports.push(line.trim());
      return '';
    }
    const depPath = resolve(dirname(filePath), spec);
    const depVar = varNameFor(depPath);
    clause = clause.trim();
    if (clause.startsWith('* as ')) {
      const alias = clause.slice(5).trim();
      return `const ${alias} = ${depVar};`;
    }
    if (clause.startsWith('{') && clause.endsWith('}')) {
      const names = clause.slice(1, -1).trim();
      return `const { ${names} } = ${depVar};`;
    }
    throw new Error(`Unsupported import clause "${clause}" in ${filePath}`);
  });

  body = body
    .split('\n')
    .map((line) => {
      if (EXPORT_DEFAULT.test(line)) {
        if (!isEntry) throw new Error(`export default only expected in the entry file (${filePath})`);
        return line.replace(EXPORT_DEFAULT, 'export default ');
      }
      let m = EXPORT_CONST.exec(line);
      if (m) { exportedNames.push(m[1]); return line.replace(/^export\s+/, ''); }
      m = EXPORT_FN.exec(line);
      if (m) { exportedNames.push(m[2]); return line.replace(/^export\s+/, ''); }
      return line;
    })
    .join('\n');

  return { body: body.trim(), externalImports, exportedNames, path: filePath };
}

function collect(filePath, seen, order) {
  if (seen.has(filePath)) return;
  seen.add(filePath);
  const source = readFileSync(filePath, 'utf8');
  const isEntry = filePath === entry;
  const result = transform(source, filePath, isEntry);
  let m;
  IMPORT_LINE.lastIndex = 0;
  while ((m = IMPORT_LINE.exec(source))) {
    const spec = m[2];
    if (spec.startsWith('.')) collect(resolve(dirname(filePath), spec), seen, order);
  }
  order.push(result);
}

function bundle() {
  const order = [];
  collect(entry, new Set(), order);

  const externals = new Set();
  for (const mod of order) for (const line of mod.externalImports) externals.add(line);

  const chunks = [...externals, ''];
  for (const mod of order) {
    if (mod.path === entry) continue;
    const varName = varNameFor(mod.path);
    const exportsObj = mod.exportedNames.map((n) => `${n}`).join(', ');
    chunks.push(
      `const ${varName} = (() => {`,
      mod.body,
      `  return { ${exportsObj} };`,
      `})();`,
      ''
    );
  }
  const entryMod = order.find((m) => m.path === entry);
  chunks.push(`// ---- ${entry.replace(srcDir + '/', '')} ----`, entryMod.body);

  return chunks.join('\n');
}

const out = bundle();
const outDir = resolve(here, '../dist');
mkdirSync(outDir, { recursive: true });
const outPath = resolve(here, '..', process.argv[3] || 'dist/worker.js');
mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, out);
console.log(`bundled ${outPath} (${(out.length / 1024).toFixed(1)} KB, ${out.split('\n').length} lines)`);
