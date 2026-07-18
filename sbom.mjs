#!/usr/bin/env node
// sbom.mjs — generator SBOM (CycloneDX-lite JSON) dla powierzchni open-source K0NSULT.
// Zero zależności (tylko wbudowane node: fs, path, crypto).
// Enumeruje: strona/*.html (top-level), strona/model_map/*.json, wykryte moduły *.mjs/*.js
//            oraz zależności node z package.json (jeśli są, poza node_modules).
//
// Uzycie:
//   node sbom.mjs                       # domyslny root (repo METER PIASKOWNICA)
//   node sbom.mjs --root "/sciezka/do/repo"
//   node sbom.mjs --out sbom.json       # domyslnie sbom.json obok skryptu
//
// Disjoint: skrypt CZYTA repo (read-only) i PISZE wylacznie sbom.json w folderze opensource/.

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// --- argumenty ---
const argv = process.argv.slice(2);
function argVal(flag, def) {
  const i = argv.indexOf(flag);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : def;
}
// Default to the current working directory; override with --root <path>.
const DEFAULT_ROOT = process.cwd();
const ROOT = path.resolve(argVal('--root', DEFAULT_ROOT));
const OUT = path.resolve(argVal('--out', path.join(__dirname, 'sbom.json')));

// --- helpers ---
function sha256(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}
function listFiles(dir, { recursive = false, ext = null } = {}) {
  const out = [];
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (recursive && entry.name !== 'node_modules') {
        out.push(...listFiles(full, { recursive, ext }));
      }
    } else if (entry.isFile()) {
      if (!ext || ext.some((e) => entry.name.toLowerCase().endsWith(e))) out.push(full);
    }
  }
  return out;
}
function relPosix(p) {
  return path.relative(ROOT, p).split(path.sep).join('/');
}
function bomRef(prefix, rel) {
  return `${prefix}:${rel}`;
}

// --- 1) enumeracja powierzchni plikowych ---
const components = [];
const surfaces = [
  { dir: path.join(ROOT, 'strona'), recursive: false, ext: ['.html'], group: 'strona', type: 'file' },
  { dir: path.join(ROOT, 'strona', 'model_map'), recursive: false, ext: ['.json'], group: 'strona/model_map', type: 'data' },
  { dir: path.join(ROOT, 'strona', 'model_map'), recursive: false, ext: ['.mjs', '.js'], group: 'strona/model_map', type: 'file' },
];

for (const s of surfaces) {
  for (const f of listFiles(s.dir, { recursive: s.recursive, ext: s.ext })) {
    const buf = fs.readFileSync(f);
    const rel = relPosix(f);
    components.push({
      type: s.type,                 // CycloneDX component type: file | data | library
      'bom-ref': bomRef('surface', rel),
      name: path.basename(f),
      group: s.group,
      version: '1.0.0',
      scope: 'required',
      hashes: [{ alg: 'SHA-256', content: sha256(buf) }],
      properties: [
        { name: 'k0nsult:path', value: rel },
        { name: 'k0nsult:bytes', value: String(buf.length) },
        { name: 'k0nsult:surface', value: 'open-source' },
      ],
    });
  }
}

// --- 2) wykryte zaleznosci node z package.json (poza node_modules) ---
const nodeDeps = [];
function scanPackageJsons(dir, depth = 0) {
  if (depth > 6 || !fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanPackageJsons(full, depth + 1);
    } else if (entry.name === 'package.json') {
      try {
        const pkg = JSON.parse(fs.readFileSync(full, 'utf8'));
        const rel = relPosix(full);
        for (const field of ['dependencies', 'devDependencies']) {
          for (const [dep, range] of Object.entries(pkg[field] || {})) {
            nodeDeps.push({
              type: 'library',
              'bom-ref': bomRef('npm', `${dep}@${range}`),
              name: dep,
              version: String(range),
              scope: field === 'devDependencies' ? 'optional' : 'required',
              purl: `pkg:npm/${dep}@${String(range).replace(/^[\^~]/, '')}`,
              properties: [
                { name: 'k0nsult:declared_in', value: rel },
                { name: 'k0nsult:dep_field', value: field },
              ],
            });
          }
        }
      } catch { /* ignore malformed */ }
    }
  }
}
scanPackageJsons(ROOT);
components.push(...nodeDeps);

// --- 3) montaz dokumentu CycloneDX-lite ---
const now = new Date().toISOString();
const bom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  '$profile': 'cyclonedx-lite (podzbior: bez services/vulnerabilities/compositions)',
  serialNumber: `urn:uuid:${crypto.randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: now,
    tools: [{ vendor: 'K0NSULT', name: 'sbom.mjs', version: '1.0.0' }],
    component: {
      type: 'application',
      'bom-ref': 'k0nsult-opensource-surface',
      name: 'K0NSULT open-source surface (ai-truth / uni0nai / ipIII)',
      version: '1.0.0',
    },
    properties: [
      { name: 'k0nsult:root', value: ROOT.split(path.sep).join('/') },
      { name: 'k0nsult:scope', value: 'strona/*.html + strona/model_map/*.json + moduly + node deps' },
      { name: 'k0nsult:license_proposed', value: 'Apache-2.0 (patrz LICENSE.proposed)' },
    ],
  },
  components,
};

// --- 4) statystyki + zapis ---
const stats = {
  total: components.length,
  files_html: components.filter((c) => c.group === 'strona').length,
  data_json: components.filter((c) => c.group === 'strona/model_map' && c.type === 'data').length,
  modules_js: components.filter((c) => c.group === 'strona/model_map' && c.type === 'file').length,
  node_libraries: nodeDeps.length,
};
bom.metadata.properties.push({ name: 'k0nsult:stats', value: JSON.stringify(stats) });

fs.writeFileSync(OUT, JSON.stringify(bom, null, 2) + '\n');

console.log('SBOM napisany:', OUT);
console.log('root:', ROOT);
console.log('komponenty:', stats.total,
  `(html=${stats.files_html}, data_json=${stats.data_json}, modules=${stats.modules_js}, node_libs=${stats.node_libraries})`);
