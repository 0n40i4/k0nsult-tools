#!/usr/bin/env node
// sbom.mjs — generator SBOM (CycloneDX-lite JSON) dla powierzchni open-source K0NSULT.
// Zero zależności (tylko wbudowane node: fs, path, crypto).
// Enumeruje: KAZDY plik pod --root (rekurencyjnie, poza .git i node_modules),
//            kazdy pliniowany SHA-256; plus zaleznosci node z package.json (jesli sa).
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
// Relative repo name only — never leak the absolute host path (OS/user/dir layout, CWE-200).
const REPO_NAME = path.basename(ROOT);

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
      if (recursive && entry.name !== 'node_modules' && entry.name !== '.git') {
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

// --- 1) enumeracja WSZYSTKICH plikow pod ROOT (rekurencyjnie) ---
const components = [];

function classify(rel) {
  const l = rel.toLowerCase();
  if (l.endsWith('.html') || l.endsWith('.htm')) return { type: 'file', group: 'html' };
  if (l.endsWith('.json')) return { type: 'data', group: 'data' };
  if (l.endsWith('.mjs') || l.endsWith('.js') || l.endsWith('.ts')) return { type: 'file', group: 'code' };
  return { type: 'file', group: 'other' };
}

for (const f of listFiles(ROOT, { recursive: true })) {
  if (path.resolve(f) === OUT) continue;        // nie inwentaryzuj wlasnego outputu
  const buf = fs.readFileSync(f);
  const rel = relPosix(f);
  const { type, group } = classify(rel);
  components.push({
    type,                           // CycloneDX component type: file | data
    'bom-ref': bomRef('surface', rel),
    name: path.basename(f),
    group,
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
      'bom-ref': REPO_NAME,
      name: REPO_NAME,
      version: '1.0.0',
      // Pole SPDX licenses (CycloneDX): identyfikator z listy SPDX, bez wiszacych wskaznikow.
      licenses: [{ license: { id: 'Apache-2.0' } }],
    },
    properties: [
      { name: 'k0nsult:repo', value: REPO_NAME },
      { name: 'k0nsult:scope', value: 'all files under root (recursive, excl. .git/node_modules) + node deps' },
      { name: 'k0nsult:license', value: 'Apache-2.0' },
    ],
  },
  components,
};

// --- 4) statystyki + zapis ---
const stats = {
  total: components.length,
  files_html: components.filter((c) => c.group === 'html').length,
  data_json: components.filter((c) => c.group === 'data').length,
  code_files: components.filter((c) => c.group === 'code').length,
  other_files: components.filter((c) => c.group === 'other').length,
  node_libraries: nodeDeps.length,
};
bom.metadata.properties.push({ name: 'k0nsult:stats', value: JSON.stringify(stats) });

fs.writeFileSync(OUT, JSON.stringify(bom, null, 2) + '\n');

console.log('SBOM napisany:', OUT);
console.log('root:', ROOT);
console.log('komponenty:', stats.total,
  `(html=${stats.files_html}, data=${stats.data_json}, code=${stats.code_files}, other=${stats.other_files}, node_libs=${stats.node_libraries})`);
