#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
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
// Heurystyka git-like: NUL w pierwszych 8000 bajtach => plik binarny.
function isBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}
// Normalizacja do postaci, jaką daje ŚWIEŻY KLON z `.gitattributes * text=auto
// eol=lf`: pliki tekstowe CRLF->LF, binarne bez zmian. Dzięki temu hash w SBOM
// == `sha256sum` pliku po `git clone` niezależnie od EOL working-tree audytora
// (naprawa audytu roxkon/RSpace issue #1 HIGH: 23 hashe nie do odtworzenia).
function contentForHash(buf) {
  if (isBinary(buf)) return buf;
  return Buffer.from(buf.toString('latin1').replace(/\r\n/g, '\n'), 'latin1');
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
function classify(rel) {
  const l = rel.toLowerCase();
  if (l.endsWith('.html') || l.endsWith('.htm')) return { type: 'file', group: 'html' };
  if (l.endsWith('.json')) return { type: 'data', group: 'data' };
  if (l.endsWith('.mjs') || l.endsWith('.js') || l.endsWith('.ts')) return { type: 'file', group: 'code' };
  return { type: 'file', group: 'other' };
}

function buildFileComponents() {
  const components = [];
  for (const f of listFiles(ROOT, { recursive: true })) {
    if (path.resolve(f) === OUT) continue;        // nie inwentaryzuj wlasnego outputu
    const raw = fs.readFileSync(f);
    const buf = contentForHash(raw);              // CRLF->LF (jak swiezy klon eol=lf)
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
        { name: 'k0nsult:bytes', value: String(buf.length) },  // dlugosc po LF-normalizacji
        { name: 'k0nsult:eol', value: isBinary(raw) ? 'binary' : 'lf-normalized' },
        { name: 'k0nsult:surface', value: 'open-source' },
      ],
    });
  }
  return components;
}

// --- 2) wykryte zaleznosci node z package.json (poza node_modules) ---
function scanPackageJsons(dir, nodeDeps, depth = 0) {
  if (depth > 6 || !fs.existsSync(dir)) return;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      scanPackageJsons(full, nodeDeps, depth + 1);
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

function buildComponents() {
  const files = buildFileComponents();
  const nodeDeps = [];
  scanPackageJsons(ROOT, nodeDeps);
  return { components: [...files, ...nodeDeps], nodeDeps };
}

// --- 3) montaz dokumentu CycloneDX-lite ---
function buildBom() {
  const { components, nodeDeps } = buildComponents();
  const bom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    '$profile': 'cyclonedx-lite (podzbior: bez services/vulnerabilities/compositions)',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      tools: [{ vendor: 'K0NSULT', name: 'sbom.mjs', version: '1.1.0' }],
      component: {
        type: 'application',
        'bom-ref': REPO_NAME,
        name: REPO_NAME,
        version: '1.0.0',
        licenses: [{ license: { id: 'Apache-2.0' } }],
      },
      properties: [
        { name: 'k0nsult:repo', value: REPO_NAME },
        { name: 'k0nsult:scope', value: 'all files under root (recursive, excl. .git/node_modules) + node deps' },
        { name: 'k0nsult:hash_basis', value: 'lf-normalized text (matches fresh clone with .gitattributes eol=lf); binary raw' },
        { name: 'k0nsult:license', value: 'Apache-2.0' },
      ],
    },
    components,
  };
  const stats = {
    total: components.length,
    files_html: components.filter((c) => c.group === 'html').length,
    data_json: components.filter((c) => c.group === 'data').length,
    code_files: components.filter((c) => c.group === 'code').length,
    other_files: components.filter((c) => c.group === 'other').length,
    node_libraries: nodeDeps.length,
  };
  bom.metadata.properties.push({ name: 'k0nsult:stats', value: JSON.stringify(stats) });
  return { bom, stats };
}

// --- 4) tryby: generate (domyslny) | --verify (recompute -> exact match) ---
function generate() {
  const { bom, stats } = buildBom();
  fs.writeFileSync(OUT, JSON.stringify(bom, null, 2) + '\n');
  console.log('SBOM napisany:', OUT);
  console.log('root:', ROOT);
  console.log('komponenty:', stats.total,
    `(html=${stats.files_html}, data=${stats.data_json}, code=${stats.code_files}, other=${stats.other_files}, node_libs=${stats.node_libraries})`);
}

// --verify: przelicz hashe plikow i porownaj z istniejacym sbom.json. To jest
// dokladnie test audytora: "recompute -> exact match". exit(1) przy rozjezdzie.
function verify() {
  if (!fs.existsSync(OUT)) { console.error('BRAK', OUT, '- najpierw wygeneruj.'); process.exit(2); }
  const existing = JSON.parse(fs.readFileSync(OUT, 'utf8'));
  const want = new Map();
  for (const c of existing.components || []) {
    if (c.hashes && c.hashes[0]) want.set(c['bom-ref'], c.hashes[0].content);
  }
  const fresh = buildFileComponents();
  let mismatch = 0, missing = 0, checked = 0;
  for (const c of fresh) {
    const ref = c['bom-ref'];
    if (!want.has(ref)) { missing++; console.error('NOWY (brak w sbom):', ref); continue; }
    checked++;
    if (want.get(ref) !== c.hashes[0].content) {
      mismatch++;
      console.error('NIEZGODNY hash:', ref);
    }
  }
  console.log(`verify: sprawdzono ${checked}, NIEZGODNE=${mismatch}, brakujace-w-sbom=${missing}`);
  if (mismatch === 0 && missing === 0) { console.log('✓ recompute -> exact match'); process.exit(0); }
  process.exit(1);
}

if (argv.includes('--verify')) verify();
else generate();
