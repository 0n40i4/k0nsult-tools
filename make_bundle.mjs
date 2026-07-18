#!/usr/bin/env node
// make_bundle.mjs — buduje kanoniczny Regulator Evidence Bundle (REB).
// GRANICA: NIE podpisuje. NIE dotyka kluczy. Liczy SHA-256 + kanoniczny manifest.
// Podpis sklada operator wlasnym kluczem (No Password Custody, Human Override).
// Zero zaleznosci. Node >= 18.
import { readFileSync, writeFileSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, isAbsolute } from 'node:path';

function arg(name, def = null) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

const meterRoot   = arg('meter',   process.cwd());
const k0nsultRoot = arg('k0nsult', process.cwd());
const outPath     = arg('out',     './bundle_manifest.json');
const srcPath     = arg('sources', './bundle_sources.json');

const roots = { meter: meterRoot, k0nsult: k0nsultRoot };

function sha256File(abs) {
  const buf = readFileSync(abs);
  return { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
}

// kanoniczna serializacja: rekurencyjne sortowanie kluczy -> deterministyczny JSON
function canonical(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  if (obj && typeof obj === 'object') {
    return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
  }
  return JSON.stringify(obj);
}

const sources = JSON.parse(readFileSync(isAbsolute(srcPath) ? srcPath : join(process.cwd(), srcPath), 'utf8'));

const artifacts = [];
let missing = 0;
for (const s of sources.artifacts) {
  const root = roots[s.repo];
  if (!root) { console.error(`[REB] nieznane repo: ${s.repo} (${s.id})`); process.exit(2); }
  const abs = join(root, s.path);
  const rec = { id: s.id, repo: s.repo, path: s.path.replace(/\\/g, '/'),
                claim: s.claim, proof_status: s.proof_status, art: s.art };
  try {
    const h = sha256File(abs);
    rec.sha256 = h.sha256; rec.bytes = h.bytes; rec.status = 'PRESENT';
  } catch {
    rec.sha256 = null; rec.bytes = 0; rec.status = 'MISSING'; missing++;
    console.error(`[REB] BRAK: ${s.repo}:${s.path} (${s.id}) — oznaczam MISSING (jawnie, evidence-first)`);
  }
  artifacts.push(rec);
}

// bundle_sha256 = hash posortowanych (sha256 obecnych artefaktow). MISSING nie wchodzi do hasha,
// ale jest widoczny w manifescie jako luka.
const present = artifacts.filter(a => a.status === 'PRESENT').map(a => a.sha256).sort();
const bundleSha = createHash('sha256').update(present.join('\n')).digest('hex');

const manifest = {
  schema: 'k0nsult.regulator-evidence-bundle/v1',
  subject: sources.subject,
  generated_at: new Date().toISOString(),
  doctrine: ['claim<=proof', 'Human Override Always', 'art.50', 'No Password Custody',
             'agents-not-people', 'zero scoringu osob', 'evidence-first'],
  counts: { total: artifacts.length, present: present.length, missing },
  artifacts,
  bundle_sha256: bundleSha,
  signature: null,
  signature_note: 'DRAFT do czasu podpisu operatora wlasnym kluczem (detached). Ten kod NIE podpisuje.',
};

writeFileSync(isAbsolute(outPath) ? outPath : join(process.cwd(), outPath),
              JSON.stringify(manifest, null, 2) + '\n', 'utf8');

// kontrolna suma kanoniczna (do niezaleznego odtworzenia)
const canonSha = createHash('sha256').update(canonical({ ...manifest, generated_at: 'IGNORED', signature: null })).digest('hex');

console.log('─────────────────────────────────────────────');
console.log('  REGULATOR EVIDENCE BUNDLE — manifest zbudowany');
console.log('─────────────────────────────────────────────');
console.log(`  artefakty:      ${present.length} PRESENT / ${missing} MISSING / ${artifacts.length} total`);
console.log(`  bundle_sha256:  ${bundleSha}`);
console.log(`  canon_sha256:   ${canonSha}  (niezalezny od timestampu/podpisu)`);
console.log(`  zapis:          ${outPath}`);
if (missing) console.log(`  UWAGA: ${missing} artefakt(ow) MISSING — luka jawna w manifescie (status: MISSING).`);
console.log('');
console.log('  NASTEPNY KROK (operator, wlasny klucz — No Password Custody):');
console.log(`    gpg --armor --detach-sign --output ${outPath}.asc ${outPath}`);
console.log(`    # lub: openssl dgst -sha256 -sign privkey.pem -out ${outPath}.sig ${outPath}`);
console.log(`    # lub: cosign sign-blob --yes ${outPath} --output-signature ${outPath}.sig`);
console.log('  Bez podpisu operatora bundle pozostaje DRAFT (nie dowod).');
