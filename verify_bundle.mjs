#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// verify_bundle.mjs — strona ORGANU / niezalezny podmiot. Odtwarza hasze artefaktow
// z manifestu i sprawdza zgodnosc + (opcjonalnie) podpis. Zero zaleznosci. Node >= 18.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, isAbsolute } from 'node:path';
import { execFileSync } from 'node:child_process';

function arg(name, def = null) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const manifestPath = arg('manifest', './bundle_manifest.json');
const roots = { meter: arg('meter', process.cwd()), k0nsult: arg('k0nsult', process.cwd()) };
const sigPath = arg('sig', null);
const pubPath = arg('pub', null);

const M = JSON.parse(readFileSync(isAbsolute(manifestPath) ? manifestPath : join(process.cwd(), manifestPath), 'utf8'));

let ok = 0, bad = 0, missing = 0;
const problems = [];
for (const a of M.artifacts) {
  if (a.status === 'MISSING') { missing++; problems.push(`MISSING w manifescie: ${a.repo}:${a.path}`); continue; }
  const abs = join(roots[a.repo] || '.', a.path);
  let cur;
  try { cur = createHash('sha256').update(readFileSync(abs)).digest('hex'); }
  catch { bad++; problems.push(`BRAK PLIKU teraz: ${a.repo}:${a.path}`); continue; }
  if (cur === a.sha256) ok++;
  else { bad++; problems.push(`HASH ROZNI SIE: ${a.repo}:${a.path}\n    manifest=${a.sha256}\n    teraz   =${cur}`); }
}

// odtworzenie bundle_sha256
const present = M.artifacts.filter(a => a.status === 'PRESENT').map(a => a.sha256).sort();
const reBundle = createHash('sha256').update(present.join('\n')).digest('hex');
const bundleOk = reBundle === M.bundle_sha256;

console.log('─────────────────────────────────────────────');
console.log('  WERYFIKACJA REGULATOR EVIDENCE BUNDLE');
console.log('─────────────────────────────────────────────');
console.log(`  subject:      ${M.subject}`);
console.log(`  generated_at: ${M.generated_at}`);
console.log(`  artefakty:    ${ok} OK / ${bad} NIEZGODNE / ${missing} MISSING`);
console.log(`  bundle_sha256:${bundleOk ? ' ZGODNY ✓' : ' NIEZGODNY ✗'}  (${reBundle})`);

// podpis (opcjonalnie, GPG)
let sigVerdict = 'BRAK PODPISU (bundle = DRAFT)';
if (sigPath) {
  try {
    if (pubPath) execFileSync('gpg', ['--import', pubPath], { stdio: 'ignore' });
    execFileSync('gpg', ['--verify', sigPath, manifestPath], { stdio: 'inherit' });
    sigVerdict = 'PODPIS OK ✓';
  } catch { sigVerdict = 'PODPIS NIEWAZNY ✗ (lub gpg/klucz niedostepny)'; }
}
console.log(`  podpis:       ${sigVerdict}`);

if (problems.length) { console.log('\n  PROBLEMY:'); for (const p of problems) console.log('   - ' + p); }

const pass = bad === 0 && bundleOk && (!sigPath || sigVerdict.includes('OK'));
console.log('\n  WYNIK: ' + (pass ? 'BUNDLE SPOJNY ✓' : 'BUNDLE NIESPOJNY / NIEPODPISANY ✗'));
process.exit(pass ? 0 : 1);
