#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// verify_bundle.mjs — strona ORGANU / niezalezny podmiot. Odtwarza hasze artefaktow
// z manifestu i sprawdza zgodnosc + (opcjonalnie) podpis. Zero zaleznosci. Node >= 18.
//
// Uzycie:
//   node verify_bundle.mjs --manifest bundle_manifest.json --meter <dir> --k0nsult <dir> [--sig f.asc --pub k.asc]
//   node verify_bundle.mjs --selftest    dowod dzialania (pozytywne + NEGATYWNE), exit 0/1
//
// PULAPKA WYWOLANIA: bez --meter/--k0nsult korzenie domyslnie = process.cwd(),
// co daje falszywe "NIEZGODNE/BRAK PLIKU". Zawsze podawaj oba korzenie.
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';

function arg(name, def = null) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

// --- rdzen weryfikacji. Czysta funkcja (poza odczytem artefaktow).
// Zwraca { ok, bad, missing, problems, reBundle, bundleOk, pass }.
export function verifyManifest(M, roots) {
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
  // odtworzenie bundle_sha256 wylacznie z artefaktow PRESENT
  const present = M.artifacts.filter(a => a.status === 'PRESENT').map(a => a.sha256).sort();
  const reBundle = createHash('sha256').update(present.join('\n')).digest('hex');
  const bundleOk = reBundle === M.bundle_sha256;
  return { ok, bad, missing, problems, reBundle, bundleOk, pass: bad === 0 && bundleOk };
}

// ===========================================================================
// SELFTEST — fixtures w tmp, pozytywne + NEGATYWNE (tamper detection)
// ===========================================================================
function runSelftest() {
  const cases = [];
  const check = (name, fn) => { try { fn(); cases.push({ name, ok: true }); } catch (e) { cases.push({ name, ok: false, err: e.message }); } };
  const assert = (c, m) => { if (!c) throw new Error(m || 'assert'); };
  const dirs = [];

  const sha = (s) => createHash('sha256').update(s).digest('hex');
  const mkManifest = (arts) => {
    const present = arts.filter(a => a.status === 'PRESENT').map(a => a.sha256).sort();
    return { schema: 'k0nsult.regulator-evidence-bundle/v1', subject: 'SELFTEST',
             generated_at: '1970-01-01T00:00:00Z', artifacts: arts,
             bundle_sha256: createHash('sha256').update(present.join('\n')).digest('hex'),
             signature: null };
  };

  try {
    const root = mkdtempSync(join(tmpdir(), 'reb-v-')); dirs.push(root);
    writeFileSync(join(root, 'a.txt'), 'alpha');
    writeFileSync(join(root, 'b.txt'), 'beta');
    const roots = { meter: root, k0nsult: root };
    const goodArts = [
      { id: 'A1', repo: 'meter', path: 'a.txt', sha256: sha('alpha'), status: 'PRESENT' },
      { id: 'B1', repo: 'k0nsult', path: 'b.txt', sha256: sha('beta'), status: 'PRESENT' },
    ];

    check('POZYTYW: spojny bundle => pass', () => {
      const r = verifyManifest(mkManifest(goodArts), roots);
      assert(r.pass === true, 'spojny bundle powinien przejsc');
      assert(r.ok === 2 && r.bad === 0, `zle liczniki: ok=${r.ok} bad=${r.bad}`);
      assert(r.bundleOk === true, 'bundle_sha256 powinien sie odtworzyc');
    });

    check('NEGATYW: podmieniona TRESC pliku => wykryte (HASH ROZNI SIE)', () => {
      writeFileSync(join(root, 'a.txt'), 'alpha-PODMIENIONE');
      const r = verifyManifest(mkManifest(goodArts), roots);
      writeFileSync(join(root, 'a.txt'), 'alpha');
      assert(r.pass === false && r.bad === 1, 'podmiana tresci musi byc wykryta');
      assert(r.problems.some(p => /HASH ROZNI SIE/.test(p)), 'brak komunikatu o roznicy hasha');
    });

    check('NEGATYW: usuniety plik => wykryte (BRAK PLIKU)', () => {
      const arts = [...goodArts, { id: 'C1', repo: 'meter', path: 'nie-ma.txt', sha256: sha('x'), status: 'PRESENT' }];
      const r = verifyManifest(mkManifest(arts), roots);
      assert(r.pass === false, 'brak pliku musi oblac weryfikacje');
      assert(r.problems.some(p => /BRAK PLIKU/.test(p)), 'brak komunikatu o braku pliku');
    });

    check('NEGATYW: sfalszowany bundle_sha256 => bundleOk=false', () => {
      const M = mkManifest(goodArts);
      M.bundle_sha256 = 'f'.repeat(64);
      const r = verifyManifest(M, roots);
      assert(r.bundleOk === false && r.pass === false, 'falszywy bundle_sha256 musi byc wykryty');
    });

    check('NEGATYW: artefakt MISSING jest raportowany, nie przemilczany', () => {
      const arts = [...goodArts, { id: 'M1', repo: 'meter', path: 'brak.txt', sha256: null, status: 'MISSING' }];
      const r = verifyManifest(mkManifest(arts), roots);
      assert(r.missing === 1, 'MISSING musi byc policzony');
      assert(r.problems.some(p => /MISSING w manifescie/.test(p)), 'MISSING musi trafic do problemow');
    });

    check('DOKTRYNA: bez --sig weryfikacja NIE twierdzi, ze bundle jest podpisany', () => {
      // pass=true dotyczy wylacznie spojnosci hashy; status podpisu jest raportowany osobno
      const M = mkManifest(goodArts);
      assert(M.signature === null, 'fixture powinien byc niepodpisany');
      const r = verifyManifest(M, roots);
      assert(r.pass === true, 'spojnosc OK');
      assert(!('signatureOk' in r), 'rdzen nie moze udawac weryfikacji podpisu');
    });
  } finally {
    for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
  }

  const passed = cases.filter(c => c.ok).length;
  for (const c of cases) process.stdout.write(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.ok ? '' : '  -> ' + c.err}\n`);
  process.stdout.write(`\nverify_bundle --selftest: ${passed}/${cases.length} PASS, ${cases.length - passed} FAIL\n`);
  process.exit(passed === cases.length ? 0 : 1);
}

// --- CLI -------------------------------------------------------------------
function main() {
  if (process.argv.includes('--selftest')) return runSelftest();

  const manifestPath = arg('manifest', './bundle_manifest.json');
  const roots = { meter: arg('meter', process.cwd()), k0nsult: arg('k0nsult', process.cwd()) };
  const sigPath = arg('sig', null);
  const pubPath = arg('pub', null);

  const M = JSON.parse(readFileSync(isAbsolute(manifestPath) ? manifestPath : join(process.cwd(), manifestPath), 'utf8'));
  const r = verifyManifest(M, roots);

  console.log('─────────────────────────────────────────────');
  console.log('  WERYFIKACJA REGULATOR EVIDENCE BUNDLE');
  console.log('─────────────────────────────────────────────');
  console.log(`  subject:      ${M.subject}`);
  console.log(`  generated_at: ${M.generated_at}`);
  console.log(`  artefakty:    ${r.ok} OK / ${r.bad} NIEZGODNE / ${r.missing} MISSING`);
  console.log(`  bundle_sha256:${r.bundleOk ? ' ZGODNY ✓' : ' NIEZGODNY ✗'}  (${r.reBundle})`);

  // podpis (opcjonalnie, GPG) — weryfikacja, NIGDY skladanie podpisu
  let sigVerdict = 'BRAK PODPISU (bundle = DRAFT)';
  if (sigPath) {
    try {
      if (pubPath) execFileSync('gpg', ['--import', pubPath], { stdio: 'ignore' });
      execFileSync('gpg', ['--verify', sigPath, manifestPath], { stdio: 'inherit' });
      sigVerdict = 'PODPIS OK ✓';
    } catch { sigVerdict = 'PODPIS NIEWAZNY ✗ (lub gpg/klucz niedostepny)'; }
  }
  console.log(`  podpis:       ${sigVerdict}`);

  if (r.problems.length) { console.log('\n  PROBLEMY:'); for (const p of r.problems) console.log('   - ' + p); }

  const pass = r.pass && (!sigPath || sigVerdict.includes('OK'));
  console.log('\n  WYNIK: ' + (pass ? 'BUNDLE SPOJNY ✓' : 'BUNDLE NIESPOJNY / NIEPODPISANY ✗'));
  process.exit(pass ? 0 : 1);
}

main();
