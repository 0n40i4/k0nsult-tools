#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// make_bundle.mjs — buduje kanoniczny Regulator Evidence Bundle (REB).
// GRANICA: NIE podpisuje. NIE dotyka kluczy. Liczy SHA-256 + kanoniczny manifest.
// Podpis sklada operator wlasnym kluczem (No Password Custody, Human Override).
// Zero zaleznosci. Node >= 18.
//
// Uzycie:
//   node make_bundle.mjs --sources bundle_sources.json --meter <dir> --k0nsult <dir> [--out manifest.json]
//   node make_bundle.mjs --selftest     dowod dzialania (pozytywne + NEGATYWNE), exit 0/1
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, isAbsolute } from 'node:path';
import { tmpdir } from 'node:os';

function arg(name, def = null) {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}

function sha256File(abs) {
  const buf = readFileSync(abs);
  return { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
}

// kanoniczna serializacja: rekurencyjne sortowanie kluczy -> deterministyczny JSON
export function canonical(obj) {
  if (Array.isArray(obj)) return '[' + obj.map(canonical).join(',') + ']';
  if (obj && typeof obj === 'object') {
    return '{' + Object.keys(obj).sort().map(k => JSON.stringify(k) + ':' + canonical(obj[k])).join(',') + '}';
  }
  return JSON.stringify(obj);
}

// --- rdzen: buduje manifest z deklaracji zrodel. Czysta funkcja (poza odczytem plikow).
// Zwraca { manifest, canonSha }. NIGDY nie podpisuje: signature zawsze null.
export function buildManifest(sources, roots, { quiet = false } = {}) {
  const artifacts = [];
  let missing = 0;
  for (const s of sources.artifacts) {
    const root = roots[s.repo];
    if (!root) throw new Error(`nieznane repo: ${s.repo} (${s.id})`);
    const abs = join(root, s.path);
    const rec = { id: s.id, repo: s.repo, path: s.path.replace(/\\/g, '/'),
                  claim: s.claim, proof_status: s.proof_status, art: s.art };
    try {
      const h = sha256File(abs);
      rec.sha256 = h.sha256; rec.bytes = h.bytes; rec.status = 'PRESENT';
    } catch {
      rec.sha256 = null; rec.bytes = 0; rec.status = 'MISSING'; missing++;
      if (!quiet) console.error(`[REB] BRAK: ${s.repo}:${s.path} (${s.id}) — oznaczam MISSING (jawnie, evidence-first)`);
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
  // kontrolna suma kanoniczna (do niezaleznego odtworzenia) — niezalezna od timestampu/podpisu
  const canonSha = createHash('sha256')
    .update(canonical({ ...manifest, generated_at: 'IGNORED', signature: null })).digest('hex');
  return { manifest, canonSha };
}

// ===========================================================================
// SELFTEST — fixtures w tmp, pozytywne + NEGATYWNE. Zero plikow zewnetrznych.
// ===========================================================================
function runSelftest() {
  const cases = [];
  const check = (name, fn) => { try { fn(); cases.push({ name, ok: true }); } catch (e) { cases.push({ name, ok: false, err: e.message }); } };
  const assert = (c, m) => { if (!c) throw new Error(m || 'assert'); };
  const dirs = [];
  const mk = () => { const d = mkdtempSync(join(tmpdir(), 'reb-')); dirs.push(d); return d; };

  try {
    const root = mk();
    writeFileSync(join(root, 'a.txt'), 'alpha');
    writeFileSync(join(root, 'b.txt'), 'beta');
    const roots = { meter: root, k0nsult: root };
    const src = { subject: 'SELFTEST', artifacts: [
      { id: 'A1', repo: 'meter', path: 'a.txt', claim: 'c', proof_status: 'DOWOD', art: '50' },
      { id: 'B1', repo: 'k0nsult', path: 'b.txt', claim: 'c', proof_status: 'DOWOD', art: '50' },
    ] };

    check('POZYTYW: hashe artefaktow + liczniki', () => {
      const { manifest } = buildManifest(src, roots, { quiet: true });
      assert(manifest.counts.total === 2 && manifest.counts.present === 2, 'zle liczniki');
      const a = manifest.artifacts.find(x => x.id === 'A1');
      const want = createHash('sha256').update('alpha').digest('hex');
      assert(a.sha256 === want, 'zly sha256 artefaktu');
      assert(a.status === 'PRESENT', 'status powinien byc PRESENT');
    });

    check('DOKTRYNA: signature ZAWSZE null (narzedzie nigdy nie podpisuje)', () => {
      const { manifest } = buildManifest(src, roots, { quiet: true });
      assert(manifest.signature === null, 'signature musi byc null — No Password Custody');
      assert(/DRAFT/.test(manifest.signature_note), 'brak adnotacji DRAFT');
    });

    check('POZYTYW: bundle_sha256 deterministyczny (te same wejscia => ten sam hash)', () => {
      const h1 = buildManifest(src, roots, { quiet: true }).manifest.bundle_sha256;
      const h2 = buildManifest(src, roots, { quiet: true }).manifest.bundle_sha256;
      assert(h1 === h2, 'bundle_sha256 niedeterministyczny');
    });

    check('POZYTYW: canon_sha256 niezalezny od timestampu', () => {
      const c1 = buildManifest(src, roots, { quiet: true }).canonSha;
      const c2 = buildManifest(src, roots, { quiet: true }).canonSha;
      assert(c1 === c2, 'canon_sha256 zalezy od czasu — a nie powinien');
    });

    check('NEGATYW: brakujacy plik => MISSING, jawnie, i NIE wchodzi do bundle_sha256', () => {
      const src2 = { subject: 'S', artifacts: [
        ...src.artifacts,
        { id: 'X1', repo: 'meter', path: 'nie-ma-mnie.txt', claim: 'c', proof_status: 'GAP', art: '50' },
      ] };
      const { manifest } = buildManifest(src2, roots, { quiet: true });
      const x = manifest.artifacts.find(a => a.id === 'X1');
      assert(x.status === 'MISSING' && x.sha256 === null, 'brak pliku musi dac MISSING/null');
      assert(manifest.counts.missing === 1, 'licznik missing');
      // hash liczony tylko z obecnych => identyczny jak bez brakujacego
      assert(manifest.bundle_sha256 === buildManifest(src, roots, { quiet: true }).manifest.bundle_sha256,
        'MISSING nie moze zmieniac bundle_sha256');
    });

    check('NEGATYW: zmiana tresci pliku zmienia bundle_sha256 (tamper-evident)', () => {
      const before = buildManifest(src, roots, { quiet: true }).manifest.bundle_sha256;
      writeFileSync(join(root, 'a.txt'), 'alpha-ZMIENIONE');
      const after = buildManifest(src, roots, { quiet: true }).manifest.bundle_sha256;
      writeFileSync(join(root, 'a.txt'), 'alpha'); // przywroc
      assert(before !== after, 'podmiana pliku MUSI zmienic bundle_sha256');
    });

    check('NEGATYW: nieznane repo => blad (nie cicha akceptacja)', () => {
      const bad = { subject: 'S', artifacts: [{ id: 'Z', repo: 'nieistnieje', path: 'a.txt' }] };
      let threw = false;
      try { buildManifest(bad, roots, { quiet: true }); } catch { threw = true; }
      assert(threw, 'nieznane repo musi rzucic blad');
    });

    check('POZYTYW: canonical() niezalezny od kolejnosci kluczy', () => {
      assert(canonical({ b: 1, a: [2, { y: 1, x: 0 }] }) === canonical({ a: [2, { x: 0, y: 1 }], b: 1 }),
        'canonical nie jest kanoniczny');
    });
  } finally {
    for (const d of dirs) { try { rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } }
  }

  const passed = cases.filter(c => c.ok).length;
  for (const c of cases) process.stdout.write(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.ok ? '' : '  -> ' + c.err}\n`);
  process.stdout.write(`\nmake_bundle --selftest: ${passed}/${cases.length} PASS, ${cases.length - passed} FAIL\n`);
  process.exit(passed === cases.length ? 0 : 1);
}

// --- CLI -------------------------------------------------------------------
function main() {
  if (process.argv.includes('--selftest')) return runSelftest();

  const meterRoot   = arg('meter',   process.cwd());
  const k0nsultRoot = arg('k0nsult', process.cwd());
  const outPath     = arg('out',     './bundle_manifest.json');
  const srcPath     = arg('sources', './bundle_sources.json');
  const roots = { meter: meterRoot, k0nsult: k0nsultRoot };

  const sources = JSON.parse(readFileSync(isAbsolute(srcPath) ? srcPath : join(process.cwd(), srcPath), 'utf8'));

  let built;
  try { built = buildManifest(sources, roots); }
  catch (e) { console.error(`[REB] ${e.message}`); process.exit(2); }
  const { manifest, canonSha } = built;

  writeFileSync(isAbsolute(outPath) ? outPath : join(process.cwd(), outPath),
                JSON.stringify(manifest, null, 2) + '\n', 'utf8');

  console.log('─────────────────────────────────────────────');
  console.log('  REGULATOR EVIDENCE BUNDLE — manifest zbudowany');
  console.log('─────────────────────────────────────────────');
  console.log(`  artefakty:      ${manifest.counts.present} PRESENT / ${manifest.counts.missing} MISSING / ${manifest.counts.total} total`);
  console.log(`  bundle_sha256:  ${manifest.bundle_sha256}`);
  console.log(`  canon_sha256:   ${canonSha}  (niezalezny od timestampu/podpisu)`);
  console.log(`  zapis:          ${outPath}`);
  if (manifest.counts.missing) console.log(`  UWAGA: ${manifest.counts.missing} artefakt(ow) MISSING — luka jawna w manifescie (status: MISSING).`);
  console.log('');
  console.log('  NASTEPNY KROK (operator, wlasny klucz — No Password Custody):');
  console.log(`    gpg --armor --detach-sign --output ${outPath}.asc ${outPath}`);
  console.log(`    # lub: openssl dgst -sha256 -sign privkey.pem -out ${outPath}.sig ${outPath}`);
  console.log('  Bez podpisu operatora bundle pozostaje DRAFT (nie dowod).');
}

main();
