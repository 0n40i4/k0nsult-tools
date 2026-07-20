#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// procurement-check.mjs
// K0NSULT open commons — procurement acceptance check (offer manifest scoring).
//
// Doktryna:
//   - claim <= proof: narzedzie punktuje TYLKO to, co oferta deklaruje jako weryfikowalne.
//   - silnik ukryty: ZERO kodu k0nsult.cloud, zero sieci, deterministyczne, offline.
//   - agents-not-people: zero PII, zero scoringu osob — oceniamy MANIFEST OFERTY, nie ludzi.
//   - No Password Custody: narzedzie NIE generuje/przechowuje kluczy; brak sekretow.
//
// Zaleznosci: TYLKO wbudowane moduly Node (>=18). Tu nie potrzeba nawet fs/crypto/path —
//   caly wejsciowy manifest przychodzi jako argument --offer (JSON) lub z wbudowanych fixtures.
//
// Model punktacji (implementacja docs/PROCUREMENT-ACCEPTANCE-CHECK.md):
//   SBOM (sbom_hash_rederivable)  => 40 pkt (0 lub 40)
//   patent (patent_grant)         => 30 pkt (0 lub 30)
//   kompletnosc (completeness)    => 20 * completeness  (completeness w [0..1])
//   VEX (vex_present)             => 10 pkt (0 lub 10)
//   total = suma, zakres [0..100]
//   verdict = PASS gdy total >= 70, w przeciwnym razie REJECT.

const WEIGHTS = Object.freeze({ sbom: 40, patent: 30, completeness: 20, vex: 10 });
const PASS_THRESHOLD = 70;

// ---------------------------------------------------------------------------
// Walidacja + normalizacja manifestu oferty.
// Deterministyczna, bez rzutowan "na sile": zle typy => blad (nie ciche 0).
// ---------------------------------------------------------------------------
function toBool(value, field) {
  if (typeof value === 'boolean') return value;
  if (value === undefined || value === null) return false; // brak deklaracji = brak dowodu
  throw new Error(`Pole "${field}" musi byc boolean (albo pominiete), otrzymano: ${JSON.stringify(value)}`);
}

function toCompleteness(value) {
  if (value === undefined || value === null) return 0;
  if (typeof value !== 'number' || Number.isNaN(value)) {
    throw new Error(`Pole "completeness" musi byc liczba w [0..1], otrzymano: ${JSON.stringify(value)}`);
  }
  if (value < 0 || value > 1) {
    throw new Error(`Pole "completeness" poza zakresem [0..1]: ${value}`);
  }
  return value;
}

function normalizeOffer(raw) {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('Oferta (--offer) musi byc obiektem JSON.');
  }
  return {
    sbom_hash_rederivable: toBool(raw.sbom_hash_rederivable, 'sbom_hash_rederivable'),
    patent_grant: toBool(raw.patent_grant, 'patent_grant'),
    completeness: toCompleteness(raw.completeness),
    vex_present: toBool(raw.vex_present, 'vex_present'),
  };
}

// ---------------------------------------------------------------------------
// Rdzen punktacji — czysta funkcja (offer -> raport).
// ---------------------------------------------------------------------------
function scoreOffer(rawOffer) {
  const offer = normalizeOffer(rawOffer);

  // Skladniki punktacji liczone DOKLADNIE (bez zaokraglania na tym etapie).
  // Zaokraglenie per-skladnik zawyzalo niepelna kompletnosc (np. 20*0.99975=19.995
  // -> round2 -> 20) i przerzucalo prog. Total i verdict licz z NIEzaokraglonych.
  const raw = {
    sbom: offer.sbom_hash_rederivable ? WEIGHTS.sbom : 0,
    patent: offer.patent_grant ? WEIGHTS.patent : 0,
    completeness: WEIGHTS.completeness * offer.completeness,
    vex: offer.vex_present ? WEIGHTS.vex : 0,
  };

  const rawTotal = raw.sbom + raw.patent + raw.completeness + raw.vex;
  const clamped = Math.max(0, Math.min(100, rawTotal));
  // WERDYKT z NIEzaokraglonego totalu — zaokraglamy WYLACZNIE do prezentacji.
  const verdict = clamped >= PASS_THRESHOLD ? 'PASS' : 'REJECT';

  // Breakdown i total zaokraglone tylko na potrzeby wyswietlania/JSON.
  const breakdown = {
    sbom: raw.sbom,
    patent: raw.patent,
    completeness: round2(raw.completeness),
    vex: raw.vex,
  };

  return {
    offer,
    weights: WEIGHTS,
    breakdown,
    total: round2(clamped),
    threshold: PASS_THRESHOLD,
    verdict,
  };
}

function round2(n) {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

// ---------------------------------------------------------------------------
// Self-test — wbudowane fixtures (pozytywne + NEGATYWNE). Zero plikow zewn.
// ---------------------------------------------------------------------------
function runSelftest() {
  const cases = [
    // --- POZYTYWNE ---
    {
      name: 'pelna oferta => 100 / PASS',
      offer: { sbom_hash_rederivable: true, patent_grant: true, completeness: 1, vex_present: true },
      expect: { total: 100, verdict: 'PASS' },
    },
    {
      name: 'SBOM+patent+kompletnosc pelna, bez VEX => 90 / PASS',
      offer: { sbom_hash_rederivable: true, patent_grant: true, completeness: 1, vex_present: false },
      expect: { total: 90, verdict: 'PASS' },
    },
    {
      name: 'prog dokladnie: SBOM+patent, completeness 0, bez VEX => 70 / PASS',
      offer: { sbom_hash_rederivable: true, patent_grant: true, completeness: 0, vex_present: false },
      expect: { total: 70, verdict: 'PASS' },
    },
    {
      name: 'czastkowa kompletnosc 0.5 => 10 pkt z 20',
      offer: { sbom_hash_rederivable: true, patent_grant: false, completeness: 0.5, vex_present: true },
      expect: { total: 60, verdict: 'REJECT', completenessPts: 10 },
    },
    // --- NEGATYWNE (brak dowodu => odrzucenie) ---
    {
      name: 'brak SBOM + brak patentu, reszta pelna => total<70 / REJECT',
      offer: { sbom_hash_rederivable: false, patent_grant: false, completeness: 1, vex_present: true },
      expect: { total: 30, verdict: 'REJECT', lessThan70: true },
    },
    {
      name: 'pusta oferta (zero deklaracji) => 0 / REJECT',
      offer: {},
      expect: { total: 0, verdict: 'REJECT' },
    },
    {
      name: 'tuz pod progiem: brak patentu, reszta pelna => 69.99 / REJECT',
      offer: { sbom_hash_rederivable: true, patent_grant: false, completeness: 0.9995, vex_present: true },
      // 40 + 0 + round2(20*0.9995)=19.99 + 10 = 69.99 => REJECT
      expect: { total: 69.99, verdict: 'REJECT', lessThan70: true },
    },
    {
      name: 'completeness 0.999 bez patentu => REJECT',
      offer: { sbom_hash_rederivable: true, patent_grant: false, completeness: 0.999, vex_present: true },
      // 40 + 0 + 20*0.999=19.98 + 10 = 69.98 < 70 => REJECT
      expect: { verdict: 'REJECT', lessThan70: true },
    },
    // --- NEGATYWNE: EXPLOIT SEDZIEGO ZABLOKOWANY (wektor ktory PRZECHODZIL, teraz FAIL) ---
    {
      // Przed fix: round2(20*0.99975)=round2(19.995)=20 zawyzalo skladnik ->
      //   total 40+0+20+10=70 -> bledny PASS. Teraz total liczony z niezaokraglonych:
      //   40+0+19.995+10 = 69.995 < 70 => REJECT (mimo ze prezentowany total zaokragla do 70).
      name: 'EXPLOIT F7 ZABLOKOWANY: completeness 0.99975 bez patentu => REJECT (nie PASS)',
      offer: { sbom_hash_rederivable: true, patent_grant: false, completeness: 0.99975, vex_present: true },
      expect: { verdict: 'REJECT' },
    },
    // --- NEGATYWNE: walidacja odrzuca smieciowe wejscie (rzuca) ---
    { name: 'completeness > 1 => blad walidacji', offer: { completeness: 1.5 }, throws: true },
    { name: 'completeness < 0 => blad walidacji', offer: { completeness: -0.1 }, throws: true },
    { name: 'completeness nie-liczba => blad walidacji', offer: { completeness: 'wysoka' }, throws: true },
    { name: 'sbom nie-boolean => blad walidacji', offer: { sbom_hash_rederivable: 'tak' }, throws: true },
    { name: 'oferta = tablica => blad walidacji', offer: [], throws: true },
    { name: 'oferta = null => blad walidacji', offer: null, throws: true },
  ];

  let passed = 0;
  let failed = 0;

  for (const c of cases) {
    if (c.throws) {
      let threw = false;
      try {
        scoreOffer(c.offer);
      } catch (_e) {
        threw = true;
      }
      if (threw) {
        passed++;
        log(`  ok   [NEG] ${c.name}`);
      } else {
        failed++;
        log(`  FAIL [NEG] ${c.name} — oczekiwano wyjatku, nie rzucilo`);
      }
      continue;
    }

    let report;
    try {
      report = scoreOffer(c.offer);
    } catch (e) {
      failed++;
      log(`  FAIL ${c.name} — nieoczekiwany wyjatek: ${e.message}`);
      continue;
    }

    const errs = [];
    if (typeof c.expect.total === 'number' && report.total !== c.expect.total) {
      errs.push(`total=${report.total}, oczekiwano ${c.expect.total}`);
    }
    if (c.expect.verdict && report.verdict !== c.expect.verdict) {
      errs.push(`verdict=${report.verdict}, oczekiwano ${c.expect.verdict}`);
    }
    if (typeof c.expect.completenessPts === 'number' && report.breakdown.completeness !== c.expect.completenessPts) {
      errs.push(`completenessPts=${report.breakdown.completeness}, oczekiwano ${c.expect.completenessPts}`);
    }
    if (c.expect.lessThan70 && !(report.total < 70)) {
      errs.push(`total ${report.total} nie jest < 70`);
    }
    // Niezmiennik zakresu: total zawsze w [0..100].
    if (report.total < 0 || report.total > 100) {
      errs.push(`total ${report.total} poza [0..100]`);
    }

    if (errs.length === 0) {
      passed++;
      log(`  ok   ${c.name}`);
    } else {
      failed++;
      log(`  FAIL ${c.name} — ${errs.join('; ')}`);
    }
  }

  log('');
  log(`SELFTEST: ${passed} passed, ${failed} failed (${cases.length} total)`);
  if (failed === 0) {
    log('SELFTEST: OK');
    process.exit(0);
  } else {
    log('SELFTEST: FAILED');
    process.exit(1);
  }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function log(...args) {
  // eslint-disable-next-line no-console
  console.log(...args);
}

function parseArgs(argv) {
  const args = { selftest: false, offer: undefined, json: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--selftest') args.selftest = true;
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--offer') args.offer = argv[++i];
    else if (a.startsWith('--offer=')) args.offer = a.slice('--offer='.length);
    else throw new Error(`Nieznany argument: ${a}`);
  }
  return args;
}

const HELP = `procurement-check.mjs — punktacja manifestu oferty (K0NSULT open commons)

Uzycie:
  node procurement-check.mjs --selftest
  node procurement-check.mjs --offer '<JSON>' [--json]

Manifest oferty (--offer, obiekt JSON):
  sbom_hash_rederivable : bool   -> 40 pkt
  patent_grant          : bool   -> 30 pkt
  completeness          : 0..1   -> 20 * completeness
  vex_present           : bool   -> 10 pkt

Verdict: PASS gdy total >= 70, inaczej REJECT.

Przyklad:
  node procurement-check.mjs --offer '{"sbom_hash_rederivable":true,"patent_grant":true,"completeness":1,"vex_present":true}'
`;

function renderHuman(r) {
  const lines = [];
  lines.push('=== PROCUREMENT ACCEPTANCE CHECK ===');
  lines.push(`  SBOM (rederivable hash)   : ${r.breakdown.sbom.toString().padStart(6)} / ${r.weights.sbom}`);
  lines.push(`  Patent grant              : ${r.breakdown.patent.toString().padStart(6)} / ${r.weights.patent}`);
  lines.push(`  Completeness (${(r.offer.completeness).toFixed(4)})   : ${r.breakdown.completeness.toString().padStart(6)} / ${r.weights.completeness}`);
  lines.push(`  VEX present               : ${r.breakdown.vex.toString().padStart(6)} / ${r.weights.vex}`);
  lines.push(`  ---------------------------------------`);
  lines.push(`  TOTAL                     : ${r.total.toString().padStart(6)} / 100   (prog: ${r.threshold})`);
  lines.push(`  VERDICT                   : ${r.verdict}`);
  return lines.join('\n');
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    log(e.message);
    log('');
    log(HELP);
    process.exit(2);
  }

  if (args.help) {
    log(HELP);
    process.exit(0);
  }

  if (args.selftest) {
    runSelftest();
    return; // runSelftest wywoluje process.exit
  }

  if (args.offer === undefined) {
    log('Brak --offer. Podaj manifest oferty jako JSON lub uruchom --selftest.');
    log('');
    log(HELP);
    process.exit(2);
  }

  let parsed;
  try {
    parsed = JSON.parse(args.offer);
  } catch (e) {
    log(`Nieprawidlowy JSON w --offer: ${e.message}`);
    process.exit(2);
  }

  let report;
  try {
    report = scoreOffer(parsed);
  } catch (e) {
    log(`Blad walidacji oferty: ${e.message}`);
    process.exit(2);
  }

  if (args.json) {
    log(JSON.stringify(report, null, 2));
  } else {
    log(renderHuman(report));
  }
  // Kod wyjscia zgodny z werdyktem: 0 = PASS, 1 = REJECT.
  process.exit(report.verdict === 'PASS' ? 0 : 1);
}

main();
