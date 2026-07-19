#!/usr/bin/env node
// sbom-expose.mjs — K0NSULT open commons tool
// Doktryna: claim<=proof. Ekspozycja komponentow SBOM wobec LOKALNEJ migawki podatnosci.
// ZERO sieci, ZERO zaleznosci (tylko wbudowane: fs, path). Deterministyczne, offline.
//
// KLUCZOWA ZASADA: NO_MATCH NIGDY nie znaczy "bezpieczny". Znaczy jedynie:
//   "sprawdzono wobec TEJ migawki i nie znaleziono trafienia".
// Brak migawki => wszystko NO_FEED (jawny GAP, nie falszywy spokoj).
//
// Uzycie:
//   node sbom-expose.mjs --sbom sbom.json [--snapshot snapshot.json] [--json]
//   node sbom-expose.mjs --selftest
//
// SBOM: CycloneDX (obiekt z tablica `components`).
// Migawka: { feed_id, snapshot_date, entries:[{ purl_prefix, id, affected_range }] }

import { readFileSync } from 'node:fs';

// --- klasyfikacja ekspozycji (stany) ---
export const EXPOSURE = Object.freeze({
  MATCH: 'MATCH',                   // wersja komponentu miesci sie w zakresie znanej podatnosci
  NO_MATCH: 'NO_MATCH',             // feed sprawdzony, brak trafienia — NIE oznacza bezpieczny
  RANGE_UNKNOWN: 'RANGE_UNKNOWN',   // wpis pasuje do komponentu, ale zakresu nie da sie ustalic/sparsowac
  UNVERSIONED: 'UNVERSIONED',       // purl bez wersji — nie sposob ocenic
  NO_FEED: 'NO_FEED',               // brak migawki — jawny GAP
});

// --- parsowanie purl: wyciagnij wersje (miedzy '@' a '?'/'#') ---
export function purlVersion(purl) {
  if (typeof purl !== 'string') return null;
  // pkg:type/namespace/name@version?qualifiers#subpath
  // scope npm koduje '@' jako %40, wiec '@' pojawia sie tylko przed wersja
  const m = purl.match(/@([^?#@]+)(?:[?#]|$)/);
  return m ? m[1] : null;
}

// --- czy purl komponentu pasuje do prefiksu wpisu (na granicy segmentu) ---
export function purlPrefixMatches(purl, prefix) {
  if (typeof purl !== 'string' || typeof prefix !== 'string' || prefix.length === 0) return false;
  if (!purl.startsWith(prefix)) return false;
  if (purl.length === prefix.length) return true;
  const next = purl[prefix.length];
  // granica: koniec, wersja, kolejny segment, kwalifikator lub subpath
  return next === '@' || next === '/' || next === '?' || next === '#';
}

// --- porownanie semver-ish: zwraca -1/0/1, lub null gdy nieporownywalne ---
export function compareVersions(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return null;
  const norm = (v) => v.trim().replace(/^v/i, '').split(/[-+]/)[0]; // odetnij prerelease/build
  const pa = norm(a).split('.');
  const pb = norm(b).split('.');
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const xa = pa[i] === undefined ? 0 : Number(pa[i]);
    const xb = pb[i] === undefined ? 0 : Number(pb[i]);
    if (!Number.isFinite(xa) || !Number.isFinite(xb)) return null; // nieliczbowe => nieporownywalne
    if (xa < xb) return -1;
    if (xa > xb) return 1;
  }
  return 0;
}

// --- ocena zakresu: czy `version` miesci sie w `range`? ---
// Zwraca true | false | null (null = nie da sie sparsowac => RANGE_UNKNOWN)
// Obslugiwane: ">=1.0.0 <2.0.0", "<2.0.0", ">1.0.0", "<=2.0.0", "=1.2.3", "1.2.3",
//              "1.0.0 - 2.0.0" (inkluzywny), tokeny rozdzielone spacja lub przecinkiem.
export function versionInRange(version, range) {
  if (typeof version !== 'string' || typeof range !== 'string') return null;
  const r = range.trim();
  if (r === '' || r === '*') return null; // pusty/dowolny zakres = nieokreslony

  // zakres hyphenowy: "A - B"
  const hyphen = r.match(/^([^\s]+)\s+-\s+([^\s]+)$/);
  if (hyphen) {
    const lo = compareVersions(version, hyphen[1]);
    const hi = compareVersions(version, hyphen[2]);
    if (lo === null || hi === null) return null;
    return lo >= 0 && hi <= 0;
  }

  const tokens = r.split(/[\s,]+/).filter(Boolean);
  let result = true;
  for (const tok of tokens) {
    const m = tok.match(/^(>=|<=|>|<|=|==)?\s*(.+)$/);
    if (!m) return null;
    const op = m[1] || '=';
    const cmp = compareVersions(version, m[2]);
    if (cmp === null) return null; // nieporownywalny token => cala ocena nieokreslona
    let ok;
    switch (op) {
      case '>': ok = cmp > 0; break;
      case '>=': ok = cmp >= 0; break;
      case '<': ok = cmp < 0; break;
      case '<=': ok = cmp <= 0; break;
      case '=':
      case '==': ok = cmp === 0; break;
      default: return null;
    }
    result = result && ok;
  }
  return result;
}

// --- klasyfikacja pojedynczego komponentu ---
export function classifyComponent(component, snapshot) {
  const purl = component && component.purl;
  if (snapshot === null || snapshot === undefined) {
    return { exposure: EXPOSURE.NO_FEED, advisories: [], feed_id: null };
  }
  const feedId = snapshot.feed_id || null;
  const version = purlVersion(purl);
  if (version === null) {
    return { exposure: EXPOSURE.UNVERSIONED, advisories: [], feed_id: feedId };
  }

  const entries = Array.isArray(snapshot.entries) ? snapshot.entries : [];
  const matchedPrefix = entries.filter((e) => e && purlPrefixMatches(purl, e.purl_prefix));

  const hits = [];        // wpisy z wersja w zakresie => MATCH
  let rangeUnknown = false;
  for (const e of matchedPrefix) {
    const inRange = versionInRange(version, e.affected_range);
    if (inRange === true) {
      hits.push(e.id);
    } else if (inRange === null) {
      rangeUnknown = true;
    }
    // inRange === false => komponent poza zakresem tego wpisu (nie trafia)
  }

  if (hits.length > 0) {
    return { exposure: EXPOSURE.MATCH, advisories: hits, feed_id: feedId };
  }
  if (rangeUnknown) {
    return { exposure: EXPOSURE.RANGE_UNKNOWN, advisories: [], feed_id: feedId };
  }
  // feed sprawdzony, brak trafienia — NIE oznacza bezpieczny
  return { exposure: EXPOSURE.NO_MATCH, advisories: [], feed_id: feedId };
}

// --- analiza calego SBOM ---
export function analyzeSbom(sbom, snapshot) {
  const components = (sbom && Array.isArray(sbom.components)) ? sbom.components : [];
  const results = [];
  for (const c of components) {
    if (!c || c.type !== 'library') continue; // tylko biblioteki
    if (typeof c.purl !== 'string' || c.purl.length === 0) continue; // tylko z purl
    const r = classifyComponent(c, snapshot);
    results.push({
      name: c.name || null,
      version: c.version || purlVersion(c.purl) || null,
      purl: c.purl,
      exposure: r.exposure,
      advisories: r.advisories,
    });
  }
  const summary = {
    MATCH: 0, NO_MATCH: 0, RANGE_UNKNOWN: 0, UNVERSIONED: 0, NO_FEED: 0,
  };
  for (const r of results) summary[r.exposure]++;
  return {
    feed_id: snapshot ? (snapshot.feed_id || null) : null,
    snapshot_date: snapshot ? (snapshot.snapshot_date || null) : null,
    feed_present: !!snapshot,
    components_assessed: results.length,
    summary,
    results,
    // jawny disclaimer w wyniku, nie tylko w dokumentacji
    note: 'NO_MATCH oznacza brak trafienia w TEJ migawce; NIE jest dowodem bezpieczenstwa. Brak migawki => NO_FEED (GAP).',
  };
}

// --- CLI arg parsing ---
function parseArgs(argv) {
  const out = { sbom: null, snapshot: null, selftest: false, json: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--selftest') out.selftest = true;
    else if (a === '--json') out.json = true;
    else if (a === '--sbom') out.sbom = argv[++i];
    else if (a === '--snapshot') out.snapshot = argv[++i];
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

// --- SELFTEST: wbudowane fixtures, pozytywne + NEGATYWNE, samowystarczalny ---
function selftest() {
  const failures = [];
  const assert = (cond, msg) => { if (!cond) failures.push(msg); };

  const sbom = {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    components: [
      { type: 'library', name: 'lodash', version: '4.17.20', purl: 'pkg:npm/lodash@4.17.20' },
      { type: 'library', name: 'lodash', version: '4.17.21', purl: 'pkg:npm/lodash@4.17.21' },
      { type: 'library', name: 'left-pad', version: '1.3.0', purl: 'pkg:npm/left-pad@1.3.0' },
      { type: 'library', name: 'lodash-es', version: '4.17.20', purl: 'pkg:npm/lodash-es@4.17.20' },
      { type: 'library', name: 'mystery', purl: 'pkg:npm/mystery' }, // bez wersji
      { type: 'library', name: 'weirdrange', version: '2.0.0', purl: 'pkg:npm/weirdrange@2.0.0' },
      { type: 'application', name: 'app', version: '1.0.0', purl: 'pkg:npm/app@1.0.0' }, // nie library
      { type: 'library', name: 'nopurl', version: '1.0.0' }, // bez purl
    ],
  };

  const snapshot = {
    feed_id: 'k0nsult-local-selftest',
    snapshot_date: '2026-07-19',
    entries: [
      { purl_prefix: 'pkg:npm/lodash', id: 'CVE-TEST-0001', affected_range: '>=4.0.0 <4.17.21' },
      { purl_prefix: 'pkg:npm/weirdrange', id: 'CVE-TEST-0002', affected_range: 'latest-broken' },
    ],
  };

  // --- z migawka ---
  const withFeed = analyzeSbom(sbom, snapshot);
  const byPurl = {};
  for (const r of withFeed.results) byPurl[r.purl] = r;
  const byName = {}; // uwaga: kolizja przy duplikatach nazw — uzywaj byPurl dla lodash
  for (const r of withFeed.results) byName[r.name] = r;

  // POZYTYWNE
  const lodash20 = byPurl['pkg:npm/lodash@4.17.20'];
  assert(lodash20 && lodash20.exposure === EXPOSURE.MATCH,
    `oczekiwano MATCH dla lodash@4.17.20, jest ${lodash20 && lodash20.exposure}`);
  assert(lodash20 && lodash20.advisories.includes('CVE-TEST-0001'),
    'MATCH powinien niesc id advisory CVE-TEST-0001');

  // NEGATYWNE — wersja poza zakresem (4.17.21 nie w <4.17.21)
  const lodash21 = withFeed.results.find((r) => r.purl === 'pkg:npm/lodash@4.17.21');
  assert(lodash21 && lodash21.exposure === EXPOSURE.NO_MATCH,
    `oczekiwano NO_MATCH dla lodash@4.17.21 (poza zakresem), jest ${lodash21 && lodash21.exposure}`);

  // NEGATYWNE — purl spoza feedu
  assert(byName['left-pad'].exposure === EXPOSURE.NO_MATCH,
    `oczekiwano NO_MATCH dla left-pad (spoza migawki), jest ${byName['left-pad'] && byName['left-pad'].exposure}`);

  // GRANICA — lodash-es NIE moze trafic na prefiks lodash
  assert(byName['lodash-es'].exposure === EXPOSURE.NO_MATCH,
    `lodash-es nie powinien trafic na prefiks pkg:npm/lodash, jest ${byName['lodash-es'] && byName['lodash-es'].exposure}`);

  // UNVERSIONED — purl bez wersji
  assert(byName['mystery'].exposure === EXPOSURE.UNVERSIONED,
    `oczekiwano UNVERSIONED dla mystery, jest ${byName['mystery'] && byName['mystery'].exposure}`);

  // RANGE_UNKNOWN — wpis pasuje, ale zakres nieparsowalny
  assert(byName['weirdrange'].exposure === EXPOSURE.RANGE_UNKNOWN,
    `oczekiwano RANGE_UNKNOWN dla weirdrange, jest ${byName['weirdrange'] && byName['weirdrange'].exposure}`);

  // FILTRY — application i bez-purl pominiete
  assert(!withFeed.results.some((r) => r.name === 'app'),
    'komponent type=application nie powinien byc oceniany');
  assert(!withFeed.results.some((r) => r.name === 'nopurl'),
    'komponent bez purl nie powinien byc oceniany');
  assert(withFeed.components_assessed === 6,
    `oczekiwano 6 ocenionych komponentow, jest ${withFeed.components_assessed}`);

  // --- BEZ migawki => wszystko NO_FEED (jawny GAP) ---
  const noFeed = analyzeSbom(sbom, null);
  assert(noFeed.results.length > 0 && noFeed.results.every((r) => r.exposure === EXPOSURE.NO_FEED),
    'bez migawki wszystkie komponenty musza byc NO_FEED');
  assert(noFeed.feed_present === false, 'feed_present musi byc false bez migawki');

  // --- jednostkowe: parsery ---
  assert(purlVersion('pkg:npm/lodash@4.17.20') === '4.17.20', 'purlVersion podstawowy');
  assert(purlVersion('pkg:npm/%40scope/pkg@1.2.3?a=b#sub') === '1.2.3', 'purlVersion scoped+qualifiers');
  assert(purlVersion('pkg:npm/lodash') === null, 'purlVersion bez wersji => null');
  assert(compareVersions('1.2.0', '1.10.0') === -1, 'compareVersions numeryczne nie leksykalne');
  assert(versionInRange('1.5.0', '>=1.0.0 <2.0.0') === true, 'versionInRange w zakresie');
  assert(versionInRange('2.5.0', '>=1.0.0 <2.0.0') === false, 'versionInRange poza zakresem');
  assert(versionInRange('1.5.0', 'garbage') === null, 'versionInRange nieparsowalny => null');
  assert(versionInRange('1.5.0', '1.0.0 - 2.0.0') === true, 'versionInRange hyphen');
  assert(purlPrefixMatches('pkg:npm/lodash-es@1.0.0', 'pkg:npm/lodash') === false, 'granica prefiksu');
  assert(purlPrefixMatches('pkg:npm/lodash@1.0.0', 'pkg:npm/lodash') === true, 'prefiks trafia na @');

  if (failures.length === 0) {
    console.log('SELFTEST OK: wszystkie asercje przeszly (pozytywne + negatywne).');
    console.log(`  ocenione komponenty: ${withFeed.components_assessed}, feed_id: ${withFeed.feed_id}`);
    console.log(`  summary: ${JSON.stringify(withFeed.summary)}`);
    process.exit(0);
  } else {
    console.error('SELFTEST FAIL:');
    for (const f of failures) console.error('  - ' + f);
    process.exit(1);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.selftest) { selftest(); return; }

  if (args.help || !args.sbom) {
    console.log('sbom-expose.mjs — ekspozycja komponentow SBOM wobec lokalnej migawki podatnosci');
    console.log('');
    console.log('Uzycie:');
    console.log('  node sbom-expose.mjs --sbom sbom.json [--snapshot snapshot.json] [--json]');
    console.log('  node sbom-expose.mjs --selftest');
    console.log('');
    console.log('Bez --snapshot => wszystkie komponenty NO_FEED (jawny GAP).');
    console.log('NO_MATCH NIGDY nie znaczy "bezpieczny" — tylko brak trafienia w tej migawce.');
    process.exit(args.help ? 0 : 1);
    return;
  }

  let sbom, snapshot = null;
  try {
    sbom = readJson(args.sbom);
  } catch (e) {
    console.error(`Blad odczytu --sbom ${args.sbom}: ${e.message}`);
    process.exit(2);
    return;
  }
  if (args.snapshot) {
    try {
      snapshot = readJson(args.snapshot);
    } catch (e) {
      console.error(`Blad odczytu --snapshot ${args.snapshot}: ${e.message}`);
      process.exit(2);
      return;
    }
  }

  const report = analyzeSbom(sbom, snapshot);

  if (args.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    console.log(`# sbom-expose — feed: ${report.feed_id || '(BRAK — GAP)'}${report.snapshot_date ? ' @ ' + report.snapshot_date : ''}`);
    console.log(`# ocenione komponenty (type=library, z purl): ${report.components_assessed}`);
    console.log(`# summary: ${JSON.stringify(report.summary)}`);
    console.log('');
    for (const r of report.results) {
      const adv = r.advisories.length ? '  [' + r.advisories.join(', ') + ']' : '';
      console.log(`${r.exposure.padEnd(14)} ${r.purl}${adv}`);
    }
    console.log('');
    console.log('# ' + report.note);
  }
  process.exit(0);
}

// uruchom main tylko gdy plik odpalony bezposrednio
const isMain = import.meta.url === `file://${process.argv[1]}` ||
               (process.argv[1] && import.meta.url.endsWith(process.argv[1].replace(/\\/g, '/')));
if (isMain || process.argv.some((a) => a === '--selftest' || a === '--sbom' || a === '--help' || a === '-h')) {
  main();
}
