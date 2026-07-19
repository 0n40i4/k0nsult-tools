#!/usr/bin/env node
// dep-provenance.mjs — K0NSULT open commons tool
// ---------------------------------------------------------------------------
// Klasyfikuje jurisdiction_class (EU | EEA | non-EU | UNKNOWN) per KOMPONENT /
// PODMIOT na podstawie mapy DEKLARACJI (--declarations). Brak deklaracji =>
// UNKNOWN (klasa NEUTRALNA, NIE kara/minus).
//
// Doktryna K0NSULT:
//  - claim <= proof        : klasa wynika WYŁĄCZNIE z deklaracji; brak = UNKNOWN
//  - agents-not-people     : ZERO PII, ZERO scoringu osób
//  - silnik ukryty         : brak kodu k0nsult.cloud, brak sekretów, offline
//
// TWARDY ZAKAZ: narzędzie NIGDY nie klasyfikuje narodowości OSOBY (człowieka).
//  Jeśli JAKAKOLWIEK deklaracja zawiera (na dowolnym poziomie zagnieżdżenia)
//  klucz: person | natural_person | nationality_of_person | nationality
//  => ABORT z błędem (throw / exit 1). Jurysdykcja PODMIOTU deklarowana jest
//  polem `country` / `region` / `jurisdiction_class`, NIGDY narodowością osoby.
//
// Zero zależności — wyłącznie moduły wbudowane Node >= 18: fs, path.
// Deterministyczne, offline (zero sieci). --selftest = dowód działania.
// ---------------------------------------------------------------------------

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// --- Klasy jurysdykcji ------------------------------------------------------
const CLASSES = Object.freeze(['EU', 'EEA', 'non-EU', 'UNKNOWN']);

// ISO 3166-1 alpha-2 — państwa członkowskie UE (27).
const EU_COUNTRIES = new Set([
  'AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR',
  'HU', 'IE', 'IT', 'LV', 'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK',
  'SI', 'ES', 'SE',
]);

// EOG poza UE: Islandia, Liechtenstein, Norwegia.
const EEA_ONLY_COUNTRIES = new Set(['IS', 'LI', 'NO']);

// --- TWARDY ZAKAZ: klucze wskazujące na OSOBĘ (człowieka) -------------------
// Ich obecność w JAKIEJKOLWIEK deklaracji = natychmiastowy ABORT.
const FORBIDDEN_PERSON_KEYS = new Set([
  'person',
  'natural_person',
  'nationality_of_person',
  'nationality',
]);

class PersonDataError extends Error {
  constructor(keyPath) {
    super(
      `ABORT: deklaracja zawiera dane OSOBY (klucz "${keyPath}"). ` +
        `Doktryna agents-not-people: narzędzie NIGDY nie klasyfikuje ` +
        `narodowości człowieka. Jurysdykcję PODMIOTU deklaruj polem ` +
        `country/region/jurisdiction_class.`,
    );
    this.name = 'PersonDataError';
    this.keyPath = keyPath;
  }
}

class DeclarationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DeclarationError';
  }
}

// --- Głęboki skan zakazanych kluczy osobowych -------------------------------
// Rzuca PersonDataError przy pierwszym trafieniu (dowolny poziom zagnieżdżenia).
function assertNoPersonData(value, pathPrefix = '') {
  if (value === null || typeof value !== 'object') return;
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) {
      assertNoPersonData(value[i], `${pathPrefix}[${i}]`);
    }
    return;
  }
  for (const key of Object.keys(value)) {
    const norm = key.toLowerCase();
    if (FORBIDDEN_PERSON_KEYS.has(norm)) {
      throw new PersonDataError(pathPrefix ? `${pathPrefix}.${key}` : key);
    }
    assertNoPersonData(value[key], pathPrefix ? `${pathPrefix}.${key}` : key);
  }
}

// --- Mapowanie kraju -> klasa jurysdykcji -----------------------------------
function classFromCountry(codeRaw) {
  const code = String(codeRaw).trim().toUpperCase();
  if (EU_COUNTRIES.has(code)) return 'EU';
  if (EEA_ONLY_COUNTRIES.has(code)) return 'EEA';
  return 'non-EU';
}

// --- Rozwiązanie klasy pojedynczej deklaracji -------------------------------
// Zwraca jedną z: EU | EEA | non-EU. Nie zwraca UNKNOWN (to stan "brak
// deklaracji", obsłużony wyżej). Deklaracja nierozwiązywalna = DeclarationError.
function resolveClass(decl) {
  if (decl == null || typeof decl !== 'object' || Array.isArray(decl)) {
    throw new DeclarationError(
      'Deklaracja musi być obiektem { component|entity, ... }.',
    );
  }
  // 1) jawne jurisdiction_class
  if (decl.jurisdiction_class != null) {
    const jc = String(decl.jurisdiction_class).trim();
    if (jc === 'UNKNOWN') {
      throw new DeclarationError(
        'jurisdiction_class="UNKNOWN" nie jest dozwolone jawnie; ' +
          'UNKNOWN wynika z BRAKU deklaracji.',
      );
    }
    if (!CLASSES.includes(jc)) {
      throw new DeclarationError(
        `Nieznane jurisdiction_class="${jc}". Dozwolone: EU | EEA | non-EU ` +
          `(lub użyj pola country).`,
      );
    }
    return jc;
  }
  // 2) region (EU|EEA|non-EU wprost)
  if (decl.region != null) {
    const r = String(decl.region).trim();
    if (['EU', 'EEA', 'non-EU'].includes(r)) return r;
    throw new DeclarationError(
      `Nieznany region="${r}". Dozwolone: EU | EEA | non-EU.`,
    );
  }
  // 3) country (ISO alpha-2)
  if (decl.country != null) {
    const code = String(decl.country).trim();
    if (!/^[A-Za-z]{2}$/.test(code)) {
      throw new DeclarationError(
        `country="${code}" musi być kodem ISO 3166-1 alpha-2 (2 litery).`,
      );
    }
    return classFromCountry(code);
  }
  throw new DeclarationError(
    'Deklaracja nie zawiera jurisdiction_class ani region ani country — ' +
      'nie da się rozwiązać klasy.',
  );
}

// --- Klucz identyfikujący komponent/podmiot ---------------------------------
function declKey(decl) {
  const c = decl && decl.component != null ? String(decl.component).trim() : '';
  const e = decl && decl.entity != null ? String(decl.entity).trim() : '';
  if (c) return c;
  if (e) return e;
  return '';
}

// --- Normalizacja wejścia deklaracji ----------------------------------------
// Akceptuje: tablicę deklaracji LUB { components|declarations: [...] }.
function extractDeclarations(root) {
  if (Array.isArray(root)) return root;
  if (root && typeof root === 'object') {
    if (Array.isArray(root.components)) return root.components;
    if (Array.isArray(root.declarations)) return root.declarations;
  }
  throw new DeclarationError(
    'Plik deklaracji musi być tablicą albo obiektem z polem ' +
      '"components"/"declarations" (tablica).',
  );
}

// --- Budowa mapy deklaracji (z twardym zakazem PII) -------------------------
function buildDeclarationMap(root) {
  // Skan CAŁEGO wejścia PRZED jakąkolwiek klasyfikacją — fail-fast na PII.
  assertNoPersonData(root, '');

  const list = extractDeclarations(root);
  const map = new Map();
  for (let i = 0; i < list.length; i++) {
    const decl = list[i];
    const key = declKey(decl);
    if (!key) {
      throw new DeclarationError(
        `Deklaracja #${i} bez pola component/entity — brak identyfikatora.`,
      );
    }
    if (map.has(key)) {
      throw new DeclarationError(
        `Zduplikowana deklaracja dla "${key}".`,
      );
    }
    const jurisdiction_class = resolveClass(decl);
    map.set(key, { component: key, jurisdiction_class });
  }
  return map;
}

// --- Klasyfikacja listy komponentów wg mapy deklaracji ----------------------
// Brak deklaracji => UNKNOWN (neutralny).
function classifyComponents(componentNames, declMap) {
  return componentNames.map((nameRaw) => {
    const name = String(nameRaw).trim();
    if (declMap.has(name)) {
      return { component: name, jurisdiction_class: declMap.get(name).jurisdiction_class, declared: true };
    }
    return { component: name, jurisdiction_class: 'UNKNOWN', declared: false };
  });
}

// --- Publiczne API rdzenia (używane też przez selftest) ---------------------
function classify({ declarationsRoot, components }) {
  const declMap = buildDeclarationMap(declarationsRoot);
  let results;
  if (Array.isArray(components) && components.length > 0) {
    results = classifyComponents(components, declMap);
  } else {
    // Bez jawnej listy komponentów: klasyfikuj wszystkie zadeklarowane.
    results = [...declMap.values()].map((r) => ({ ...r, declared: true }));
  }
  const summary = { EU: 0, EEA: 0, 'non-EU': 0, UNKNOWN: 0 };
  for (const r of results) summary[r.jurisdiction_class]++;
  return { results, summary, total: results.length };
}

// --- Odczyt listy komponentów z pliku ---------------------------------------
function extractComponentNames(root) {
  if (Array.isArray(root)) {
    return root.map((x) => (typeof x === 'string' ? x : declKey(x))).filter(Boolean);
  }
  if (root && typeof root === 'object' && Array.isArray(root.components)) {
    return root.components.map((x) => (typeof x === 'string' ? x : declKey(x))).filter(Boolean);
  }
  throw new DeclarationError(
    'Plik komponentów musi być tablicą nazw/obiektów albo { components: [...] }.',
  );
}

// ===========================================================================
// SELFTEST — wbudowane fixtures, ZERO plików zewnętrznych, pozytywne+NEGATYWNE
// ===========================================================================
function runSelftest() {
  const cases = [];
  const check = (name, fn) => {
    try {
      fn();
      cases.push({ name, ok: true });
    } catch (e) {
      cases.push({ name, ok: false, err: e.message });
    }
  };
  const assert = (cond, msg) => {
    if (!cond) throw new Error(msg || 'assert failed');
  };

  // (1) POZYTYWNY: komponent z deklaracją country=PL => EU
  check('komponent EU (country=PL)', () => {
    const root = { components: [{ component: 'lib-pl', country: 'PL' }] };
    const { results } = classify({ declarationsRoot: root, components: ['lib-pl'] });
    assert(results[0].jurisdiction_class === 'EU', 'oczekiwano EU');
    assert(results[0].declared === true, 'oczekiwano declared=true');
  });

  // (1b) POZYTYWNY: jawne jurisdiction_class=EU
  check('komponent EU (jurisdiction_class=EU)', () => {
    const root = [{ entity: 'Foundation EU', jurisdiction_class: 'EU' }];
    const { results } = classify({ declarationsRoot: root, components: ['Foundation EU'] });
    assert(results[0].jurisdiction_class === 'EU', 'oczekiwano EU');
  });

  // (1c) POZYTYWNY: EEA (country=NO)
  check('komponent EEA (country=NO)', () => {
    const root = [{ component: 'lib-no', country: 'NO' }];
    const { results } = classify({ declarationsRoot: root, components: ['lib-no'] });
    assert(results[0].jurisdiction_class === 'EEA', 'oczekiwano EEA');
  });

  // (1d) POZYTYWNY: non-EU (country=US)
  check('komponent non-EU (country=US)', () => {
    const root = [{ component: 'lib-us', country: 'US' }];
    const { results } = classify({ declarationsRoot: root, components: ['lib-us'] });
    assert(results[0].jurisdiction_class === 'non-EU', 'oczekiwano non-EU');
  });

  // (2) NEUTRALNY: komponent BEZ deklaracji => UNKNOWN (nie minus)
  check('komponent bez deklaracji => UNKNOWN', () => {
    const root = { components: [{ component: 'lib-pl', country: 'PL' }] };
    const { results } = classify({
      declarationsRoot: root,
      components: ['lib-pl', 'lib-nieznany'],
    });
    const unknown = results.find((r) => r.component === 'lib-nieznany');
    assert(unknown, 'brak wpisu dla lib-nieznany');
    assert(unknown.jurisdiction_class === 'UNKNOWN', 'oczekiwano UNKNOWN');
    assert(unknown.declared === false, 'oczekiwano declared=false');
  });

  // (3) NEGATYWNY: deklaracja z polem OSOBY => ABORT (throw)
  check('NEGATYWNY: pole person => ABORT', () => {
    const root = { components: [{ component: 'x', person: { name: 'Jan K.' }, country: 'PL' }] };
    let threw = false;
    try {
      classify({ declarationsRoot: root, components: ['x'] });
    } catch (e) {
      threw = e instanceof PersonDataError;
    }
    assert(threw, 'oczekiwano PersonDataError dla pola person');
  });

  // (3b) NEGATYWNY: natural_person zagnieżdżony głęboko => ABORT
  check('NEGATYWNY: natural_person (deep) => ABORT', () => {
    const root = [{ component: 'y', country: 'DE', meta: { info: { natural_person: true } } }];
    let threw = false;
    try {
      classify({ declarationsRoot: root, components: ['y'] });
    } catch (e) {
      threw = e instanceof PersonDataError;
    }
    assert(threw, 'oczekiwano PersonDataError dla natural_person');
  });

  // (3c) NEGATYWNY: nationality_of_person => ABORT
  check('NEGATYWNY: nationality_of_person => ABORT', () => {
    const root = [{ component: 'z', nationality_of_person: 'PL' }];
    let threw = false;
    try {
      classify({ declarationsRoot: root, components: ['z'] });
    } catch (e) {
      threw = e instanceof PersonDataError;
    }
    assert(threw, 'oczekiwano PersonDataError dla nationality_of_person');
  });

  // (3d) NEGATYWNY: nationality (narodowość) => ABORT
  check('NEGATYWNY: nationality => ABORT', () => {
    const root = [{ component: 'q', nationality: 'German' }];
    let threw = false;
    try {
      classify({ declarationsRoot: root, components: ['q'] });
    } catch (e) {
      threw = e instanceof PersonDataError;
    }
    assert(threw, 'oczekiwano PersonDataError dla nationality');
  });

  // (4) STRAŻNIK: jawne jurisdiction_class="UNKNOWN" jest zakazane
  check('jawne UNKNOWN => DeclarationError', () => {
    const root = [{ component: 'w', jurisdiction_class: 'UNKNOWN' }];
    let threw = false;
    try {
      classify({ declarationsRoot: root, components: ['w'] });
    } catch (e) {
      threw = e instanceof DeclarationError;
    }
    assert(threw, 'oczekiwano DeclarationError dla jawnego UNKNOWN');
  });

  const passed = cases.filter((c) => c.ok).length;
  const failed = cases.length - passed;
  for (const c of cases) {
    process.stdout.write(`${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.ok ? '' : `  -> ${c.err}`}\n`);
  }
  process.stdout.write(`\n--selftest: ${passed}/${cases.length} PASS, ${failed} FAIL\n`);
  process.exit(failed === 0 ? 0 : 1);
}

// ===========================================================================
// CLI
// ===========================================================================
function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--selftest') args.selftest = true;
    else if (a === '--json') args.json = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--declarations') args.declarations = argv[++i];
    else if (a === '--components') args.components = argv[++i];
    else args._.push(a);
  }
  return args;
}

const HELP = `dep-provenance.mjs — klasyfikacja jurisdiction_class per komponent/podmiot

Użycie:
  node dep-provenance.mjs --declarations <plik.json> [--components <plik.json>] [--json]
  node dep-provenance.mjs --selftest

Klasy: EU | EEA | non-EU | UNKNOWN   (brak deklaracji => UNKNOWN, neutralny)

--declarations  Mapa deklaracji: tablica lub { components: [...] }. Każdy wpis:
                { component|entity, jurisdiction_class } lub { ..., country: "PL" }
                lub { ..., region: "EU" }.
--components    (opcjonalnie) Lista komponentów do sklasyfikowania (tablica nazw
                lub { components: [...] }). Bez tej listy klasyfikowane są
                wszystkie zadeklarowane.
--json          Wyjście maszynowe (JSON).
--selftest      Uruchamia wbudowane testy (pozytywne + NEGATYWNE) i kończy
                exit(0) gdy OK, exit(1) gdy błąd.

TWARDY ZAKAZ: deklaracja z polem person/natural_person/nationality_of_person/
nationality => ABORT (agents-not-people; ZERO klasyfikacji narodowości OSOBY).
`;

function readJson(pathArg) {
  const p = resolve(process.cwd(), pathArg);
  return JSON.parse(readFileSync(p, 'utf8'));
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.selftest) return runSelftest();
  if (args.help || (!args.declarations && args._.length === 0)) {
    process.stdout.write(HELP);
    process.exit(args.help ? 0 : 2);
  }

  const declPath = args.declarations || args._[0];
  if (!declPath) {
    process.stderr.write('Błąd: brak --declarations.\n');
    process.exit(2);
  }

  let out;
  try {
    const declarationsRoot = readJson(declPath);
    const components = args.components ? extractComponentNames(readJson(args.components)) : [];
    out = classify({ declarationsRoot, components });
  } catch (e) {
    process.stderr.write(`${e.name || 'Error'}: ${e.message}\n`);
    process.exit(1);
  }

  if (args.json) {
    process.stdout.write(JSON.stringify(out, null, 2) + '\n');
    return;
  }

  process.stdout.write('KOMPONENT/PODMIOT                          KLASA      ŹRÓDŁO\n');
  process.stdout.write('-------------------------------------------------------------\n');
  for (const r of out.results) {
    const name = r.component.padEnd(42).slice(0, 42);
    const cls = r.jurisdiction_class.padEnd(10);
    const src = r.declared ? 'deklaracja' : 'brak (UNKNOWN neutralny)';
    process.stdout.write(`${name} ${cls} ${src}\n`);
  }
  const s = out.summary;
  process.stdout.write(
    `\nRazem ${out.total} | EU=${s.EU} EEA=${s.EEA} non-EU=${s['non-EU']} UNKNOWN=${s.UNKNOWN}\n`,
  );
}

main();
