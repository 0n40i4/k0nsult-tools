#!/usr/bin/env node
// attest-verify.mjs — K0NSULT open commons
// Weryfikator atestacji CRA art.25 — sciezka BEZ podpisywania.
//
// DOKTRYNA:
//   - claim <= proof: narzedzie weryfikuje, nie twierdzi wiecej niz udowodni hash.
//   - silnik ukryty: ZERO kodu k0nsult.cloud.
//   - agents-not-people: ZERO PII, zero scoringu osob.
//   - soulbound NIE krypto.
//   - No Password Custody: narzedzie NIGDY nie generuje, nie przechowuje ani nie
//     prosi o klucz prywatny. Podpis powstaje wylacznie u operatora, poza narzedziem.
//
// Node >= 18. ZERO zaleznosci zewnetrznych (tylko wbudowane: crypto).
// Offline, deterministyczne.
//
// verify(record, artifactBuffer) => { hash_ok, signer, status }
//
// Wybor backendu signer (record.signer, domyslnie "none"):
//   none    => UNSIGNED_DRAFT   (brak podpisu — draft, dozwolone)
//   keyless => HALT_FOR_ACK     (Rekor/transparency log NIEODWRACALNY — wymaga ACK
//                                operatora; narzedzie NIE podpisuje)
//   offline => BLOCKED          (brak klucza operatora w narzedziu — No Password
//                                Custody; podpis robi operator poza narzedziem)
//
// Narzedzie NIGDY nie tworzy podpisu. Zwraca tylko werdykt.

import { createHash } from 'node:crypto';

const SIGNER_DEFAULT = 'none';

// Kanoniczne statusy — jeden zrodlo prawdy.
export const STATUS = Object.freeze({
  UNSIGNED_DRAFT: 'UNSIGNED_DRAFT',
  HALT_FOR_ACK: 'HALT_FOR_ACK',
  BLOCKED: 'BLOCKED',
  INVALID_HASH: 'INVALID_HASH',
  BAD_RECORD: 'BAD_RECORD',
});

const SIGNER_BACKENDS = Object.freeze(['none', 'keyless', 'offline']);

function sha256Hex(buf) {
  return createHash('sha256').update(buf).digest('hex');
}

function toBuffer(artifact) {
  if (Buffer.isBuffer(artifact)) return artifact;
  if (artifact instanceof Uint8Array) return Buffer.from(artifact);
  if (typeof artifact === 'string') return Buffer.from(artifact, 'utf8');
  return null;
}

/**
 * Weryfikuje rekord atestacji wzgledem bufora artefaktu.
 * NIE podpisuje. NIE dotyka klucza prywatnego.
 *
 * @param {object} record          - rekord atestacji (JSON).
 * @param {string} record.content_sha256 - oczekiwany sha256 (hex) artefaktu.
 * @param {string} [record.signer] - backend: none | keyless | offline.
 * @param {Buffer|Uint8Array|string} artifactBuffer - tresc artefaktu.
 * @returns {{hash_ok:boolean, signer:string, status:string}}
 */
export function verify(record, artifactBuffer) {
  // --- walidacja rekordu (fail-closed) ---
  if (record == null || typeof record !== 'object') {
    return { hash_ok: false, signer: SIGNER_DEFAULT, status: STATUS.BAD_RECORD };
  }

  const signer = record.signer == null ? SIGNER_DEFAULT : record.signer;
  if (!SIGNER_BACKENDS.includes(signer)) {
    return { hash_ok: false, signer: String(signer), status: STATUS.BAD_RECORD };
  }

  const expected = record.content_sha256;
  if (typeof expected !== 'string' || !/^[0-9a-f]{64}$/i.test(expected)) {
    return { hash_ok: false, signer, status: STATUS.BAD_RECORD };
  }

  const buf = toBuffer(artifactBuffer);
  if (buf === null) {
    return { hash_ok: false, signer, status: STATUS.BAD_RECORD };
  }

  // --- weryfikacja hash (claim <= proof) ---
  const actual = sha256Hex(buf);
  const hash_ok = actual.toLowerCase() === expected.toLowerCase();

  if (!hash_ok) {
    // Artefakt nie zgadza sie z rekordem — atestacja bezwartosciowa.
    return { hash_ok: false, signer, status: STATUS.INVALID_HASH };
  }

  // --- wybor statusu wg backendu signer (narzedzie NIGDY nie podpisuje) ---
  let status;
  switch (signer) {
    case 'none':
      status = STATUS.UNSIGNED_DRAFT;
      break;
    case 'keyless':
      // Rekor / transparency log = akt NIEODWRACALNY. Wymaga ACK operatora.
      status = STATUS.HALT_FOR_ACK;
      break;
    case 'offline':
      // No Password Custody — klucza operatora NIE ma w narzedziu.
      status = STATUS.BLOCKED;
      break;
  }

  return { hash_ok, signer, status };
}

// ---------------------------------------------------------------------------
// SELFTEST — samowystarczalny, wbudowane fixtures. Pozytywne I NEGATYWNE.
// ---------------------------------------------------------------------------
function selftest() {
  const cases = [];
  const rec = (msg, expect, cond) => cases.push({ msg, expect, ok: cond });

  const artifact = Buffer.from('K0NSULT attest artifact v1\n', 'utf8');
  const goodHash = sha256Hex(artifact);
  const tampered = Buffer.from('K0NSULT attest artifact v1 TAMPERED\n', 'utf8');

  // 1. Poprawny hash, signer=none => hash_ok true, UNSIGNED_DRAFT (default).
  {
    const r = verify({ content_sha256: goodHash }, artifact);
    rec('none: poprawny hash => UNSIGNED_DRAFT', 'hash_ok=true,UNSIGNED_DRAFT',
      r.hash_ok === true && r.signer === 'none' && r.status === STATUS.UNSIGNED_DRAFT);
  }

  // 2. Zmieniony artefakt => hash_ok false (NEGATYWNY).
  {
    const r = verify({ content_sha256: goodHash }, tampered);
    rec('none: zmieniony artefakt => hash_ok false + INVALID_HASH', 'hash_ok=false,INVALID_HASH',
      r.hash_ok === false && r.status === STATUS.INVALID_HASH);
  }

  // 3. signer=keyless, poprawny hash => HALT_FOR_ACK (nie podpisano).
  {
    const r = verify({ content_sha256: goodHash, signer: 'keyless' }, artifact);
    rec('keyless: poprawny hash => HALT_FOR_ACK', 'hash_ok=true,HALT_FOR_ACK',
      r.hash_ok === true && r.signer === 'keyless' && r.status === STATUS.HALT_FOR_ACK);
  }

  // 4. signer=offline, poprawny hash => BLOCKED (No Password Custody).
  {
    const r = verify({ content_sha256: goodHash, signer: 'offline' }, artifact);
    rec('offline: poprawny hash => BLOCKED', 'hash_ok=true,BLOCKED',
      r.hash_ok === true && r.signer === 'offline' && r.status === STATUS.BLOCKED);
  }

  // 5. NEGATYWNY: keyless + zmieniony artefakt => INVALID_HASH (hash bije przed podpisem).
  {
    const r = verify({ content_sha256: goodHash, signer: 'keyless' }, tampered);
    rec('keyless: zmieniony artefakt => INVALID_HASH (nie HALT)', 'hash_ok=false,INVALID_HASH',
      r.hash_ok === false && r.status === STATUS.INVALID_HASH);
  }

  // 6. NEGATYWNY: brak content_sha256 => BAD_RECORD.
  {
    const r = verify({ signer: 'none' }, artifact);
    rec('brak content_sha256 => BAD_RECORD', 'BAD_RECORD',
      r.hash_ok === false && r.status === STATUS.BAD_RECORD);
  }

  // 7. NEGATYWNY: nieznany backend signer => BAD_RECORD.
  {
    const r = verify({ content_sha256: goodHash, signer: 'ledger' }, artifact);
    rec('nieznany signer => BAD_RECORD', 'BAD_RECORD',
      r.hash_ok === false && r.status === STATUS.BAD_RECORD);
  }

  // 8. NEGATYWNY: content_sha256 zly format => BAD_RECORD.
  {
    const r = verify({ content_sha256: 'deadbeef' }, artifact);
    rec('zly format sha256 => BAD_RECORD', 'BAD_RECORD',
      r.hash_ok === false && r.status === STATUS.BAD_RECORD);
  }

  // 9. NEGATYWNY: record=null => BAD_RECORD (fail-closed).
  {
    const r = verify(null, artifact);
    rec('record=null => BAD_RECORD', 'BAD_RECORD',
      r.hash_ok === false && r.status === STATUS.BAD_RECORD);
  }

  // 10. Domyslny signer to none, gdy pole nieobecne.
  {
    const r = verify({ content_sha256: goodHash }, artifact);
    rec('domyslny signer=none', 'signer=none', r.signer === 'none');
  }

  // 11. Artefakt jako string (utf8) — akceptowany.
  {
    const r = verify({ content_sha256: goodHash }, 'K0NSULT attest artifact v1\n');
    rec('artefakt jako string utf8', 'hash_ok=true', r.hash_ok === true);
  }

  let passed = 0;
  for (const c of cases) {
    const mark = c.ok ? 'PASS' : 'FAIL';
    if (c.ok) passed++;
    console.log(`[${mark}] ${c.msg}  (oczekiwano: ${c.expect})`);
  }
  const all = passed === cases.length;
  console.log(`\n${passed}/${cases.length} testow przeszlo — ${all ? 'OK' : 'BLAD'}`);
  return all;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function main(argv) {
  const args = argv.slice(2);

  if (args.includes('--selftest')) {
    process.exit(selftest() ? 0 : 1);
  }

  if (args.includes('--help') || args.includes('-h') || args.length === 0) {
    console.log(`attest-verify.mjs — weryfikator atestacji CRA art.25 (BEZ podpisywania)

Uzycie:
  node attest-verify.mjs --record <record.json> --artifact <plik>
  node attest-verify.mjs --selftest

Doktryna: No Password Custody — narzedzie NIGDY nie podpisuje.
  signer=none    => UNSIGNED_DRAFT
  signer=keyless => HALT_FOR_ACK  (Rekor nieodwracalny — wymaga ACK operatora)
  signer=offline => BLOCKED       (klucz operatora poza narzedziem)`);
    process.exit(args.length === 0 ? 1 : 0);
  }

  const recIdx = args.indexOf('--record');
  const artIdx = args.indexOf('--artifact');
  if (recIdx === -1 || artIdx === -1 || !args[recIdx + 1] || !args[artIdx + 1]) {
    console.error('BLAD: wymagane --record <plik.json> oraz --artifact <plik>');
    process.exit(1);
  }

  // Lazy import fs tylko w trybie CLI-plikowym (selftest go nie potrzebuje).
  import('node:fs').then((fs) => {
    let record;
    try {
      record = JSON.parse(fs.readFileSync(args[recIdx + 1], 'utf8'));
    } catch (e) {
      console.error(`BLAD: nie moge wczytac/parsowac rekordu: ${e.message}`);
      process.exit(1);
    }
    let artifactBuffer;
    try {
      artifactBuffer = fs.readFileSync(args[artIdx + 1]);
    } catch (e) {
      console.error(`BLAD: nie moge wczytac artefaktu: ${e.message}`);
      process.exit(1);
    }
    const result = verify(record, artifactBuffer);
    console.log(JSON.stringify(result, null, 2));
    // Exit: 0 tylko gdy hash sie zgadza; status to sygnal, nie blad procesu.
    process.exit(result.hash_ok ? 0 : 1);
  });
}

// Uruchom CLI tylko gdy plik wywolany bezposrednio.
const invokedDirectly =
  process.argv[1] && import.meta.url === new URL(`file://${process.argv[1].replace(/\\/g, '/')}`).href;
if (invokedDirectly || (process.argv[1] && process.argv[1].endsWith('attest-verify.mjs'))) {
  main(process.argv);
}
