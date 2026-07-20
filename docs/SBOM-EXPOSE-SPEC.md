# SBOM-EXPOSE-SPEC

PL: `sbom-expose.mjs` — narzedzie open commons K0NSULT. Wczytuje SBOM w formacie
CycloneDX oraz LOKALNA, offline'owa migawke podatnosci i dla kazdego komponentu
`type=library` z `purl` emituje status **ekspozycji**. Zero sieci, zero
zaleznosci (tylko wbudowane `node:fs`), deterministyczne. Node >= 18.

EN: `sbom-expose.mjs` — a K0NSULT open-commons tool. It reads an SBOM in
CycloneDX format plus a LOCAL, offline vulnerability snapshot and, for every
component with `type=library` and a `purl`, emits an **exposure** status. Zero
network, zero dependencies (built-in `node:fs` only), deterministic. Node >= 18.

## Doktryna / Doctrine

PL:
- **claim <= proof** — narzedzie nie twierdzi wiecej niz wynika z danych.
- **NO_MATCH NIGDY nie znaczy "bezpieczny"** — znaczy jedynie: sprawdzono wobec
  TEJ migawki i nie znaleziono trafienia. Migawka moze byc niepelna/nieaktualna.
- **Brak migawki => jawny GAP** — kazdy komponent dostaje `NO_FEED`, nie falszywy
  spokoj.
- **Silnik ukryty** — zero kodu k0nsult.cloud, zero PII, zero sekretow.

EN:
- **claim <= proof** — the tool never asserts more than the data supports.
- **NO_MATCH NEVER means "safe"** — it means only: checked against THIS
  snapshot and no hit found. The snapshot may be incomplete/outdated.
- **No snapshot => explicit GAP** — every component gets `NO_FEED`, not false
  reassurance.
- **Engine hidden** — zero k0nsult.cloud code, zero PII, zero secrets.

## Wejscie / Input

### `--sbom <sciezka>` (wymagane / required)

PL: CycloneDX JSON: obiekt z tablica `components`. Oceniane sa wylacznie komponenty o
`type === "library"` posiadajace niepuste pole `purl`. Pozostale sa pomijane.

EN: CycloneDX JSON: an object with a `components` array. Only components with
`type === "library"` and a non-empty `purl` field are assessed. All others are
skipped.

### `--snapshot <sciezka>` (opcjonalne / optional)

PL: Migawka podatnosci:
EN: Vulnerability snapshot:

```json
{
  "feed_id": "string",
  "snapshot_date": "YYYY-MM-DD",
  "entries": [
    { "purl_prefix": "pkg:npm/lodash", "id": "CVE-...", "affected_range": ">=4.0.0 <4.17.21" }
  ]
}
```

PL: Bez `--snapshot` wszystkie komponenty => `NO_FEED`.
EN: Without `--snapshot`, all components => `NO_FEED`.

## Stany ekspozycji / Exposure states

| Stan / State | Znaczenie / Meaning |
|---|---|
| `MATCH` | PL: Wersja komponentu miesci sie w `affected_range` dopasowanego wpisu (`purl_prefix`). Niesie liste `id` advisory. — EN: The component version falls within the `affected_range` of a matched entry (`purl_prefix`). Carries the list of advisory `id`s. |
| `NO_MATCH` | PL: Feed sprawdzony, brak trafienia. **NIE jest dowodem bezpieczenstwa.** — EN: Feed checked, no hit. **NOT a proof of safety.** |
| `RANGE_UNKNOWN` | PL: Wpis pasuje do komponentu, ale `affected_range` jest pusty/nieparsowalny — nie sposob ustalic. — EN: An entry matches the component, but `affected_range` is empty/unparseable — impossible to determine. |
| `UNVERSIONED` | PL: `purl` bez wersji — nie sposob ocenic. — EN: `purl` without a version — impossible to assess. |
| `NO_FEED` | PL: Brak migawki — jawny GAP. — EN: No snapshot — explicit GAP. |

## Dopasowanie / Matching

PL:
- **purl_prefix** dopasowywany jest na granicy segmentu: `pkg:npm/lodash` pasuje do
  `pkg:npm/lodash@4.17.20`, ale NIE do `pkg:npm/lodash-es@...`.
- **affected_range** obsluguje: `>=`, `>`, `<=`, `<`, `=`; wiele tokenow (AND) po
  spacji/przecinku; zakres hyphenowy `A - B` (inkluzywny). Porownanie semver-owe
  numeryczne (nie leksykalne), prerelease/build odcinane. Nieparsowalny zakres =>
  `RANGE_UNKNOWN`.

EN:
- **purl_prefix** is matched on a segment boundary: `pkg:npm/lodash` matches
  `pkg:npm/lodash@4.17.20`, but NOT `pkg:npm/lodash-es@...`.
- **affected_range** supports: `>=`, `>`, `<=`, `<`, `=`; multiple tokens (AND)
  separated by space/comma; hyphenated range `A - B` (inclusive). Semver
  comparison is numeric (not lexical), with prerelease/build stripped. An
  unparseable range => `RANGE_UNKNOWN`.

## Priorytet klasyfikacji komponentu / Component classification priority

PL:
1. brak migawki -> `NO_FEED`
2. `purl` bez wersji -> `UNVERSIONED`
3. ktorykolwiek pasujacy wpis z wersja w zakresie -> `MATCH`
4. inaczej, ktorykolwiek pasujacy wpis z nieparsowalnym zakresem -> `RANGE_UNKNOWN`
5. inaczej -> `NO_MATCH`

EN:
1. no snapshot -> `NO_FEED`
2. `purl` without a version -> `UNVERSIONED`
3. any matching entry with the version in range -> `MATCH`
4. otherwise, any matching entry with an unparseable range -> `RANGE_UNKNOWN`
5. otherwise -> `NO_MATCH`

## Wyjscie / Output

PL: Tekstowe (domyslnie) lub `--json`. Raport zawiera `feed_id`, `snapshot_date`,
`feed_present`, `components_assessed`, `summary` (licznik per stan), `results` oraz
`note` z disclaimerem o NO_MATCH.

EN: Text (default) or `--json`. The report contains `feed_id`, `snapshot_date`,
`feed_present`, `components_assessed`, `summary` (count per state), `results`, and
a `note` with the NO_MATCH disclaimer.

## Self-test

```
node sbom-expose.mjs --selftest
```

PL: Uruchamia wbudowane fixtures (maly SBOM + migawka), asercje pozytywne i NEGATYWNE:
znany purl w zakresie => `MATCH`; purl spoza migawki => `NO_MATCH`; wersja poza
zakresem => `NO_MATCH`; granica prefiksu (`lodash-es` nie trafia na `lodash`);
purl bez wersji => `UNVERSIONED`; zakres nieparsowalny => `RANGE_UNKNOWN`; brak
migawki => wszystko `NO_FEED`. `exit(0)` gdy wszystko przeszlo, `exit(1)` gdy nie.

EN: Runs built-in fixtures (a small SBOM + snapshot), with positive and NEGATIVE
assertions: a known purl in range => `MATCH`; a purl outside the snapshot =>
`NO_MATCH`; a version outside the range => `NO_MATCH`; the prefix boundary
(`lodash-es` does not hit `lodash`); a purl without a version => `UNVERSIONED`; an
unparseable range => `RANGE_UNKNOWN`; no snapshot => everything `NO_FEED`.
`exit(0)` when all passed, `exit(1)` when not.
