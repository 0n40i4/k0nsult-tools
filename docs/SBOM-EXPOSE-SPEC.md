# SBOM-EXPOSE-SPEC

`sbom-expose.mjs` — narzedzie open commons K0NSULT. Wczytuje SBOM w formacie
CycloneDX oraz LOKALNA, offline'owa migawke podatnosci i dla kazdego komponentu
`type=library` z `purl` emituje status **ekspozycji**. Zero sieci, zero
zaleznosci (tylko wbudowane `node:fs`), deterministyczne. Node >= 18.

## Doktryna

- **claim <= proof** — narzedzie nie twierdzi wiecej niz wynika z danych.
- **NO_MATCH NIGDY nie znaczy "bezpieczny"** — znaczy jedynie: sprawdzono wobec
  TEJ migawki i nie znaleziono trafienia. Migawka moze byc niepelna/nieaktualna.
- **Brak migawki => jawny GAP** — kazdy komponent dostaje `NO_FEED`, nie falszywy
  spokoj.
- **Silnik ukryty** — zero kodu k0nsult.cloud, zero PII, zero sekretow.

## Wejscie

### `--sbom <sciezka>` (wymagane)
CycloneDX JSON: obiekt z tablica `components`. Oceniane sa wylacznie komponenty o
`type === "library"` posiadajace niepuste pole `purl`. Pozostale sa pomijane.

### `--snapshot <sciezka>` (opcjonalne)
Migawka podatnosci:
```json
{
  "feed_id": "string",
  "snapshot_date": "YYYY-MM-DD",
  "entries": [
    { "purl_prefix": "pkg:npm/lodash", "id": "CVE-...", "affected_range": ">=4.0.0 <4.17.21" }
  ]
}
```
Bez `--snapshot` wszystkie komponenty => `NO_FEED`.

## Stany ekspozycji

| Stan | Znaczenie |
|---|---|
| `MATCH` | Wersja komponentu miesci sie w `affected_range` dopasowanego wpisu (`purl_prefix`). Niesie liste `id` advisory. |
| `NO_MATCH` | Feed sprawdzony, brak trafienia. **NIE jest dowodem bezpieczenstwa.** |
| `RANGE_UNKNOWN` | Wpis pasuje do komponentu, ale `affected_range` jest pusty/nieparsowalny — nie sposob ustalic. |
| `UNVERSIONED` | `purl` bez wersji — nie sposob ocenic. |
| `NO_FEED` | Brak migawki — jawny GAP. |

## Dopasowanie

- **purl_prefix** dopasowywany jest na granicy segmentu: `pkg:npm/lodash` pasuje do
  `pkg:npm/lodash@4.17.20`, ale NIE do `pkg:npm/lodash-es@...`.
- **affected_range** obsluguje: `>=`, `>`, `<=`, `<`, `=`; wiele tokenow (AND) po
  spacji/przecinku; zakres hyphenowy `A - B` (inkluzywny). Porownanie semver-owe
  numeryczne (nie leksykalne), prerelease/build odcinane. Nieparsowalny zakres =>
  `RANGE_UNKNOWN`.

## Priorytet klasyfikacji komponentu

1. brak migawki -> `NO_FEED`
2. `purl` bez wersji -> `UNVERSIONED`
3. ktorykolwiek pasujacy wpis z wersja w zakresie -> `MATCH`
4. inaczej, ktorykolwiek pasujacy wpis z nieparsowalnym zakresem -> `RANGE_UNKNOWN`
5. inaczej -> `NO_MATCH`

## Wyjscie

Tekstowe (domyslnie) lub `--json`. Raport zawiera `feed_id`, `snapshot_date`,
`feed_present`, `components_assessed`, `summary` (licznik per stan), `results` oraz
`note` z disclaimerem o NO_MATCH.

## Self-test

```
node sbom-expose.mjs --selftest
```
Uruchamia wbudowane fixtures (maly SBOM + migawka), asercje pozytywne i NEGATYWNE:
znany purl w zakresie => `MATCH`; purl spoza migawki => `NO_MATCH`; wersja poza
zakresem => `NO_MATCH`; granica prefiksu (`lodash-es` nie trafia na `lodash`);
purl bez wersji => `UNVERSIONED`; zakres nieparsowalny => `RANGE_UNKNOWN`; brak
migawki => wszystko `NO_FEED`. `exit(0)` gdy wszystko przeszlo, `exit(1)` gdy nie.
