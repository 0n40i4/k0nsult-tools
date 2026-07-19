# DEP-PROVENANCE-SPEC

Specyfikacja narzędzia `dep-provenance.mjs` (K0NSULT open commons).

## Cel

Klasyfikacja **proweniencji jurysdykcyjnej** zależności/komponentów oprogramowania
na osi `jurisdiction_class ∈ { EU | EEA | non-EU | UNKNOWN }`, wyłącznie na
podstawie **deklaracji** dostarczonych przez operatora (`--declarations`).

Narzędzie jest **deterministyczne**, **offline** (zero sieci), bez zależności
(tylko wbudowane moduły Node >= 18: `node:fs`, `node:path`).

## Doktryna (wiążąca)

- **claim ≤ proof** — klasa wynika WYŁĄCZNIE z deklaracji. Brak deklaracji dla
  komponentu => `UNKNOWN`. `UNKNOWN` jest **neutralny** (nie kara, nie minus).
- **agents-not-people** — narzędzie klasyfikuje KOMPONENTY i PODMIOTY, **nigdy
  osoby**. Zero PII, zero scoringu ludzi.
- **silnik ukryty** — brak jakiegokolwiek kodu k0nsult.cloud, brak sekretów.

## TWARDY ZAKAZ (fail-fast)

Jeśli JAKAKOLWIEK deklaracja zawiera — na **dowolnym poziomie zagnieżdżenia** —
klucz:

- `person`
- `natural_person`
- `nationality_of_person`
- `nationality`

=> narzędzie **przerywa** (`PersonDataError`, `exit 1`) PRZED jakąkolwiek
klasyfikacją i raportuje pełną ścieżkę klucza. Jurysdykcję PODMIOTU deklaruje
się polem `country` / `region` / `jurisdiction_class`, **nigdy** narodowością
człowieka.

## Wejście: `--declarations <plik.json>`

Tablica deklaracji lub obiekt `{ "components": [...] }` /
`{ "declarations": [...] }`. Każda deklaracja:

| pole                 | opis                                                              |
|----------------------|-------------------------------------------------------------------|
| `component`/`entity` | identyfikator komponentu/podmiotu (wymagany, co najmniej jedno)    |
| `jurisdiction_class` | jawnie `EU` \| `EEA` \| `non-EU` (jawne `UNKNOWN` ZAKAZANE)        |
| `region`             | `EU` \| `EEA` \| `non-EU`                                          |
| `country`            | ISO 3166-1 alpha-2 (mapowane: 27×UE=EU; IS/LI/NO=EEA; reszta=non-EU)|

Priorytet rozwiązywania: `jurisdiction_class` > `region` > `country`.

## Wejście opcjonalne: `--components <plik.json>`

Lista nazw komponentów do sklasyfikowania (tablica stringów/obiektów lub
`{ "components": [...] }`). Komponent bez deklaracji => `UNKNOWN` (`declared:false`).
Bez tego pliku klasyfikowane są wszystkie zadeklarowane komponenty.

## Wyjście

- domyślnie: czytelna tabela + podsumowanie liczności klas,
- `--json`: `{ results:[{component,jurisdiction_class,declared}], summary, total }`.

## `--selftest`

Samowystarczalny (wbudowane fixtures, ZERO plików zewnętrznych). Uruchamia
przypadki **pozytywne** (EU/EEA/non-EU), **neutralny** (brak deklaracji => UNKNOWN)
oraz **NEGATYWNE** (pola osobowe => ABORT). `exit(0)` gdy wszystko przeszło,
`exit(1)` gdy cokolwiek zawiodło.

```
node dep-provenance.mjs --selftest
```
