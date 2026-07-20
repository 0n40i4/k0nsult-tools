# DEP-PROVENANCE-SPEC

PL: Specyfikacja narzędzia `dep-provenance.mjs` (K0NSULT open commons).

EN: Specification of the `dep-provenance.mjs` tool (K0NSULT open commons).

## Cel / Purpose

PL: Klasyfikacja **proweniencji jurysdykcyjnej** zależności/komponentów oprogramowania
na osi `jurisdiction_class ∈ { EU | EEA | non-EU | UNKNOWN }`, wyłącznie na
podstawie **deklaracji** dostarczonych przez operatora (`--declarations`).

Narzędzie jest **deterministyczne**, **offline** (zero sieci), bez zależności
(tylko wbudowane moduły Node >= 18: `node:fs`, `node:path`).

EN: Classification of the **jurisdictional provenance** of software
dependencies/components along the axis
`jurisdiction_class ∈ { EU | EEA | non-EU | UNKNOWN }`, based solely on the
**declarations** supplied by the operator (`--declarations`).

The tool is **deterministic**, **offline** (zero network), dependency-free
(only built-in Node >= 18 modules: `node:fs`, `node:path`).

## Doktryna (wiążąca) / Doctrine (binding)

PL:
- **claim ≤ proof** — klasa wynika WYŁĄCZNIE z deklaracji. Brak deklaracji dla
  komponentu => `UNKNOWN`. `UNKNOWN` jest **neutralny** (nie kara, nie minus).
- **agents-not-people** — narzędzie klasyfikuje KOMPONENTY i PODMIOTY, **nigdy
  osoby**. Zero PII, zero scoringu ludzi.
- **silnik ukryty** — brak jakiegokolwiek kodu k0nsult.cloud, brak sekretów.

EN:
- **claim ≤ proof** — the class follows SOLELY from the declaration. No
  declaration for a component => `UNKNOWN`. `UNKNOWN` is **neutral** (not a
  penalty, not a minus).
- **agents-not-people** — the tool classifies COMPONENTS and ENTITIES, **never
  people**. Zero PII, zero scoring of humans.
- **hidden engine** — no k0nsult.cloud code whatsoever, no secrets.

## TWARDY ZAKAZ (fail-fast) / HARD PROHIBITION (fail-fast)

PL: Jeśli JAKAKOLWIEK deklaracja zawiera — na **dowolnym poziomie zagnieżdżenia** —
klucz:

- `person`
- `natural_person`
- `nationality_of_person`
- `nationality`

=> narzędzie **przerywa** (`PersonDataError`, `exit 1`) PRZED jakąkolwiek
klasyfikacją i raportuje pełną ścieżkę klucza. Jurysdykcję PODMIOTU deklaruje
się polem `country` / `region` / `jurisdiction_class`, **nigdy** narodowością
człowieka.

EN: If ANY declaration contains — at **any nesting level** — the key:

- `person`
- `natural_person`
- `nationality_of_person`
- `nationality`

=> the tool **aborts** (`PersonDataError`, `exit 1`) BEFORE any classification
and reports the full key path. The jurisdiction of an ENTITY is declared with
the `country` / `region` / `jurisdiction_class` field, **never** with a
person's nationality.

## Wejście: `--declarations <plik.json>` / Input: `--declarations <file.json>`

PL: Tablica deklaracji lub obiekt `{ "components": [...] }` /
`{ "declarations": [...] }`. Każda deklaracja:

| pole                 | opis                                                              |
|----------------------|-------------------------------------------------------------------|
| `component`/`entity` | identyfikator komponentu/podmiotu (wymagany, co najmniej jedno)    |
| `jurisdiction_class` | jawnie `EU` \| `EEA` \| `non-EU` (jawne `UNKNOWN` ZAKAZANE)        |
| `region`             | `EU` \| `EEA` \| `non-EU`                                          |
| `country`            | ISO 3166-1 alpha-2 (mapowane: 27×UE=EU; IS/LI/NO=EEA; reszta=non-EU)|

Priorytet rozwiązywania: `jurisdiction_class` > `region` > `country`.

EN: An array of declarations or an object `{ "components": [...] }` /
`{ "declarations": [...] }`. Each declaration:

| field                | description                                                       |
|----------------------|-------------------------------------------------------------------|
| `component`/`entity` | component/entity identifier (required, at least one)              |
| `jurisdiction_class` | explicit `EU` \| `EEA` \| `non-EU` (explicit `UNKNOWN` FORBIDDEN)  |
| `region`             | `EU` \| `EEA` \| `non-EU`                                          |
| `country`            | ISO 3166-1 alpha-2 (mapped: 27×EU=EU; IS/LI/NO=EEA; rest=non-EU)   |

Resolution priority: `jurisdiction_class` > `region` > `country`.

## Wejście opcjonalne: `--components <plik.json>` / Optional input: `--components <file.json>`

PL: Lista nazw komponentów do sklasyfikowania (tablica stringów/obiektów lub
`{ "components": [...] }`). Komponent bez deklaracji => `UNKNOWN` (`declared:false`).
Bez tego pliku klasyfikowane są wszystkie zadeklarowane komponenty.

EN: A list of component names to classify (an array of strings/objects or
`{ "components": [...] }`). A component with no declaration => `UNKNOWN`
(`declared:false`). Without this file, all declared components are classified.

## Wyjście / Output

PL:
- domyślnie: czytelna tabela + podsumowanie liczności klas,
- `--json`: `{ results:[{component,jurisdiction_class,declared}], summary, total }`.

EN:
- default: a human-readable table + a summary of class counts,
- `--json`: `{ results:[{component,jurisdiction_class,declared}], summary, total }`.

## `--selftest`

PL: Samowystarczalny (wbudowane fixtures, ZERO plików zewnętrznych). Uruchamia
przypadki **pozytywne** (EU/EEA/non-EU), **neutralny** (brak deklaracji => UNKNOWN)
oraz **NEGATYWNE** (pola osobowe => ABORT). `exit(0)` gdy wszystko przeszło,
`exit(1)` gdy cokolwiek zawiodło.

EN: Self-contained (built-in fixtures, ZERO external files). Runs **positive**
cases (EU/EEA/non-EU), a **neutral** case (no declaration => UNKNOWN) and
**NEGATIVE** cases (person fields => ABORT). `exit(0)` when everything passed,
`exit(1)` when anything failed.

```
node dep-provenance.mjs --selftest
```
