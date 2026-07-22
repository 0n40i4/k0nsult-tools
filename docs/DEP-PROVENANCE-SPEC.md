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

PL: Cztery rozłączne strażniki. Każdy ma w `--selftest` **wektor izolujący**
(wyłączenie tego jednego strażnika wywala dokładnie jeden test):

| id | reguła | błąd |
|----|--------|------|
| `GUARD-KEY` | klucz na **dowolnym poziomie** zawierający (jako substring, po normalizacji `lowercase` + `[\s-]→_`) termin osobowy: `person`, `nationality`, `citizen`, `gender`, `pesel`, `passport`, `first_name`, `date_of_birth`, `email`, `phone`, `biometric`, … | `PersonDataError` |
| `GUARD-VALUE` | wartość skalarna o kształcie **e-maila**, **PESEL-u** (suma kontrolna + poprawna część datowa, skanowana w każdym oknie 11 cyfr wewnątrz ciągu cyfr dowolnej długości) lub **telefonu** (9–14 cyfr z separatorami) | `PersonDataError` |
| `GUARD-ID-A` | **wartość** `component`/`entity` zawiera termin osobowy (np. `did:person:fatou.diop`) | `PersonDataError` |
| `GUARD-ID-B` | `component` **oraz** `entity` muszą należeć do **allowlisty przestrzeni nazw**: `pkg:…` (Package URL, `@wersja` dozwolona w środku), `did:…`, `https://…`. Gołe (`left-pad`, `JanKowalski`), kropkowane (`jan.kowalski`, `example.com`) i zawierające spację (`Jan Kowalski`) => ODRZUCONE | `DeclarationError` |

Strażniki działają **fail-fast, PRZED** jakąkolwiek klasyfikacją, i raportują
pełną ścieżkę klucza. Jurysdykcję PODMIOTU deklaruje się polem
`country` / `region` / `jurisdiction_class`, **nigdy** narodowością człowieka.

> ⚠️ **ZNANE OGRANICZENIE (KNOWN-LIMITATIONS.md).** Dopasowanie po stringu **nie
> odróżnia nazwiska od nazwy pakietu**. Identyfikator w dozwolonej przestrzeni
> nazw, który koduje nazwisko (`did:x:local:jan1kowalski:executor`), **przejdzie**
> i zostanie sklasyfikowany. Allowlista **podnosi koszt** nadużycia, ale go **nie
> eliminuje**. To jest ograniczenie strukturalne, nie „naprawione".

EN: Four disjoint guards. Each has an **isolating vector** in `--selftest`
(disabling that one guard fails exactly one test):

| id | rule | error |
|----|------|-------|
| `GUARD-KEY` | a key at **any nesting level** containing (as a substring, after `lowercase` + `[\s-]→_` normalisation) a person term: `person`, `nationality`, `citizen`, `gender`, `pesel`, `passport`, `first_name`, `date_of_birth`, `email`, `phone`, `biometric`, … | `PersonDataError` |
| `GUARD-VALUE` | a scalar value shaped like an **e-mail**, a **PESEL** (checksum + valid date part, scanned over every 11-digit window inside a digit run of any length) or a **phone number** (9–14 digits with separators) | `PersonDataError` |
| `GUARD-ID-A` | the **value** of `component`/`entity` contains a person term (e.g. `did:person:fatou.diop`) | `PersonDataError` |
| `GUARD-ID-B` | `component` **and** `entity` must belong to the **namespace allowlist**: `pkg:…` (Package URL, `@version` allowed mid-string), `did:…`, `https://…`. Bare (`left-pad`, `JanKowalski`), dotted (`jan.kowalski`, `example.com`) and space-containing (`Jan Kowalski`) identifiers are REJECTED | `DeclarationError` |

The guards are **fail-fast, BEFORE** any classification, and report the full key
path. The jurisdiction of an ENTITY is declared with the
`country` / `region` / `jurisdiction_class` field, **never** with a person's
nationality.

> ⚠️ **KNOWN LIMITATION (KNOWN-LIMITATIONS.md).** String matching **cannot
> distinguish a surname from a package name**. An identifier inside an allowed
> namespace that encodes a surname (`did:x:local:jan1kowalski:executor`) **will
> pass** and be classified. The allowlist **raises the cost** of misuse; it does
> **not eliminate** it. This is a structural limitation, not "fixed".

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

PL: Samowystarczalny (wbudowane fixtures, ZERO plików zewnętrznych), **27
przypadków**: **pozytywne** (EU/EEA/non-EU, purl `pkg:npm/express@4.18.2`),
**neutralny** (brak deklaracji => UNKNOWN) oraz **NEGATYWNE** (pola/wartości
osobowe, identyfikatory poza allowlistą, duplikat deklaracji => ABORT).
`exit(0)` gdy wszystko przeszło, `exit(1)` gdy cokolwiek zawiodło.

Przypadki oznaczone `[izolujący]` to **wektory mutacyjne**: wyłączenie
odpowiadającego im pojedynczego strażnika (warunek → `if (false)`) wywala
**dokładnie jeden** test. Wektory bez tego oznaczenia są **regresyjne** —
potwierdzają werdykt, ale są współdzielone przez kilka strażników i **nie
dowodzą**, że konkretny strażnik działa.

EN: Self-contained (built-in fixtures, ZERO external files), **27 cases**:
**positive** (EU/EEA/non-EU, purl `pkg:npm/express@4.18.2`), a **neutral** case
(no declaration => UNKNOWN) and **NEGATIVE** cases (person keys/values,
identifiers outside the allowlist, duplicate declaration => ABORT). `exit(0)`
when everything passed, `exit(1)` when anything failed.

Cases marked `[izolujący]` are **mutation vectors**: disabling the single
corresponding guard (condition → `if (false)`) fails **exactly one** test.
Unmarked vectors are **regression** vectors — they confirm the verdict but are
shared between guards and therefore do **not** prove that a specific guard works.

```
node dep-provenance.mjs --selftest
```
