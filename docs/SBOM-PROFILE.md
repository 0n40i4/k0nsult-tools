# SBOM Profile — CycloneDX-lite (K0NSULT)

> **Evidence class: DOWÓD.** Każde zdanie normatywne w tym profilu jest
> sprawdzalne bajt-w-bajt względem pliku `sbom.json` wygenerowanego przez
> `sbom.mjs` na dowolnym katalogu. Nie ma tu obietnic — jest kontrakt formatu.
> Weryfikacja: `node sbom.mjs --root <dir> --out /tmp/s.json` i porównanie
> emitowanych pól z tabelami poniżej.

PL: Profil opisuje **podzbiór** CycloneDX 1.5 ("lite"), który emituje generator
`sbom.mjs`. Celem jest inwentarz **każdego pliku** danej powierzchni, przypięty
SHA-256, tak by strona trzecia (regulator, zamawiający, audytor) mogła
zweryfikować **co dokładnie** publikacja wystawia — bajt w bajt.

EN: This profile defines the **subset** of CycloneDX 1.5 ("lite") emitted by
`sbom.mjs`. Its purpose is a **per-file** inventory of a surface, each pinned by
SHA-256, so a third party (regulator, contracting authority, auditor) can verify
**exactly** what a publication exposes — byte for byte.

---

## 1. Zakres / Scope

PL:
- **Wchodzi:** każdy plik pod `--root` (rekurencyjnie), plus zadeklarowane
  zależności node z każdego napotkanego `package.json`.
- **Wykluczone z rekurencji:** katalogi `.git/` i `node_modules/`.
- **Wykluczone z inwentarza:** własny plik wyjściowy (`--out`), by SBOM nie
  liczył sam siebie.
- **Read-only:** generator wyłącznie **czyta** katalog źródłowy i **pisze**
  jeden plik `--out`. Nie modyfikuje powierzchni.

EN:
- **Included:** every file under `--root` (recursive), plus node dependencies
  declared in each encountered `package.json`.
- **Excluded from recursion:** `.git/` and `node_modules/` directories.
- **Excluded from inventory:** the output file itself (`--out`), so the SBOM
  never counts itself.
- **Read-only:** the generator only **reads** the source tree and **writes** a
  single `--out` file. It never mutates the surface.

---

## 2. Klasyfikacja plików / File classification

Klasyfikacja jest deterministyczna, wyłącznie po rozszerzeniu (case-insensitive).
Classification is deterministic, by file extension only (case-insensitive).

| `group` | CycloneDX `type` | Rozszerzenia / Extensions              | Znaczenie / Meaning                          |
|---------|------------------|----------------------------------------|----------------------------------------------|
| `html`  | `file`           | `.html`, `.htm`                        | Powierzchnia wystawiana użytkownikowi / user-facing surface |
| `data`  | `data`           | `.json`                                | Dane / schematy / konfiguracja / data, schemas, config |
| `code`  | `file`           | `.mjs`, `.js`, `.ts`                   | Kod wykonywalny / executable code            |
| `other` | `file`           | wszystko pozostałe / everything else   | Licencje, dokumentacja, media, itd. / licenses, docs, media, etc. |
| `library` (component) | `library` | — (z `package.json`)             | Zadeklarowana zależność npm / declared npm dependency |

Uwaga / Note: `data` jest jedyną grupą mapowaną na CycloneDX `type: "data"`;
pozostałe pliki są `type: "file"`. Ta rozłączność (html vs data vs code vs other)
jest **stabilnym kontacktem** — zmiana mapowania jest zmianą wersji profilu.

---

## 3. Pola komponentu-pliku / File-component fields

Każdy zinwentaryzowany plik emituje dokładnie następujące pola:
Each inventoried file emits exactly the following fields:

| Pole / Field        | Typ / Type | Przykład / Example                                  | Uwagi / Notes |
|---------------------|-----------|------------------------------------------------------|---------------|
| `type`              | string    | `file` \| `data`                                     | Wg tabeli §2 / per §2 table |
| `bom-ref`           | string    | `surface:README.md`                                  | Prefiks `surface:` + ścieżka POSIX-relatywna do root |
| `name`             | string    | `README.md`                                          | Basename pliku / file basename |
| `group`            | string    | `other`                                              | Wg tabeli §2 / per §2 table |
| `version`          | string    | `1.0.0`                                              | Stała wersja profilu / fixed profile version |
| `scope`            | string    | `required`                                           | Pliki: zawsze `required` / files: always `required` |
| `hashes[0].alg`    | string    | `SHA-256`                                            | Jedyny dozwolony algorytm / the only permitted algorithm |
| `hashes[0].content`| string    | `b2dc7a…04ca72`                                      | 64 znaki hex, SHA-256 zawartości bajtowej / hex, of byte content |
| `properties[]`     | array     | patrz niżej / see below                              | Rozszerzenia `k0nsult:*` / `k0nsult:*` extensions |

### Właściwości `k0nsult:*` (per plik) / `k0nsult:*` properties (per file)

| `name`              | `value` (przykład / example)                          | Znaczenie / Meaning |
|---------------------|-------------------------------------------------------|---------------------|
| `k0nsult:path`      | `schema/finding-v1.schema.json`                       | Ścieżka POSIX względem root / POSIX path relative to root |
| `k0nsult:bytes`     | `1953`                                                 | Rozmiar w bajtach (string) / size in bytes (string) |
| `k0nsult:surface`   | `open-source`                                          | Znacznik powierzchni / surface tag |

### Pola komponentu-zależności / Dependency-component fields

| Pole / Field | Przykład / Example                          | Uwagi / Notes |
|--------------|---------------------------------------------|---------------|
| `type`       | `library`                                   | Zadeklarowana zależność / declared dependency |
| `bom-ref`    | `npm:left-pad@^1.3.0`                        | Prefiks `npm:` + `name@range` |
| `name`       | `left-pad`                                   | Nazwa pakietu / package name |
| `version`    | `^1.3.0`                                     | Zakres z `package.json` / range from `package.json` |
| `scope`      | `required` \| `optional`                     | `optional` dla `devDependencies` |
| `purl`       | `pkg:npm/left-pad@1.3.0`                     | Package URL, prefiks `^`/`~` usunięty / stripped |
| `properties` | `k0nsult:declared_in`, `k0nsult:dep_field`  | Gdzie zadeklarowano / where declared |

---

## 4. Metadane dokumentu / Document metadata

| Ścieżka / Path                        | Wartość / Value |
|---------------------------------------|-----------------|
| `bomFormat`                           | `CycloneDX` |
| `specVersion`                         | `1.5` |
| `$profile`                            | `cyclonedx-lite (podzbior: bez services/vulnerabilities/compositions)` |
| `serialNumber`                        | `urn:uuid:<v4>` — nowy UUID na każde uruchomienie / fresh UUID per run |
| `version`                             | `1` |
| `metadata.timestamp`                  | ISO-8601 UTC |
| `metadata.tools[0]`                   | `{ vendor: "K0NSULT", name: "sbom.mjs", version: "1.0.0" }` |
| `metadata.component`                  | `type: application`, `bom-ref: k0nsult-opensource-surface` |
| `metadata.properties[]`               | `k0nsult:root`, `k0nsult:scope`, `k0nsult:license_proposed`, `k0nsult:stats` |

### `k0nsult:stats` — obiekt liczbowy (jako string JSON) / numeric object (JSON string)

```json
{"total":8,"files_html":0,"data_json":1,"code_files":3,"other_files":4,"node_libraries":0}
```

- `total` — wszystkie komponenty (pliki + zależności) / all components.
- `files_html`, `data_json`, `code_files`, `other_files` — liczności grup z §2.
- `node_libraries` — liczba zależności npm / count of npm dependencies.

---

## 5. Determinizm i weryfikacja / Determinism and verification

PL:
- **Zawartość** SBOM (zbiór plików, hasze, rozmiary, grupy) jest
  **deterministyczna** dla stałego drzewa źródłowego.
- **Niedeterministyczne pola** (celowo): `serialNumber` (świeży UUID) oraz
  `metadata.timestamp`. Przy porównaniu dwóch przebiegów te dwa pola należy
  pominąć; reszta musi być identyczna.
- **Autorytatywny dowód** to pole `hashes[0].content` (SHA-256). Adopter
  liczy własny SHA-256 pliku i porównuje — jeśli zgadza się, plik jest
  bajt-w-bajt tym, co deklaruje SBOM.

EN:
- The SBOM **content** (file set, hashes, sizes, groups) is **deterministic**
  for a fixed source tree.
- **Non-deterministic fields** (by design): `serialNumber` (fresh UUID) and
  `metadata.timestamp`. When diffing two runs, ignore these two; everything
  else must be identical.
- The **authoritative proof** is `hashes[0].content` (SHA-256). An adopter
  recomputes the file's SHA-256 and compares — a match means the file is
  byte-for-byte what the SBOM claims.

Procedura weryfikacji minimalna / minimal verification procedure:

```bash
# 1) wygeneruj SBOM / generate the SBOM
node sbom.mjs --root ./surface --out /tmp/sbom.json

# 2) dla wybranego pliku porownaj hash / for a chosen file, compare the hash
sha256sum ./surface/README.md
# porownaj z hashes[0].content przy k0nsult:path == "README.md"
```

---

## 6. Powiązania regulacyjne / Regulatory linkage

> Klasa: NARRACJA (kontekst prawny, nie roszczenie techniczne). Odcinamy od
> części normatywnej (§1–§5, DOWÓD) świadomie — mapowanie na przepisy jest
> interpretacją, nie faktem sprawdzalnym `sha256sum`.

PL:
- **CRA (Cyber Resilience Act)** — obowiązek dostarczenia SBOM dla produktów z
  elementami cyfrowymi. Ten profil dostarcza minimalny, sprawdzalny inwentarz
  z haszami.
- **AI Act art. 72** — logowanie / nadzór po wprowadzeniu na rynek: hasze plików
  pozwalają wykazać niezmienność wystawionej powierzchni w czasie.
- SBOM ↔ **VEX**: pojedyncze findingi (podatności, statusy `not_affected`
  itd.) opisuje osobny kontrakt `schema/finding-v1.schema.json` (pole
  `vex_status`). SBOM mówi *co jest*; VEX/finding mówi *czy to groźne*.

EN:
- **CRA (Cyber Resilience Act)** — obligation to provide an SBOM for products
  with digital elements. This profile provides a minimal, checkable, hashed
  inventory.
- **AI Act art. 72** — post-market logging / monitoring: file hashes let you
  demonstrate the immutability of the published surface over time.
- SBOM ↔ **VEX**: individual findings (vulnerabilities, `not_affected`
  statuses, etc.) are described by the separate `schema/finding-v1.schema.json`
  contract (`vex_status` field). The SBOM says *what exists*; the VEX/finding
  says *whether it is dangerous*.

---

## 7. Wersjonowanie profilu / Profile versioning

PL: Zmiana mapowania klasyfikacji (§2), zestawu pól (§3) lub algorytmu haszowania
jest **zmianą łamiącą** i wymaga podbicia wersji profilu oraz
`metadata.tools[0].version`. Dodanie nowej właściwości `k0nsult:*` jest zmianą
kompatybilną.

EN: Changing the classification mapping (§2), the field set (§3), or the hashing
algorithm is a **breaking change** and requires bumping the profile version and
`metadata.tools[0].version`. Adding a new `k0nsult:*` property is a compatible
change.

---

**License:** Apache-2.0 (see `LICENSE`, `NOTICE`, `PATENT_GRANT.md`). No engine
code, no data, no keys — *No Password Custody*.
