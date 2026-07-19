# SBOM Exposure Map — SPEC (K0NSULT)

> **Evidence class: GAP.** Ta SPEC opisuje, jak **skorelować** komponenty z
> profilu `docs/SBOM-PROFILE.md` z podatnościami — ale **bez podłączonego,
> autorytatywnego feedu** (EUVD/ENISA, NVD) każdy werdykt ekspozycji jest
> **jawnym GAP-em**, nie dowodem. Doktryna `claim ≤ proof`: nie wolno twierdzić
> „komponent bezpieczny" ani „komponent podatny" bez cytowalnego źródła z datą
> migawki. Deterministyczna jest **procedura korelacji** (§4) i **format
> wyniku** (§5); *nie* jest deterministyczny stan świata podatności. Brak feedu
> = `UNKNOWN` + jawny wpis GAP, nigdy cisza.

PL: Cel — nadbudować nad inwentarzem SBOM (co dokładnie wystawia powierzchnia)
**mapę ekspozycji**: dla każdej zależności wskazać, czy istnieje znana
podatność, przeciw **której migawce** feedu to sprawdzono i **kiedy**. Kluczowa
zasada: narzędzie działa **offline** wobec lokalnej migawki; nieobecność feedu
jest raportowana jako brak, a nie zamiatana pod „0 podatności".

EN: Goal — build on top of the SBOM inventory (what a surface exposes) an
**exposure map**: for each dependency, state whether a known vulnerability
exists, **against which feed snapshot** it was checked, and **when**. Core rule:
the tool runs **offline** against a local snapshot; absence of a feed is
reported as a gap, never laundered into "0 vulnerabilities".

---

## 1. Zakres / Scope

PL:
- **Wejście:** SBOM w profilu `cyclonedx-lite` (`docs/SBOM-PROFILE.md`) — bierze
  komponenty `type: library` z polem `purl` (`pkg:npm/...`) oraz opcjonalnie
  pliki `group: code`/`data` z haszem SHA-256.
- **Korelacja:** wyłącznie wobec **lokalnej migawki** bazy podatności (plik na
  dysku), której pochodzenie i data są zadeklarowane w wyniku.
- **Read-only, offline:** narzędzie **nie** nawiązuje połączeń sieciowych, **nie**
  pobiera feedów, **nie** modyfikuje SBOM ani powierzchni. Pobranie/aktualizacja
  migawki jest **osobnym, ludzkim** aktem poza tą SPEC.
- **Poza zakresem:** ocena wykorzystywalności (to VEX — `schema/finding-v1`,
  pole `vex_status`), skanowanie kodu (SAST), sekrety (osobne narzędzia).

EN:
- **Input:** an SBOM in the `cyclonedx-lite` profile — it consumes
  `type: library` components carrying a `purl` (`pkg:npm/...`), and optionally
  `group: code`/`data` files with a SHA-256 hash.
- **Correlation:** only against a **local snapshot** of a vulnerability database
  (a file on disk), whose provenance and date are declared in the output.
- **Read-only, offline:** the tool makes **no** network connections, fetches
  **no** feeds, mutates neither the SBOM nor the surface. Fetching/updating the
  snapshot is a **separate, human** act outside this SPEC.
- **Out of scope:** exploitability assessment (that is VEX —
  `schema/finding-v1`, `vex_status`), code scanning (SAST), secrets.

---

## 2. Źródła podatności / Vulnerability sources

Kolejność preferencji jest jawna i wpisywana do wyniku. Preference order is
explicit and recorded in the output.

| `feed_id`   | Autorytet / Authority | Identyfikator / Identifier | Uwaga / Note |
|-------------|-----------------------|----------------------------|--------------|
| `euvd`      | **ENISA — EU Vulnerability Database** | `EUVD-YYYY-NNNNN` | Preferowane źródło UE (NIS2 art. 12). / Preferred EU source. |
| `nvd`       | NIST NVD              | `CVE-YYYY-NNNNN`           | Szeroko cytowane, non-EU autorytet. / Widely cited, non-EU authority. |
| `osv`       | OSV.dev               | `GHSA-...` / ekosystemowe  | Ekosystemowe (npm/PyPI…). / Ecosystem-scoped. |
| `ghsa`      | GitHub Advisory       | `GHSA-xxxx-...`            | Często zawiera zakresy `purl`. / Often carries `purl` ranges. |
| `(none)`    | **brak migawki / no snapshot** | —              | **Wynik = GAP** dla wszystkich komponentów. / **Result = GAP** for all. |

Zasada rozstrzygania / tie-break: jeśli podatność ma jednocześnie ID EUVD i CVE,
w wyniku emitowane są **oba** (`euvd_id` + `cve[]`); pole `primary_feed`
wskazuje, wobec której migawki dopasowano.

---

## 3. Model ekspozycji per komponent / Per-component exposure model

Dla każdego komponentu `library` wynik przyjmuje dokładnie jeden `exposure`:

| `exposure`      | Znaczenie / Meaning | Warunek / Condition | Klasa / Class |
|-----------------|---------------------|---------------------|:-------------:|
| `MATCH`         | Znana podatność dotyczy zadeklarowanej wersji. | `purl` pasuje do wpisu migawki **i** wersja mieści się w zakresie dotkniętym. | GAP→DOWÓD* |
| `NO_MATCH`      | Brak dopasowania **w tej migawce**. | `purl` obecny w namyśle, ale wersja poza zakresami / brak wpisu. | GAP |
| `RANGE_UNKNOWN` | Wpis istnieje, ale bez maszynowego zakresu wersji. | Wymaga ludzkiej oceny. | GAP |
| `UNVERSIONED`   | Komponent bez konkretnej wersji (`^`/`~`/zakres). | Nie da się rozstrzygnąć bez rozwiązania zależności. | GAP |
| `NO_FEED`       | **Brak migawki feedu.** | `feed_id = (none)`. | **GAP (jawny)** |

> \* `MATCH` staje się **DOWÓD** dopiero, gdy wskazuje **cytowalny** identyfikator
> (`EUVD-…`/`CVE-…`) **plus** `feed_snapshot_date`. Bez daty migawki nawet
> „match" jest GAP-em — bo migawka mogła być przestarzała. To nie formalizm:
> podatność ujawniona po dacie migawki jest **niewidoczna**, i wynik musi to
> ujawniać, a nie ukrywać.

PL — kluczowa asymetria: **`NO_MATCH` nigdy nie znaczy „bezpieczny".** Znaczy
tylko „nie znaleziono w migawce X z dnia Y". Twierdzenie o bezpieczeństwie
wymaga aktualnego feedu **i** oceny VEX — to poza tą SPEC.

EN — key asymmetry: **`NO_MATCH` never means "safe".** It means only "not found
in snapshot X dated Y". A safety claim needs a current feed **and** a VEX
assessment — outside this SPEC.

---

## 4. Procedura korelacji / Correlation procedure

Deterministyczna wobec pary (SBOM, migawka). Deterministic given (SBOM,
snapshot).

```
WEJŚCIE:
  - sbom.json  (profil cyclonedx-lite)
  - snapshot   (plik migawki: {feed_id, snapshot_date, entries[]})
               entries[i] = { id, purl_pattern, affected_ranges[], severity, cve[] }

1. JEŻELI snapshot nieobecny LUB snapshot.entries puste:
     dla KAŻDEGO komponentu library → exposure = NO_FEED (GAP)
     emituj feed_id = "(none)", zakończ z global_status = "NO_FEED".

2. Zbuduj indeks migawki po znormalizowanym purl (bez wersji).

3. Dla KAŻDEGO komponentu library z purl:
   a. znormalizuj purl → (typ, nazwa, wersja).
   b. JEŻELI wersja jest zakresem (^,~,x,*) → exposure = UNVERSIONED.
   c. W PRZECIWNYM RAZIE dopasuj (typ,nazwa) do indeksu:
      - brak wpisu                       → NO_MATCH
      - wpis bez affected_ranges         → RANGE_UNKNOWN
      - wersja ∈ któregoś zakresu        → MATCH  (+ id, +cve[], +severity)
      - wersja ∉ żadnego zakresu         → NO_MATCH

4. Dla komponentów library BEZ purl → exposure = RANGE_UNKNOWN (adnotacja: brak purl).

5. Emituj mapę (§5) z NAGŁÓWKIEM migawki (feed_id, snapshot_date, entry_count).
```

Nieobecność kroku sieciowego jest **cechą, nie brakiem**: wynik jest w 100%
odtwarzalny offline, a każdy audytor z tą samą migawką dostaje identyczną mapę.

---

## 5. Format wyniku / Output format

```json
{
  "$spec": "sbom-expose/1.0",
  "generated_at": "2026-07-19T00:00:00Z",
  "source_sbom": { "serialNumber": "urn:uuid:...", "component_count": 8 },
  "feed": {
    "feed_id": "euvd",
    "snapshot_date": "2026-07-15",
    "entry_count": 284119,
    "provenance": "ENISA EUVD offline export (declared, not fetched by tool)"
  },
  "global_status": "CORRELATED",           // lub "NO_FEED"
  "exposures": [
    {
      "bom-ref": "npm:left-pad@^1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "exposure": "NO_MATCH",
      "evidence_class": "GAP",
      "matched": [],
      "note": "not found in euvd@2026-07-15; NOT a safety claim"
    }
  ],
  "summary": {
    "MATCH": 0, "NO_MATCH": 6, "RANGE_UNKNOWN": 1,
    "UNVERSIONED": 1, "NO_FEED": 0
  },
  "gaps": [
    "1 component UNVERSIONED (range not resolved): npm:left-pad@^1.3.0",
    "feed euvd@2026-07-15 is 4 days old at generation time"
  ]
}
```

- `evidence_class` per wpis: `DOWOD` **tylko** dla `MATCH` z `id`+`snapshot_date`;
  w innych przypadkach `GAP`.
- `gaps[]` jest **obowiązkowe** i niepuste, gdy cokolwiek pozostaje
  nierozstrzygnięte lub migawka jest starsza niż zadeklarowany próg świeżości.
- `global_status = "NO_FEED"` gdy brak migawki — cała mapa jest wtedy jednym
  wielkim, jawnym GAP-em, i tak musi być zaraportowana.

---

## 6. Świeżość migawki / Snapshot freshness

PL: Migawka bez daty jest **odrzucana** (błąd, nie ciche „0 podatności").
Zalecany próg świeżości: **≤ 7 dni** dla `euvd`/`nvd`. Migawka starsza niż próg
nadal jest używana, ale **każdy** komponent dziedziczy adnotację
`stale_feed` w `gaps[]`, a wynik nie może być prezentowany jako aktualny.
Data migawki jest deklarowana przez człowieka przy jej pobraniu — narzędzie jej
**nie** ustala samo (nie ma sieci).

EN: A snapshot without a date is **rejected** (an error, not a silent "0
vulns"). Recommended freshness threshold: **≤ 7 days** for `euvd`/`nvd`. A
snapshot older than the threshold is still used, but **every** component
inherits a `stale_feed` note in `gaps[]`, and the result may not be presented as
current. The snapshot date is declared by a human at fetch time — the tool does
**not** derive it (no network).

---

## 7. Powiązania regulacyjne / Regulatory linkage

> Klasa: NARRACJA (kontekst prawny, nie roszczenie techniczne). Odcięte
> świadomie od §1–§6.

PL:
- **NIS2 / ENISA EUVD** — UE prowadzi własną bazę podatności (EUVD); ta SPEC
  traktuje `euvd` jako **preferowane** źródło suwerenne, z NVD jako uzupełnieniem.
- **CRA (Cyber Resilience Act)** — obowiązki obsługi podatności; mapa ekspozycji
  wiąże inwentarz (SBOM) z podatnościami, ale **rozdziela** „istnieje CVE" od
  „jest wykorzystywalne" (to drugie = VEX / `vex_status`).
- **AI Act art. 72** — nadzór po wprowadzeniu na rynek: datowane migawki dają
  ślad, wobec jakiego stanu wiedzy oceniano powierzchnię w danym dniu.

EN:
- **NIS2 / ENISA EUVD** — the EU maintains its own vulnerability database
  (EUVD); this SPEC treats `euvd` as the **preferred** sovereign source, with NVD
  as a complement.
- **CRA** — vulnerability-handling duties; the exposure map links the inventory
  (SBOM) to vulnerabilities but **separates** "a CVE exists" from "it is
  exploitable" (the latter = VEX / `vex_status`).
- **AI Act art. 72** — post-market monitoring: dated snapshots record against
  which state of knowledge the surface was assessed on a given day.

---

## 8. Wersjonowanie / Versioning

PL: Zmiana zbioru wartości `exposure` (§3), algorytmu korelacji (§4) lub
schematu wyniku (§5) jest **zmianą łamiącą** i podbija `$spec`. Dodanie nowego
`feed_id` (§2) jest zmianą kompatybilną.

EN: Changing the `exposure` value set (§3), the correlation algorithm (§4), or
the output schema (§5) is a **breaking change** and bumps `$spec`. Adding a new
`feed_id` (§2) is a compatible change.

---

**License:** Apache-2.0 (see `LICENSE`, `NOTICE`, `PATENT_GRANT.md`). No engine
code, no data, no keys — *No Password Custody*. Ten dokument nie zawiera feedu
podatności; migawkę dostarcza operator poza narzędziem.
