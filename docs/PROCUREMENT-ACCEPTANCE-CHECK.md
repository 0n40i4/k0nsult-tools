# Procurement Acceptance Check — SPEC (K0NSULT)

> **Evidence class: NARRACJA.** To jest **proponowana metoda** oceny ofert
> open-source dla zamawiającego publicznego — rekomendacja, nie fakt
> weryfikowalny `sha256sum`. Sekcje algorytmiczne (§3 detektor grantu, §2
> punktacja) są deterministyczne i implementowalne, ale dokument jako całość
> pozostaje ramą decyzyjną, nie roszczeniem technicznym. Reguła K02: propozycja
> ≠ naruszenie ≠ dowód.

PL: Cel — dać zamawiającemu (SWZ / RFP) **sprawdzalną, powtarzalną** kartę oceny
dostawy open-source jako komponentu compliance, tak by kryteria dało się
zastosować mechanicznie i obronić przy odwołaniu do KIO.

EN: Goal — give a contracting authority (SWZ / RFP) a **checkable, repeatable**
scorecard for accepting an open-source deliverable as a compliance component, so
the criteria can be applied mechanically and defended on appeal.

---

## 1. Wejścia / Inputs

Dostawca składa / the supplier submits:
1. **Repozytorium / dostawa** (drzewo plików).
2. **SBOM** zgodny z profilem `docs/SBOM-PROFILE.md` (CycloneDX-lite,
   per-plik SHA-256).
3. **Plik licencji** (`LICENSE`) + opcjonalnie `PATENT_GRANT.md`.
4. **Findingi/VEX** zgodne z `schema/finding-v1.schema.json` (pole
   `vex_status`), o ile deklaruje bezpieczeństwo.

---

## 2. Punktacja / Scoring (0–100)

| Kryterium / Criterion              | Waga / Weight | Warunek pełnych punktów / Full-marks condition |
|------------------------------------|:-------------:|-----------------------------------------------|
| **SBOM**                           | **40**        | Kompletny SBOM wg profilu; **każdy** plik dostawy ma komponent z `SHA-256`; hasze weryfikują się bajt-w-bajt. |
| **Patent grant**                   | **30**        | Licencja OSI **z jawnym grantem patentowym** (detektor §3 = `GRANTED`). |
| **Kompletność / Completeness**     | **20**        | `k0nsult:stats.total` = rzeczywista liczba plików; brak plików spoza SBOM; brak sekretów/PII (skan negatywny). |
| **VEX**                            | **10**        | Każdy finding ma poprawny `vex_status`; findingi HIGH/CRITICAL mają status inny niż `under_investigation` lub uzasadnienie. |
| **RAZEM / TOTAL**                  | **100**       | |

### Reguły cząstkowe / Sub-rules

**SBOM (40):**
- 40 — SBOM kompletny, wszystkie hasze zgodne.
- 20 — SBOM obecny, ale ≤ 5% plików bez komponentu **lub** ≤ 5% haszy
  niezgodnych.
- 0 — brak SBOM, > 5% braków, lub jakikolwiek hash niezgodny na pliku
  wykonywalnym (`group: code`).

**Patent grant (30):** patrz detektor §3. `GRANTED` → 30; `SILENT` → 0;
`UNKNOWN` → 0 z adnotacją do wyjaśnienia (nie dyskwalifikacja z urzędu).

**Kompletność (20):**
- 20 — `total` zgodne, zero plików spoza SBOM, skan sekretów/PII negatywny.
- 10 — drobne rozbieżności liczności bez plików wykonywalnych.
- 0 — plik wykonywalny spoza SBOM **albo** wykryty sekret/PII.

**VEX (10):**
- 10 — wszystkie findingi z poprawnym `vex_status`.
- 5 — findingi obecne, część bez statusu lub `under_investigation` na HIGH+.
- 0 — brak findingów mimo deklaracji funkcji bezpieczeństwa, lub findingi
  niezgodne ze schematem.

**Próg akceptacji (rekomendowany):** ≥ 70/100, przy czym **Patent grant = 0
jest twardym vetem** dla komponentu, który wykonawca ma prawny obowiązek
uruchamiać (patrz `PATENT_GRANT.md`, COM(2026)503) — bez grantu patentowego
deployer nie ma odporności patentowej.

---

## 3. Detektor grantu patentowego / Patent-grant detector

Deterministyczna procedura na podstawie identyfikatora SPDX z pliku `LICENSE`.
Deterministic procedure based on the SPDX identifier in `LICENSE`.

### 3.1 Allowlist — licencje z jawnym grantem patentowym (`GRANTED`)

| SPDX-ID              | Klauzula patentowa / Patent clause |
|----------------------|------------------------------------|
| `Apache-2.0`         | §3 „Grant of Patent License" + defensive termination |
| `MPL-2.0`            | §2.1(b) patent grant |
| `GPL-3.0-only` / `GPL-3.0-or-later` | §11 patent provisions |
| `LGPL-3.0-only` / `LGPL-3.0-or-later` | dziedziczy z GPL-3.0 §11 |
| `EPL-2.0`            | §2(b) patent grant |
| `BSL-1.0`            | (Boost) — patrz analiza; traktuj jako `UNKNOWN` bez opinii prawnej |

### 3.2 Denylist — licencje milczące o patentach (`SILENT`)

| SPDX-ID       | Uwaga / Note |
|---------------|--------------|
| `MIT`         | brak wzmianki o patentach / silent on patents |
| `BSD-2-Clause`, `BSD-3-Clause` | jw. |
| `ISC`         | jw. |
| `0BSD`, `Unlicense`, `CC0-1.0` | jw. — public-domain-like, brak grantu patentowego |

### 3.3 Algorytm / Algorithm

```
WEJŚCIE: identyfikator SPDX z LICENSE (lub z pola SBOM k0nsult:license_proposed)

1. Znormalizuj SPDX-ID (trim, dokładne dopasowanie, bez wersji „+").
2. JEŻELI SPDX-ID ∈ allowlist (3.1)  → WYNIK = GRANTED  (30 pkt)
3. JEŻELI SPDX-ID ∈ denylist (3.2)   → WYNIK = SILENT   (0 pkt)
4. W przeciwnym razie                 → WYNIK = UNKNOWN  (0 pkt, adnotacja)

WALIDACJA WZMOCNIONA (opcjonalna, dla GRANTED):
5. Potwierdź obecność tekstu grantu w LICENSE:
   - Apache-2.0: szukaj nagłówka sekcji „Grant of Patent License".
   - MPL-2.0 / EPL-2.0 / GPL-3.0: szukaj słowa „patent" w treści licencji.
   JEŻELI tekst nieobecny mimo SPDX=GRANTED → obniż do UNKNOWN (niespójność).
```

Wynik detektora jest **weryfikowalny** przez każdą stronę: identyfikator SPDX i
treść pliku `LICENSE` są jawne. To jedyny fragment tej SPEC klasy DOWÓD w
otoczeniu (reszta = metoda/rekomendacja = NARRACJA).

---

## 4. Karta wyniku / Scorecard (przykład)

```
Dostawa: <nazwa>            Data oceny: <ISO-8601>
---------------------------------------------------
SBOM ............... 40 / 40   (hasze zgodne 8/8)
Patent grant ....... 30 / 30   (SPDX=Apache-2.0 → GRANTED)
Kompletność ........ 20 / 20   (total=8, 0 plików spoza SBOM, skan PII: negatywny)
VEX ................ 10 / 10   (0 findingów; deklaracja bezpieczeństwa: brak)
---------------------------------------------------
RAZEM .............. 100 / 100   → AKCEPTACJA (próg 70; patent-veto: nie)
```

---

## 5. Szablon kryterium SWZ / Tender criterion template

### PL — kryterium do Specyfikacji Warunków Zamówienia (SWZ)

> **Kryterium: Sprawdzalność i odporność patentowa dostawy open-source (waga 100 pkt).**
>
> Wykonawca dostarcza komponent oprogramowania wraz z:
> a) **SBOM** w formacie CycloneDX (co najmniej profil „lite": jeden komponent
>    na plik, każdy z sumą kontrolną SHA-256) obejmującym **wszystkie** pliki
>    dostawy — **40 pkt** przyznawane, gdy suma kontrolna każdego pliku zgadza
>    się bajt-w-bajt;
> b) **licencją zgodną z definicją Open Source (OSI) zawierającą jawny grant
>    patentowy** (np. Apache-2.0, MPL-2.0, EPL-2.0, GPL-3.0) — **30 pkt**;
>    licencje milczące o patentach (MIT, BSD, ISC) otrzymują 0 pkt w tym
>    podkryterium;
> c) **kompletnością i czystością dostawy** (brak plików spoza SBOM, brak
>    danych osobowych i sekretów) — **20 pkt**;
> d) **oświadczeniem o podatnościach w formacie VEX** dla zadeklarowanych
>    funkcji bezpieczeństwa — **10 pkt**.
>
> Zamawiający weryfikuje kryteria (a) i (b) **niezależnie**, przeliczając sumy
> kontrolne i sprawdzając identyfikator licencji SPDX. Brak jawnego grantu
> patentowego dla komponentu, który zamawiający jest **prawnie zobowiązany**
> uruchamiać, stanowi **przesłankę odrzucenia** oferty w tym zakresie.

### EN — criterion for the tender specification

> **Criterion: Verifiability and patent resilience of the open-source deliverable (weight 100 pts).**
>
> The supplier provides a software component together with:
> a) an **SBOM** in CycloneDX format (at least the "lite" profile: one component
>    per file, each with a SHA-256 hash) covering **all** delivery files —
>    **40 pts** awarded when every file's hash matches byte-for-byte;
> b) a **licence conforming to the Open Source (OSI) definition and carrying an
>    explicit patent grant** (e.g. Apache-2.0, MPL-2.0, EPL-2.0, GPL-3.0) —
>    **30 pts**; licences silent on patents (MIT, BSD, ISC) receive 0 pts in
>    this sub-criterion;
> c) **completeness and cleanliness** of the delivery (no files outside the
>    SBOM, no personal data, no secrets) — **20 pts**;
> d) a **VEX vulnerability statement** for any declared security function —
>    **10 pts**.
>
> The contracting authority verifies criteria (a) and (b) **independently**, by
> recomputing the hashes and checking the SPDX licence identifier. The absence
> of an explicit patent grant for a component the authority is **legally
> required** to run constitutes **grounds for rejection** to that extent.

---

## 6. Powiązania / Linkage

- Profil SBOM: `docs/SBOM-PROFILE.md`.
- Kontrakt findingu/VEX: `schema/finding-v1.schema.json` (`vex_status`).
- Uzasadnienie grantu patentowego: `PATENT_GRANT.md`, COM(2026)503.
- Doktryna: `claim ≤ proof`, *No Password Custody* — narzędzia oceny nie
  generują ani nie przechowują kluczy; podpis dostawy (jeśli wymagany) jest
  aktem człowieka poza narzędziem.

---

**License:** Apache-2.0 (see `LICENSE`, `NOTICE`, `PATENT_GRANT.md`).
