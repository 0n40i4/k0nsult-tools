# PROCUREMENT ACCEPTANCE CHECK

PL: Deterministyczna, offline bramka akceptacji oferty (procurement). Punktuje **manifest
oferty** — nie ludzi, nie dostawce jako osobe. Zgodne z doktryna K0NSULT open commons:
`claim <= proof`, silnik ukryty, `agents-not-people` (zero PII/scoringu osob),
No Password Custody (zero kluczy, zero sekretow).

EN: A deterministic, offline offer acceptance gate (procurement). It scores the **offer
manifest** — not people, not the supplier as a person. Aligned with the K0NSULT open
commons doctrine: `claim <= proof`, engine hidden, `agents-not-people` (zero PII / zero
person scoring), No Password Custody (zero keys, zero secrets).

PL: Narzedzie: [`procurement-check.mjs`](../procurement-check.mjs). Node >= 18, ZERO zaleznosci.

EN: Tool: [`procurement-check.mjs`](../procurement-check.mjs). Node >= 18, ZERO dependencies.

## Manifest oferty / Offer manifest (`--offer`, obiekt JSON / JSON object)

| Pole / Field            | Typ / Type | Znaczenie / Meaning                                            |
|-------------------------|------------|----------------------------------------------------------------|
| `sbom_hash_rederivable` | bool       | Hash SBOM da sie niezaleznie odtworzyc (rederive). / The SBOM hash can be independently re-derived (rederive). |
| `patent_grant`          | bool       | Oferta zawiera wyrazna licencje/grant patentowy. / The offer includes an explicit patent license/grant. |
| `completeness`          | 0..1       | Udzial kompletnosci dostarczonego artefaktu. / Completeness fraction of the delivered artifact. |
| `vex_present`           | bool       | Dolaczono dokument VEX (exploitability podatnosci). / A VEX document is attached (vulnerability exploitability). |

PL: Brak pola = brak zadeklarowanego dowodu = 0 pkt dla tej pozycji (`claim <= proof`).
Zle typy lub `completeness` poza `[0..1]` => blad walidacji (nie ciche 0).

EN: A missing field = no declared evidence = 0 pts for that item (`claim <= proof`).
Wrong types or `completeness` outside `[0..1]` => validation error (not a silent 0).

## Punktacja / Scoring

```
SBOM        : sbom_hash_rederivable ? 40 : 0
patent      : patent_grant         ? 30 : 0
kompletnosc : 20 * completeness           (completeness w [0..1] / completeness in [0..1])
VEX         : vex_present          ? 10 : 0

total   = SBOM + patent + kompletnosc + VEX   (klamrowane do [0..100] / clamped to [0..100])
verdict = total >= 70 ? PASS : REJECT
```

PL: Maksimum = **100** (40 + 30 + 20 + 10). Prog akceptacji = **70**.

EN: Maximum = **100** (40 + 30 + 20 + 10). Acceptance threshold = **70**.

## Przyklady / Examples

PL:
- Pelna oferta `{sbom:true, patent:true, completeness:1, vex:true}` => **100 / PASS**.
- Brak SBOM i patentu `{sbom:false, patent:false, completeness:1, vex:true}` => 30 => **REJECT**.
- Prog dokladnie `{sbom:true, patent:true, completeness:0, vex:false}` => 70 => **PASS**.

EN:
- Full offer `{sbom:true, patent:true, completeness:1, vex:true}` => **100 / PASS**.
- No SBOM and no patent `{sbom:false, patent:false, completeness:1, vex:true}` => 30 => **REJECT**.
- Exactly at threshold `{sbom:true, patent:true, completeness:0, vex:false}` => 70 => **PASS**.

## Uruchomienie / Running

```
node procurement-check.mjs --selftest
node procurement-check.mjs --offer '{"sbom_hash_rederivable":true,"patent_grant":true,"completeness":1,"vex_present":true}'
```

PL: `--selftest` uruchamia wbudowane przypadki (pozytywne + NEGATYWNE) i konczy
`exit(0)` przy sukcesie, `exit(1)` przy niepowodzeniu. To jest dowod dzialania.

EN: `--selftest` runs the built-in cases (positive + NEGATIVE) and exits with
`exit(0)` on success, `exit(1)` on failure. That is the proof of operation.

PL: Kody wyjscia CLI dla oceny oferty: `0` = PASS, `1` = REJECT, `2` = blad wejscia.

EN: CLI exit codes for offer evaluation: `0` = PASS, `1` = REJECT, `2` = input error.
