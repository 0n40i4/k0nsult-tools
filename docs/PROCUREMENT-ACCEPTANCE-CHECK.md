# PROCUREMENT ACCEPTANCE CHECK

Deterministyczna, offline bramka akceptacji oferty (procurement). Punktuje **manifest
oferty** — nie ludzi, nie dostawce jako osobe. Zgodne z doktryna K0NSULT open commons:
`claim <= proof`, silnik ukryty, `agents-not-people` (zero PII/scoringu osob),
No Password Custody (zero kluczy, zero sekretow).

Narzedzie: [`procurement-check.mjs`](../procurement-check.mjs). Node >= 18, ZERO zaleznosci.

## Manifest oferty (`--offer`, obiekt JSON)

| Pole                    | Typ    | Znaczenie                                             |
|-------------------------|--------|-------------------------------------------------------|
| `sbom_hash_rederivable` | bool   | Hash SBOM da sie niezaleznie odtworzyc (rederive).    |
| `patent_grant`          | bool   | Oferta zawiera wyrazna licencje/grant patentowy.      |
| `completeness`          | 0..1   | Udzial kompletnosci dostarczonego artefaktu.          |
| `vex_present`           | bool   | Dolaczono dokument VEX (exploitability podatnosci).   |

Brak pola = brak zadeklarowanego dowodu = 0 pkt dla tej pozycji (`claim <= proof`).
Zle typy lub `completeness` poza `[0..1]` => blad walidacji (nie ciche 0).

## Punktacja

```
SBOM        : sbom_hash_rederivable ? 40 : 0
patent      : patent_grant         ? 30 : 0
kompletnosc : 20 * completeness           (completeness w [0..1])
VEX         : vex_present          ? 10 : 0

total   = SBOM + patent + kompletnosc + VEX   (klamrowane do [0..100])
verdict = total >= 70 ? PASS : REJECT
```

Maksimum = **100** (40 + 30 + 20 + 10). Prog akceptacji = **70**.

## Przyklady

- Pelna oferta `{sbom:true, patent:true, completeness:1, vex:true}` => **100 / PASS**.
- Brak SBOM i patentu `{sbom:false, patent:false, completeness:1, vex:true}` => 30 => **REJECT**.
- Prog dokladnie `{sbom:true, patent:true, completeness:0, vex:false}` => 70 => **PASS**.

## Uruchomienie

```
node procurement-check.mjs --selftest
node procurement-check.mjs --offer '{"sbom_hash_rederivable":true,"patent_grant":true,"completeness":1,"vex_present":true}'
```

`--selftest` uruchamia wbudowane przypadki (pozytywne + NEGATYWNE) i konczy
`exit(0)` przy sukcesie, `exit(1)` przy niepowodzeniu. To jest dowod dzialania.

Kody wyjscia CLI dla oceny oferty: `0` = PASS, `1` = REJECT, `2` = blad wejscia.
