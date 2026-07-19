# Signed Attestation Adapter — SPEC (K0NSULT)

> **Evidence class: GAP.** Ta SPEC opisuje **adapter** podpisujący manifest
> dowodowy (`make_bundle.mjs` → `bundle_manifest.json`) pod kątem CRA art. 25.
> Domyślnie **nic nie podpisuje** (`SIGNER=none`) — atestacja jest **zdolnością
> do włączenia**, nie stanem gotowym, więc jako całość klasa = GAP/ROADMAP.
> Jedyny sprawdzalny, obecny fakt (DOWÓD) to zachowanie negatywne: **narzędzie
> nigdy nie generuje, nie przechowuje ani nie prosi o klucz prywatny**
> (*No Password Custody*). Podpis jest **aktem operatora** poza narzędziem.
>
> **⚠️ NIEODWRACALNOŚĆ:** backend `sigstore-keyless` zapisuje do **publicznego,
> nieusuwalnego** logu przejrzystości (Rekor). To akt **nieodwracalny** —
> dozwolony **wyłącznie po jawnym ACK operatora**. Narzędzie nie wykona go
> automatycznie ani „domyślnie".

PL: Cel — dać jeden, spójny interfejs „podpisz manifest", za którym stoją trzy
wymienne backendy o **jawnie różnych** właściwościach zaufania i
odwracalności, tak by operator świadomie wybrał kompromis, a strona trzecia
mogła zweryfikować **czym** podpisano.

EN: Goal — provide one consistent "sign the manifest" interface backed by three
swappable backends with **explicitly different** trust and reversibility
properties, so the operator picks the trade-off consciously and a third party
can verify **how** it was signed.

---

## 1. Zakres / Scope

PL:
- **Wejście:** `bundle_manifest.json` z `make_bundle.mjs` — kanoniczny,
  deterministyczny, z polem `signature: null` (DRAFT).
- **Wyjście:** atestacja odniesiona do `bundle_sha256` (detached signature /
  DSSE envelope / wpis transparency), **obok** manifestu — manifest pozostaje
  niezmieniony.
- **Read-only wobec manifestu:** adapter **nie** przepisuje manifestu; produkuje
  osobny artefakt podpisu. `bundle_sha256` jest jedyną podpisywaną wartością.
- **Poza zakresem:** generacja kluczy, zarządzanie kluczem, PKI, rotacja — to
  **domena operatora**. Narzędzie ich nie dotyka.

EN:
- **Input:** `bundle_manifest.json` from `make_bundle.mjs` — canonical,
  deterministic, with `signature: null` (DRAFT).
- **Output:** an attestation over `bundle_sha256` (detached signature / DSSE
  envelope / transparency entry), **alongside** the manifest — the manifest is
  left unchanged.
- **Read-only over the manifest:** the adapter does **not** rewrite the manifest;
  it produces a separate signature artefact. `bundle_sha256` is the only value
  signed.
- **Out of scope:** key generation, key management, PKI, rotation — the
  **operator's** domain. The tool never touches them.

---

## 2. Backendy podpisu / Signing backends

| `SIGNER`           | Zaufanie / Trust | Odwracalność / Reversibility | Stan / State |
|--------------------|------------------|------------------------------|--------------|
| **`none`** (domyślny) | — | — (nic się nie dzieje) | **Domyślny.** DRAFT bez podpisu. |
| `sigstore-keyless` | OIDC + publiczny CA (Fulcio) + log Rekor | **NIEODWRACALNE** (publiczny wpis) | Działające, **tylko za ACK**. |
| `sovereign-eu`     | Suwerenny CA/TSA UE (eIDAS QES/QeSeal) | Odwracalne wg polityki CA | **GAP** — brak dostępnego backendu open. |
| `offline-detached` | Klucz operatora (GPG/OpenSSL), zero sieci | Odwracalne (klucz u operatora) | **Blocker** — wymaga klucza, którego narzędzie nie ma. |

> **Domyślnie `SIGNER=none`.** Bez jawnego wyboru backendu i bez ACK narzędzie
> zostawia manifest jako DRAFT. To jest poprawny stan końcowy, nie awaria.

---

## 3. `sigstore-keyless` — nieodwracalny, tylko ACK

PL:
- **Mechanizm:** tożsamość OIDC operatora → krótkotrwały certyfikat Fulcio →
  podpis → **wpis do publicznego logu Rekor**. Klucz efemeryczny; nie ma sekretu
  do przechowania (stąd „keyless").
- **Dlaczego nieodwracalne:** Rekor jest **append-only i publiczny**. Wpis
  (w tym `bundle_sha256`, tożsamość OIDC, znacznik czasu) staje się trwałym,
  światowym rekordem. **Nie da się go wycofać.**
- **Bramka ACK (obowiązkowa):** adapter **musi** przed wykonaniem wyświetlić
  dokładnie, co trafi do publicznego logu, i **zatrzymać się** na jawne
  potwierdzenie operatora. Brak ACK = brak akcji. To realizacja bramy
  wykonawczej dla aktu nieodwracalnego.
- **Doktryna:** mimo „keyless" tożsamość OIDC należy do **operatora** — narzędzie
  jej nie posiada ani nie odnawia w tle.

EN:
- **Mechanism:** operator's OIDC identity → short-lived Fulcio cert → signature →
  **entry in the public Rekor log**. Ephemeral key; no secret to store ("keyless").
- **Why irreversible:** Rekor is **append-only and public**. The entry (incl.
  `bundle_sha256`, OIDC identity, timestamp) becomes a permanent, worldwide
  record. It **cannot be withdrawn**.
- **ACK gate (mandatory):** before executing, the adapter **must** display exactly
  what will enter the public log and **halt** for the operator's explicit
  confirmation. No ACK = no action.
- **Doctrine:** despite "keyless", the OIDC identity is the **operator's** — the
  tool neither holds nor silently refreshes it.

---

## 4. `sovereign-eu` — suwerenny UE (GAP)

PL:
- **Zamiar:** podpis/pieczęć oparty na suwerennej infrastrukturze UE — kwalifikowany
  podpis/pieczęć elektroniczna (eIDAS QES/QeSeal), europejski urząd znacznika
  czasu (TSA), potencjalnie europejski log przejrzystości.
- **Stan: GAP (jawny).** Na moment tej SPEC **brak** dostępnego, otwartego
  backendu suwerennego UE do wpięcia bez zależności komercyjnej/HSM. Adapter
  **deklaruje ten backend jako niezaimplementowany** i zwraca `NOT_AVAILABLE`,
  a nie cichą degradację do innego backendu.
- **Warunek wyjścia z GAP:** dostępny interfejs do kwalifikowanego dostawcy
  zaufania (QTSP) lub europejskiego TSA, z kluczem/poświadczeniem **operatora**.
  Do tego czasu — GAP, nie obietnica.

EN:
- **Intent:** signing/sealing on EU-sovereign infrastructure — qualified
  electronic signature/seal (eIDAS QES/QeSeal), an EU timestamp authority (TSA),
  potentially an EU transparency log.
- **State: GAP (explicit).** As of this SPEC there is **no** available open
  sovereign-EU backend to wire in without a commercial/HSM dependency. The
  adapter **declares this backend unimplemented** and returns `NOT_AVAILABLE`,
  never a silent downgrade to another backend.
- **Exit condition:** an available interface to a qualified trust service
  provider (QTSP) or EU TSA, using the **operator's** key/credential. Until then
  — a GAP, not a promise.

---

## 5. `offline-detached` — klucz operatora (blocker)

PL:
- **Mechanizm:** klasyczny podpis odłączony nad `bundle_sha256`
  (`gpg --detach-sign`, `openssl dgst -sign`), **zero sieci**, weryfikowalny
  kluczem publicznym operatora (jak `verify_bundle.mjs --sig --pub`).
- **Blocker (z założenia):** wymaga **klucza prywatnego operatora**, którego
  narzędzie **nie ma i nie wygeneruje**. Jeśli keyring jest pusty / brak klucza →
  adapter zwraca `BLOCKED: no operator key` i **kończy**. To nie usterka —
  to *No Password Custody* w działaniu: brak klucza jest twardym blokerem, a nie
  zaproszeniem do wygenerowania klucza za operatora.
- **Odblokowanie = akt operatora:** ustanowienie tożsamości podpisującej (klucz
  GPG/OpenSSL) jest krokiem człowieka poza tą SPEC. Narzędzie jedynie **wywołuje**
  podpis na już istniejącym kluczu i **weryfikuje** wynik.

EN:
- **Mechanism:** a classic detached signature over `bundle_sha256`
  (`gpg --detach-sign`, `openssl dgst -sign`), **no network**, verifiable with the
  operator's public key (as in `verify_bundle.mjs --sig --pub`).
- **Blocker (by design):** requires the **operator's private key**, which the tool
  **does not have and will not generate**. Empty keyring / no key → the adapter
  returns `BLOCKED: no operator key` and **stops**. Not a defect — this is
  *No Password Custody* in action: a missing key is a hard blocker, not an
  invitation to generate one on the operator's behalf.
- **Unblocking = the operator's act:** establishing a signing identity (a
  GPG/OpenSSL key) is a human step outside this SPEC. The tool merely **invokes**
  the signature over an already-existing key and **verifies** the result.

---

## 6. Interfejs adaptera / Adapter interface

Jednolite wywołanie, jawny wybór backendu. Uniform call, explicit backend choice.

```
podpisz(manifest_path, SIGNER, {ack?}) → attestation | status

WSPÓLNE NIEZMIENNIKI (wszystkie backendy):
  - podpisywana jest WYŁĄCZNIE wartość bundle_sha256 z manifestu;
  - manifest NIE jest modyfikowany (osobny artefakt podpisu);
  - narzędzie NIE generuje/nie przechowuje/nie żąda klucza prywatnego;
  - klucz/tożsamość należy do OPERATORA.

ROUTING:
  SIGNER=none              → zwróć DRAFT (bez podpisu). [domyślne]
  SIGNER=sigstore-keyless  → JEŻELI !ack → HALT_FOR_ACK (pokaż, co pójdzie do Rekor)
                             JEŻELI ack  → wykonaj (NIEODWRACALNE), zwróć wpis Rekor
  SIGNER=sovereign-eu      → zwróć NOT_AVAILABLE (GAP; nie degraduj po cichu)
  SIGNER=offline-detached  → JEŻELI brak klucza operatora → BLOCKED: no operator key
                             JEŻELI klucz jest → wywołaj podpis, zwróć .sig
```

### Kody statusu / Status codes

| Status            | Znaczenie / Meaning |
|-------------------|---------------------|
| `DRAFT`           | `SIGNER=none` — manifest niepodpisany (poprawny stan). |
| `HALT_FOR_ACK`    | Keyless wymaga jawnego ACK przed nieodwracalnym wpisem. |
| `SIGNED`          | Podpis wyprodukowany; dołączony `attestation_ref`. |
| `NOT_AVAILABLE`   | `sovereign-eu` — GAP, backend niezaimplementowany. |
| `BLOCKED`         | `offline-detached` — brak klucza operatora. |

---

## 7. Format atestacji / Attestation format

```json
{
  "$spec": "signed-attestation/1.0",
  "manifest_ref": { "path": "bundle_manifest.json", "bundle_sha256": "…64hex…" },
  "signer": "none",
  "status": "DRAFT",
  "evidence_class": "GAP",
  "attestation": null,
  "reversible": null,
  "notes": [
    "SIGNER=none: manifest is a DRAFT; a human must sign with their own key.",
    "No private key was generated, stored, or requested (No Password Custody)."
  ]
}
```

Przykład po podpisie keyless (za ACK) / after keyless signing (post-ACK):

```json
{
  "signer": "sigstore-keyless",
  "status": "SIGNED",
  "evidence_class": "DOWOD",
  "reversible": false,
  "attestation": {
    "type": "dsse",
    "rekor_log_index": 000000000,
    "rekor_url": "…",
    "note": "IRREVERSIBLE public transparency entry; created after operator ACK"
  }
}
```

- `evidence_class`: `GAP` dla `DRAFT`/`NOT_AVAILABLE`/`BLOCKED`; `DOWOD` dla
  `SIGNED` (istnieje weryfikowalny artefakt podpisu).
- `reversible: false` **musi** być jawnie ustawione dla keyless — nieodwracalność
  jest częścią rekordu, nie przypisem.

---

## 8. Powiązania regulacyjne / Regulatory linkage

> Klasa: NARRACJA. Odcięte od części operacyjnej (§1–§7).

PL:
- **CRA art. 25** — integralność i pochodzenie artefaktów; ten adapter wiąże
  manifest dowodowy z **podpisem operatora**, rozdzielając *co* (SBOM/bundle) od
  *kto potwierdza* (podpis) i *jak trwały* (Rekor vs offline).
- **eIDAS** — `sovereign-eu` celuje w kwalifikowany podpis/pieczęć; dziś GAP.
- **AI Act art. 72** — nadzór po wprowadzeniu: podpisany, datowany manifest
  daje niezaprzeczalny punkt odniesienia stanu powierzchni.
- **Doktryna:** *No Password Custody* — podpis jest aktem człowieka; ustanowienie
  tożsamości podpisującej (np. termin art. 50 / bramki operatora) jest zadaniem
  operatora, nie 10-sekundową komendą narzędzia.

EN:
- **CRA art. 25** — artefact integrity and provenance; this adapter binds the
  evidence manifest to the **operator's signature**, separating *what* (SBOM/
  bundle) from *who attests* (signature) and *how durable* (Rekor vs offline).
- **eIDAS** — `sovereign-eu` targets a qualified signature/seal; a GAP today.
- **AI Act art. 72** — post-market monitoring: a signed, dated manifest gives a
  non-repudiable reference point for the surface state.
- **Doctrine:** *No Password Custody* — signing is a human act; establishing the
  signing identity is the operator's task, not a 10-second tool command.

---

## 9. Wersjonowanie / Versioning

PL: Zmiana zbioru backendów (§2), routingu/kodów statusu (§6) lub schematu
atestacji (§7) jest **zmianą łamiącą** i podbija `$spec`. Zmiana domyślnej
wartości `SIGNER` z `none` na cokolwiek innego jest **zakazana** — domyślnie
narzędzie nie podpisuje i nie dotyka klucza.

EN: Changing the backend set (§2), routing/status codes (§6), or the attestation
schema (§7) is a **breaking change** and bumps `$spec`. Changing the default
`SIGNER` away from `none` is **forbidden** — by default the tool signs nothing
and touches no key.

---

**License:** Apache-2.0 (see `LICENSE`, `NOTICE`, `PATENT_GRANT.md`). No engine
code, no keys — *No Password Custody*. Narzędzie nie generuje klucza; podpis jest
aktem operatora. Backend keyless zapisuje do publicznego, nieodwracalnego logu —
tylko za jawnym ACK.
