# Dependency Provenance — SPEC (K0NSULT)

> **Evidence class: DOWÓD** (dla klasyfikatora) z sekcją NARRACJA (§7, prawo).
> Klasyfikacja `jurisdiction_class` jest **deterministyczną funkcją
> zadeklarowanych metadanych** komponentu/dostawcy — ten sam wsad daje ten sam
> wynik, sprawdzalny bajt-w-bajt. Ale **prawdziwość** deklaracji jurysdykcji nie
> jest przez narzędzie weryfikowalna: brak deklaracji = **`UNKNOWN`**, nigdy
> zgadywanie. Doktryna `claim ≤ proof`: twierdzimy tylko „tak zadeklarowano",
> nie „taka jest prawda".
>
> **⛔ TWARDY ZAKAZ:** ta SPEC klasyfikuje **komponent, pakiet, repozytorium i
> podmiot-dostawcę** — **NIGDY osobę fizyczną**. Zabroniony jest scoring
> narodowości, pochodzenia etnicznego, obywatelstwa czy miejsca urodzenia
> **człowieka** (maintainera, autora, kontrybutora). Jurysdykcja dotyczy
> **prawnej lokalizacji dostawcy oprogramowania**, nie tożsamości ludzi.
> (RODO art. 9; agents-not-people.)

PL: Cel — dla każdej zależności ustalić **klasę jurysdykcyjną dostawcy**
(EU / EEA / non-EU / UNKNOWN) na podstawie **jawnie zadeklarowanych** metadanych,
tak by zamawiający publiczny mógł ocenić zależność od dostawców spoza UE
**bez** dotykania danych osobowych osób.

EN: Goal — for each dependency, determine a **supplier jurisdiction class**
(EU / EEA / non-EU / UNKNOWN) from **explicitly declared** metadata, so a public
buyer can assess non-EU supplier dependence **without** touching any person's
personal data.

---

## 1. Jednostka klasyfikacji / Unit of classification

PL: Klasyfikowany jest **byt-dostawca**, nie człowiek. Dopuszczalne jednostki:

| Jednostka / Unit          | Przykład / Example                     |
|---------------------------|----------------------------------------|
| Komponent / pakiet        | `pkg:npm/left-pad@1.3.0`               |
| Repozytorium / projekt    | fundacja, organizacja hostująca / hosting org |
| Podmiot-dostawca (firma/fundacja) | „Foo Foundation, siedziba: Bruksela" |

**Niedopuszczalne / forbidden:** osoba fizyczna, konto osobiste utożsamiane z
człowiekiem, dane biograficzne maintainera. Jeżeli jedyną „deklaracją" jest
osobiste konto osoby fizycznej bez podmiotu prawnego → `UNKNOWN` (nie wolno
wnioskować jurysdykcji z narodowości osoby).

EN: The classified thing is a **supplier entity**, never a human. Where the only
"declaration" is a private individual's personal account with no legal entity →
`UNKNOWN` (jurisdiction must not be inferred from a person's nationality).

---

## 2. Klasy jurysdykcji / Jurisdiction classes

| `jurisdiction_class` | Znaczenie / Meaning | Warunek / Condition |
|----------------------|---------------------|---------------------|
| `EU`     | Dostawca deklaruje siedzibę w państwie członkowskim UE. | Zadeklarowany kraj ∈ 27 państw UE. |
| `EEA`    | Deklaruje EOG poza UE (Norwegia, Islandia, Liechtenstein). | Kraj ∈ {NO, IS, LI}. |
| `non-EU` | Deklaruje siedzibę poza EOG. | Zadeklarowany kraj ∉ (UE ∪ EOG). |
| `UNKNOWN`| **Brak wiarygodnej deklaracji jurysdykcji.** | Brak pola / sprzeczne / tylko konto osoby fizycznej. |

> **`UNKNOWN` jest stanem domyślnym, nie awaryjnym.** Większość pakietów npm nie
> deklaruje jurysdykcji podmiotu — i to jest poprawny, uczciwy wynik, nie błąd.
> `UNKNOWN` ≠ „podejrzany". Nie wolno mapować `UNKNOWN` na `non-EU`.

---

## 3. Dopuszczalne źródła deklaracji / Admissible declaration sources

Kolejność wiarygodności; pierwsze trafienie wygrywa, ale konflikt → `UNKNOWN` +
adnotacja. Reliability order; first hit wins, but a conflict → `UNKNOWN` + note.

| `source_id`        | Co czyta / Reads | Uwaga / Note |
|--------------------|------------------|--------------|
| `provenance_att`   | Podpisana atestacja pochodzenia (SLSA/in-toto) z polem jurysdykcji. | Najsilniejsze, jeśli podpisane. / Strongest, if signed. |
| `supplier_manifest`| Jawny plik dostawcy (np. `SUPPLIER.json`: `{legal_entity, country}`). | Deklaracja podmiotu. |
| `spdx_supplier`    | Pole SPDX `Supplier:` / `Originator:` (gdy to **organizacja**). | `Organization:` OK; `Person:` → ignoruj (patrz §5). |
| `package_org`      | Zadeklarowana organizacja w `package.json` (`author`/`publisher` jako firma). | Słabe; łatwe do sfałszowania. |
| `(none)`           | Brak którejkolwiek deklaracji podmiotu. | → `UNKNOWN`. |

**Zakaz źródeł zakazanych / forbidden inference sources:** geolokalizacja IP
commitów, strefa czasowa, język w komentarzach, imię/nazwisko maintainera,
TLD e-maila osoby, „brzmienie" nazwy. Żadne z nich nie jest deklaracją
jurysdykcji **podmiotu** i wiąże się z **osobą** — zakazane.

---

## 4. Procedura klasyfikacji / Classification procedure

Deterministyczna wobec (komponent, zadeklarowane metadane). Deterministic given
(component, declared metadata).

```
WEJŚCIE: component (bom-ref, purl), declarations[] z §3

1. Zbierz deklaracje jurysdykcji z dopuszczalnych źródeł (§3), pomijając
   wszystko, co odnosi się do OSOBY fizycznej (§5).

2. JEŻELI zero deklaracji podmiotu → jurisdiction_class = UNKNOWN
     (evidence_class = GAP, reason = "no supplier declaration"). KONIEC.

3. JEŻELI ≥2 deklaracje i wskazują różne kraje → jurisdiction_class = UNKNOWN
     (evidence_class = GAP, reason = "conflicting declarations"). KONIEC.

4. Znormalizuj zadeklarowany kraj do ISO-3166-1 alpha-2.
   - kraj ∈ UE-27               → EU
   - kraj ∈ {NO, IS, LI}        → EEA
   - kraj rozpoznany, poza EOG  → non-EU
   - kraj nierozpoznany/pusty   → UNKNOWN

5. Emituj wynik z:
   - source_id użytego źródła,
   - declared_country (surowa deklaracja),
   - evidence_class = DOWOD, GDY źródło jest podpisane (provenance_att);
     w przeciwnym razie NARRACJA ("deklaracja niepodpisana, przyjęta na słowo").
```

> **Kluczowe rozróżnienie klasy dowodu:** jurysdykcja z **podpisanej** atestacji
> pochodzenia = `DOWOD` (sprawdzalne). Jurysdykcja z niepodpisanego
> `package.json` = `NARRACJA` (przyjęte na słowo dostawcy — nie da się
> zweryfikować, że firma naprawdę tam siedzi). Narzędzie **nie** waliduje
> istnienia podmiotu w rejestrze — to poza zakresem i poza doktryną.

---

## 5. Ochrona osoby fizycznej / Natural-person guard

PL — reguła nienaruszalna (obowiązkowy test negatywny w każdej implementacji):

1. Jeśli źródło jurysdykcji jest **osobą** (SPDX `Person:`, osobiste konto,
   imię i nazwisko) → **odrzuć źródło**, nie klasyfikuj z niego. Traktuj jak brak.
2. Nigdy nie emituj pola wiążącego jurysdykcję z tożsamością człowieka.
   Zabronione klucze w wyniku: `maintainer_country`, `author_nationality`,
   `person_*`, cokolwiek PII.
3. Wynik opisuje **komponent/podmiot**; jedyne dozwolone pola „kto" to nazwa
   **organizacji** (`legal_entity`), nie osoby.
4. Test akceptacyjny: wsad z samym osobistym `author` bez organizacji **musi**
   dać `UNKNOWN` — jeżeli daje cokolwiek innego, implementacja jest wadliwa.

EN — inviolable rule (mandatory negative test in every implementation):

1. If the jurisdiction source is a **person** (SPDX `Person:`, personal account,
   a human name) → **reject the source**; do not classify from it. Treat as absent.
2. Never emit a field binding jurisdiction to a human identity. Forbidden output
   keys: `maintainer_country`, `author_nationality`, `person_*`, any PII.
3. The result describes a **component/entity**; the only permitted "who" field is
   an **organization** name (`legal_entity`), never a person.
4. Acceptance test: input with only a personal `author` and no organization
   **must** yield `UNKNOWN` — anything else is a defective implementation.

---

## 6. Format wyniku / Output format

```json
{
  "$spec": "dep-provenance/1.0",
  "generated_at": "2026-07-19T00:00:00Z",
  "components": [
    {
      "bom-ref": "npm:left-pad@^1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "jurisdiction_class": "UNKNOWN",
      "declared_country": null,
      "legal_entity": null,
      "source_id": "(none)",
      "evidence_class": "GAP",
      "reason": "no supplier declaration"
    }
  ],
  "summary": { "EU": 0, "EEA": 0, "non-EU": 0, "UNKNOWN": 8 },
  "notes": [
    "UNKNOWN is the honest default; it does not imply non-EU or risk.",
    "No natural-person data is read or emitted (RODO art. 9; agents-not-people)."
  ]
}
```

- `evidence_class`: `DOWOD` tylko dla podpisanej atestacji pochodzenia; inaczej
  `NARRACJA` (deklaracja przyjęta na słowo) lub `GAP` (brak deklaracji →
  `UNKNOWN`).
- `summary` **musi** ujawniać liczbę `UNKNOWN` — ukrycie jej (np. tylko procent
  „EU vs non-EU") jest naruszeniem doktryny (własna linijka metryki).

---

## 7. Powiązania regulacyjne / Regulatory linkage

> Klasa: NARRACJA. Odcięte od klasyfikatora (§1–§6, DOWÓD/GAP).

PL:
- **CRA / cyfrowa suwerenność** — zamawiający publiczny może chcieć ocenić
  zależność od dostawców spoza UE; ta SPEC daje **audytowalną, komponentową**
  metrykę bez profilowania ludzi.
- **RODO art. 9** — zakaz przetwarzania danych ujawniających pochodzenie etniczne;
  klasyfikacja **podmiotu** (nie osoby) świadomie omija tę kategorię.
- **Dyrektywa o zamówieniach** — kryteria muszą być obiektywne i niedyskryminujące;
  `UNKNOWN` jako stan neutralny (nie „minus") chroni przed dyskryminacją dostawcy
  na podstawie braku deklaracji.

EN:
- **CRA / digital sovereignty** — a public buyer may want to assess non-EU
  supplier dependence; this SPEC gives an **auditable, per-component** metric with
  no profiling of humans.
- **GDPR art. 9** — prohibits processing data revealing ethnic origin;
  classifying the **entity** (not the person) deliberately avoids that category.
- **Procurement directive** — criteria must be objective and non-discriminatory;
  `UNKNOWN` as a neutral state (not a "minus") guards against discriminating a
  supplier for a missing declaration.

---

## 8. Wersjonowanie / Versioning

PL: Zmiana zbioru klas (§2), listy dopuszczalnych źródeł (§3) lub algorytmu (§4)
jest **zmianą łamiącą** i podbija `$spec`. Osłabienie ochrony osoby fizycznej
(§5) jest **zakazane** — nie ma wersji SPEC, w której PII wchodzi do wyniku.

EN: Changing the class set (§2), admissible sources (§3), or the algorithm (§4)
is a **breaking change** and bumps `$spec`. Weakening the natural-person guard
(§5) is **forbidden** — there is no SPEC version in which PII enters the output.

---

**License:** Apache-2.0 (see `LICENSE`, `NOTICE`, `PATENT_GRANT.md`). No engine
code, no PII, no keys — *No Password Custody*, *agents-not-people*.
