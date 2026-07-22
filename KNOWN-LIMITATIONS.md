# KNOWN LIMITATIONS — read before relying on these tools

**Status: REFERENCE / EXPERIMENTAL.** The validators in the K0NSULT open commons
(`conformance.mjs`, `did-resolver.mjs`, and the sibling tools in `k0nsult-tools` /
`k0nsult-eu-shield`) are **reference implementations of a specification**, not
production-grade security or privacy guards. **Do not rely on them as your sole
PII / private-key / accessibility enforcement layer.**

This file is published deliberately. The commons has undergone **four rounds of
internal adversarial review** (5-judge and 20-specialist panels, maintainer-run, each prompted to
*refute*). Every finding — including the ones still open below — is public. That
transparency is the point: `claim ≤ proof` means we document exactly where the tools
are incomplete rather than overclaiming they are bulletproof.

## Known open weaknesses (from the adversarial audit)

These are **structural limitations of regex/denylist-based validation**, not one-off
bugs. Closing each class tends to reveal the next; we state them plainly instead.

### PII / private-key detection (conformance.mjs, did-resolver.mjs, art50, dep-provenance)
- **Scalar array elements may not be scanned.** PII/PEM placed as a *string element of
  an array* (e.g. `skills[].contacts[]`) can pass. The scan covers object values, not
  every array scalar.
- **Regexes are ASCII-centric.** `\d` does not match full-width/Arabic-Indic digits, so a
  PESEL written `４４…` or split with spaces/zero-width chars can pass. `EMAIL_RE` requires
  a dotted TLD, so `admin@localhost` or IDN/internal addresses can pass.
- **Key-name denylist is not camelCase-normalised in every path.** `passportNumber`,
  `dateOfBirth`, `homeAddress` (camelCase) may pass where the snake_case form fails.
- **11-digit PESEL as a JSON number** (not string) bypasses the string value scan.
- **PGP block vs PEM.** The private-key value scan matches `-----BEGIN … PRIVATE KEY-----`
  but not `-----BEGIN PGP PRIVATE KEY BLOCK-----` in every tool.
- **Validator drift.** `conformance.validate()` and `did-resolver.validate()` do not enforce
  an identical rule set — a document may PASS one and FAIL the other. Treat them as two
  independent partial checks, not one canonical gate.
- **Closed schema is top-level only.** Sub-trees (`public_key`, `skills`, `token`) are guarded
  by denylist, not a recursive allowlist.

**Consequence:** these tools reduce, but do **not eliminate**, the risk of PII or key
material entering an artefact. For real enforcement, pair them with a reviewed,
allowlist-based, Unicode-normalising, structure-aware validator and human review.

### Jurisdiction classification cannot tell a surname from a package name (dep-provenance.mjs)

**This is the honest position after external audit round 2 (roxkon / RSpace). It is a
KNOWN LIMITATION, not a fixed defect.**

`dep-provenance.mjs` classifies an identifier into `EU | EEA | non-EU`. The doctrine
says it must classify **components and entities, never people**. Enforcing that
doctrine requires deciding, **from a string alone**, whether `X` denotes a package or
a human. **That decision is not decidable by string matching.**

- **Round 1 fix was cosmetic.** The "must be a machine identifier" guard rejected only
  the **space** character. `entity:"JanKowalski", country:"DE"` still returned `EU`;
  `entity:"jan.kowalski", country:"SN"` still returned `non-EU`;
  `entity:"did:person:fatou.diop", country:"CM"` still returned `non-EU`. In other
  words: a person's nationality was still being classified — you just had to delete
  one space.
- **The same guard was simultaneously too strict.** `MACHINE_ID_RE` allowed `@` only at
  position 0, so the valid Package URL `pkg:npm/express@4.18.2` — the exact format the
  tool's own `--help` advertises — was ABORTed. (Found by the maintainer, not reported
  by the auditor.)
- **Round 2 hardening (namespace allowlist) still does not close the class.** The
  identifier must now be `pkg:…`, `did:…` or `https://…`, and must not contain a person
  term (`did:person:…` aborts). But **any surname can be smuggled inside an allowed
  namespace**:

  ```
  entity: "did:k0nsult:local:jan1kowalski:executor", country: "PL"  ->  EU
  ```

  This **still passes and is still classified.** The allowlist raises the cost of misuse
  (the caller must deliberately mint a DID); it does not make the tool incapable of
  classifying a human.

- **Corollary: `pkg:`/`did:`/`https://` are not proof of non-personhood.** A namespace
  prefix is a *convention*, not an attestation. The tool cannot verify that the DID
  method or the purl namespace actually resolves to a software artefact — it is offline
  and does no resolution.
- **Side effect of the person-term scan on identifiers.** Short/ambiguous terms
  (`race`, `dob`, `ssn`, `email`, `phone`, `mobile`, `political`) are excluded from the
  identifier scan because they produce false positives in real package names
  (`trace-events`, `emailjs`, `headphones`). Consequently `pkg:npm/…email…` is **not**
  blocked. Conversely `person` is matched as a plain substring, so a legitimate package
  named `personal-data-utils` **is** blocked (false positive, conservative by design).
- **EMAIL_RE false positive on purls.** A purl with an alphabetic pre-release suffix
  (`pkg:npm/foo@1.0.0-beta.rc`) matches the e-mail value-scan and aborts.

**Consequence:** treat the jurisdiction output as **operator-declared metadata about a
declared identifier**, never as evidence that no human was classified. The only real
control is that the operator does not put people in the declaration file; the tool
raises the cost of doing so accidentally, and cannot prevent doing so deliberately.

### Soulbound / transfer (conformance.mjs R4)
- Transfer-shape detection is a **name denylist**; novel aliases (`new_owner`, `recipient`,
  `beneficiary`, `airdrop`, `escrow`, …) may certify a transferable token as "soulbound".

### Test coverage
- **Self-tests assert the verdict, not the rule — except where explicitly marked.**
  Mutation testing showed that removing an individual guard could leave the self-tests
  green (multiple guards catch the same vector). Concrete case found in audit round 2:
  the PESEL value-scan in `dep-provenance.mjs` was **entirely shadowed** by the phone
  regex (both match 11 contiguous digits), so deleting the PESEL line left the suite
  20/20 green.
- **Partially closed (round 2).** `dep-provenance.mjs` now marks its mutation-verified
  vectors `[izolujący]`. For those guards — `GUARD-PESEL`, `GUARD-PHONE`, `GUARD-ID-A`,
  `GUARD-ID-B`, `GUARD-DUP` — disabling the single guard (`if (false)`) fails **exactly
  one** test, verified by running the mutation. Vectors **not** marked `[izolujący]` are
  regression vectors and carry the old caveat.
- **The blanket claim "any guard ⇒ exactly one test" is withdrawn.** It was never true
  and is not claimed. Guards outside `dep-provenance.mjs` — notably the oversized-input
  cap and `MAX_DEPTH` recursion guard in `conformance.mjs` — still have **no vector at
  all**: removing them fails nothing. Only the guards explicitly listed above are
  mutation-verified.

### SBOM component count (sbom.mjs)
- **Fixed in round 2, was non-deterministic.** Self-exclusion applied only to the current
  `--out` path, so a committed `sbom.json` counted as a component whenever `--out` pointed
  outside the tree. The same repository reported `committed=23` vs `regen=24`. Any
  `*sbom.json` is now excluded unconditionally; the count is identical on a fresh clone,
  in-place regeneration, and with `--out` outside the tree.
- **Still true:** the count depends on what is checked into the tree. It is an inventory
  of files present, not an attestation of what *should* be present.

## What IS solid (also from the audit)
- No repo generates, stores, or requests a private key (No Password Custody holds).
- `attest-verify` never signs (`SIGNER=none ⇒ UNSIGNED_DRAFT`, `keyless ⇒ HALT_FOR_ACK`).
- No leaked secrets/keys in the working tree or git history; Apache-2.0 `LICENSE` byte-identical.
- Path-traversal, dead-hash, ReDoS length-cap and recursion-depth guards are in place.

## How to help
Run the tools, try to break them, and open an issue or PR with a reproducing input.
That is exactly how the findings above were surfaced.
