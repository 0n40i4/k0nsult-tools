# ERRATA — k0nsult-tools

Corrections to claims this repository previously made in public. Recorded rather than
silently edited. Canonical index:
[`k0nsult-governance/ERRATA.md`](https://github.com/0n40i4/k0nsult-governance/blob/master/ERRATA.md).

## 2026-07-22 — the SBOM component count was not re-derivable

**Previous claim**, used to describe this repository to third parties (including a public
consultation submission): *"SBOM = 21 components; 119 across the commons — a figure
re-derivable with `node sbom.mjs`"*.

**Status: WRONG, and the re-derivability property itself did not hold.**

Two independent defects, both now fixed:

1. `sbom.mjs` excluded the SBOM artefact from its own output **only** when the output
   went through `--out`. A committed `sbom.json` sitting in the working tree was counted
   as a component of itself, so the total depended on the state of the clone rather than
   on repository content.
2. The default output path was anchored to the **script's** directory (`__dirname`) while
   the scanned root was the **current working directory**. Running
   `node ../k0nsult-tools/sbom.mjs` from a sibling repository therefore scanned *that*
   repository but wrote the result into `k0nsult-tools/sbom.json`, silently overwriting
   this repository's evidence artefact while leaving the scanned repository's own SBOM
   untouched and stale. Present since the tool's first commit; this is the underlying
   reason the figures were never reproducible.

`*sbom.json` is now excluded unconditionally and the output belongs to the scanned tree.
Regenerated output matches the committed `sbom.json` in 10 of 10 repositories. Corrected
figures are tabulated in the canonical errata; this repository has **24** components.

Verify on a fresh clone:

```bash
node sbom.mjs --verify
```

## 2026-07-22 — the "no nationality scoring" fix was cosmetic

**Previous claim:** the `agents-not-people` guard was *fixed* by requiring `entity` to be
a machine identifier.

**Status: OVERSTATED.** The only barrier was whitespace. Verified against a fresh clone:
`entity:"JanKowalski", country:"DE"` classified as `EU`; `jan.kowalski` as `non-EU`; and
`did:person:fatou.diop` — a DID containing the literal string `person` — as `non-EU`.

The guard has been strengthened (personal-data terms are now rejected inside identifier
*values*, and a namespace allowlist is enforced), and a genuine defect found in the
process was fixed: valid Package URLs such as `pkg:npm/express@4.18.2` were being
rejected outright, because `@` was permitted only in the first position. The guard was
simultaneously too weak and too strict.

**The residual limitation is stated, not claimed away:** a surname embedded in an allowed
namespace — `did:k0nsult:local:jan1kowalski:executor` — still classifies. String matching
cannot distinguish a person's name from a package name, and this tool resolves neither
DIDs nor purls. This is a **known limitation**, not a solved problem. See
`KNOWN-LIMITATIONS.md`.

## 2026-07-22 — a blanket coverage claim was withdrawn

The claim that disabling **any** guard fails exactly one test was not true: `PESEL_RE`,
`PHONE_RE` and the duplicate-declaration guard had no vector at all — disabling them left
the suite green. The claim is now restricted, by name, to the guards actually verified by
mutation, and vectors were added for those that lacked one.
