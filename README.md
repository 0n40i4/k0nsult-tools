# k0nsult-tools

Reusable, zero-dependency tooling for **evidence-first open source**: a supply-chain
SBOM generator and a deterministic evidence-bundle builder/verifier. Part of the
K0NSULT open commons. The proprietary k0nsult.cloud engine is **not** included here.

> **Doctrine:** `claim ≤ proof`. A bundle is a **DRAFT** until a human signs it with
> their own key. These tools **never** generate, store, or ask for a private key
> (*No Password Custody*).

## Requirements
Node.js ≥ 18. No dependencies.

## `sbom.mjs` — CycloneDX-lite SBOM generator

Enumerates every file under a root and pins each by SHA-256.

```bash
node sbom.mjs --root ./my-surface --out ./sbom.json
```

- `--root <path>` — directory to inventory (default: current working directory)
- `--out <path>` — output file (default: `./sbom.json`)

Output is CycloneDX-lite 1.5: one component per file, each with a `SHA-256` hash,
so an adopter can verify byte-for-byte exactly what a published surface exposes.

## `make_bundle.mjs` — evidence-bundle manifest

Reads a declared list of artefacts from `bundle_sources.json`, computes each file's
SHA-256, and emits a canonical, deterministic `bundle_manifest.json` with a
`bundle_sha256` (hash of the sorted artefact hashes). Same inputs → same hash, on
any machine — so a regulator can independently reproduce and compare.

```bash
node make_bundle.mjs --meter <root-a> --k0nsult <root-b> --out ./bundle_manifest.json
```

The manifest is emitted with `signature: null` — it is a **DRAFT**. The operator
signs it out-of-band with their own key (`gpg --detach-sign`, `openssl dgst -sign`,
or equivalent). The tool never touches the key.

## `verify_bundle.mjs` — independent verifier

Recomputes artefact hashes from a manifest and checks consistency (and, optionally,
a detached signature). Intended for the receiving party (regulator / third party).

```bash
node verify_bundle.mjs --manifest ./bundle_manifest.json \
  --meter <root-a> --k0nsult <root-b> \
  [--sig bundle_manifest.json.asc --pub pubkey.asc]
```

Pass the same roots used to build the manifest. Without a signature it reports
`BUNDLE CONSISTENT` but `DRAFT (unsigned)` — consistency and authenticity are
separate checks, by design.

## License
Apache-2.0 (explicit patent grant, Section 3). See `LICENSE` and `NOTICE`.
