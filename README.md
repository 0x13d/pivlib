# pivlib

A PIV-card and PKI toolkit for the people who actually wrangle the files.
Inspect, classify, and convert X.509 certificates, CSRs, CRLs, private keys,
PKCS#7 / PKCS#12 envelopes, the PIV BER-TLV containers (CHUID, CCC, Security
Object), and the INCITS biometric records that ride inside CBEFF — all from one
WASM-backed core, with a CLI, npm package, web demo, and VS Code extension.

The encoding detector is the first thing most people hit: drop in *any* file
and pivlib will figure out whether it's DER, PEM, base64-wrapped DER,
hex-wrapped DER, gzipped DER, a PKCS#7 chain, a PKCS#12 bundle, or none of the
above — then hand you a canonical form to work with.

## What's in the box

| Tool | Input | Output |
|------|-------|--------|
| **Encoding detector** | any bytes | format + canonical DER + warnings |
| **Cert inspector** | X.509 v3 cert (any encoding) | parsed fields + PIV key-role classification |
| **CSR inspector** | PKCS#10 (any encoding) | requested subject + extensions |
| **CRL inspector** | X.509 CRL (any encoding) | issuer + revoked entries |
| **Key inspector** | PKCS#8, encrypted or plain | algorithm + parameters (never the raw key) |
| **PKCS#7 / CMS** | SignedData envelope | embedded certs + signers |
| **PKCS#12 / PFX** | bundle | enumerated certs and key slots (no decrypt; just structure) |
| **CHUID** | SP 800-73 BER-TLV | FASC-N, GUID, expiration, signature ref |
| **CCC** | SP 800-73 BER-TLV | card capability set |
| **Security Object** | SP 800-73 CMS | container hashes + signer |
| **Portrait encoder** | JPEG | INCITS 385 + CBEFF |
| **Fingerprint encoder** | WSQ | INCITS 378 (minutiae) + INCITS 381 (image) + CBEFF, multi-BDB |

## PIV key-role classifier

The classifier looks at the X.509 policy OIDs, extended key usage, key usage,
and PIV-specific SAN extensions, then returns one of:

- `PivAuth` — the cert behind the `id-PIV-NIST-9A` slot
- `CardAuth` — `id-PIV-cardAuth` EKU present, slot `9E`
- `DigitalSignature` — non-repudiation, `id-fpki-common-hardware` policy
- `KeyManagement` — `keyEncipherment` / `keyAgreement`, slot `9D`
- `ContentSigning` — `id-PIV-content-signing` EKU (signs CHUID / facial / fingerprint containers)
- `Unknown` — none of the above

Each classification carries the evidence it used, so an operator can see *why*
pivlib chose what it chose.

## Quick demo

```bash
# Install wasm-bindgen-cli once (we drive wasm-pack manually — see Build notes).
cargo install wasm-bindgen-cli --version 0.2.121

make test          # cargo workspace tests
make cli           # release CLI at target/release/pivlib
make wasm wasm-node  # both wasm-bindgen output targets

# Sniff a mystery file
./target/release/pivlib detect path/to/mystery.bin

# Classify a PIV cert (any encoding)
./target/release/pivlib cert path/to/cert.b64
```

For the web app:

```bash
cd apps/web && npm install && npm run dev
```

For the VS Code extension:

```bash
cd apps/vscode-extension && npm install && npm run package
# Sideload the .vsix from the Extensions panel → "..." → Install from VSIX...
```

## Components

```text
crates/pivlib/                 Rust core: encoding detect + cert/CSR/CRL/key/PKCS7/PKCS12
                               + CHUID/CCC/SecurityObject + biometric (face/finger) + CBEFF
crates/pivlib_cli/             Thin clap-based CLI
packages/pivlib/               npm package: WASM bindings + TypeScript wrappers
packages/pivlib-cli/           npm wrapper around the native CLI binary
apps/web/                      Toolkit-grid web demo (Vite + React + Tailwind)
apps/vscode-extension/         VS Code "inspect this PKI/PIV file" extension
crates/pivlib/nbis/            Vendored NIST Biometric Image Software (WSQ + mindtct)
tests/fixtures/                Canonical PKI + PIV fixtures
```

## CLI

```text
pivlib detect    [INPUT]                 — encoding + content sniffer
pivlib cert      [INPUT] [-f json|text]  — parse + classify an X.509 cert
pivlib csr       [INPUT] [-f json|text]
pivlib crl       [INPUT] [-f json|text]
pivlib key       [INPUT] [-f json|text]  — PKCS#8 metadata only (never the key material)
pivlib pkcs7     [INPUT]                 — enumerate SignedData embedded certs
pivlib pkcs12    [INPUT]                 — enumerate SafeBag contents
pivlib chuid     [INPUT]                 — decode PIV CHUID container
pivlib ccc       [INPUT]                 — decode PIV CCC container
pivlib face      INPUT.jpg               — JPEG → INCITS 385 + CBEFF
pivlib finger    INPUT.wsq --position N  — WSQ → INCITS 378 + 381 + CBEFF
pivlib convert   INPUT --to der|pem|pkcs7  — transcode between encodings
```

Omit `INPUT` to read stdin. All commands default to text output; pass `-f json`
for a machine-readable form.

## npm package

```ts
import { detect, parseCert, classifyPivRole } from 'pivlib';

const result = await detect(bytes);
// → { format: 'base64-of-der', normalizedDer: Uint8Array, warnings: [...] }

const cert = await parseCert(result.normalizedDer);
const role = classifyPivRole(cert);
// → { role: 'PivAuth', evidence: { policyOids: [...], ekus: [...], ... } }
```

## How rendering decisions are made

- **Format detection** (`encoding.rs`) walks a fixed cascade (ASN.1 magic →
  PEM sniff → base64-of-DER → hex-of-DER → gzip-of-DER → PKCS#7 envelope →
  PKCS#12 envelope). Returns the first match plus a normalized DER form.
- **PIV role classification** (`cert/piv_role.rs`) inspects EKUs, KeyUsage,
  policy OIDs, and the SAN OIDs defined in NIST SP 800-78. Returns the role
  plus the evidence used.
- **BER-TLV containers** (`chuid.rs`, `ccc.rs`, `security_object.rs`) follow
  the tag tables in NIST SP 800-73 Part 1 §3.

## Build notes

- `wasm-pack 0.14.0` is incompatible with current Cargo (`--out-dir` flag rename).
  We drive `cargo build --target wasm32-unknown-unknown` + `wasm-bindgen-cli`
  directly. The Rust crate is `crate-type = ["cdylib", "rlib"]`; WASM bindings
  are gated behind `--features wasm`.
- NBIS C library lives at `crates/pivlib/nbis/` and is compiled by `build.rs`
  when the `nbis` feature is enabled. See [CLAUDE.md](./CLAUDE.md) for the WASI
  SDK + `__NBISLE__` gotchas.
- The npm package ships **two** WASM builds — `wasm/` (bundler target) and
  `wasm-node/` (CommonJS for Node). Conditional `exports` route consumers.

## Project layout & contributing

- [SPEC.md](./SPEC.md) — authoritative behavior (format detection cascade,
  PIV role classifier rules, BER-TLV tag tables)
- [CLAUDE.md](./CLAUDE.md) — operational notes for future sessions
- [CHANGELOG.md](./CHANGELOG.md) — release history

## License

See [LICENSE.md](./LICENSE.md).
