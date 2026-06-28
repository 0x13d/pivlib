# Charter — pivlib

> Links this project to the [portfolio](https://ariugwu.com) and its governing
> C-suite. The charter test: every project serves
> at least one of the five goals.

| | |
|---|---|
| **Primary goal** | **Career Relevancy Showcase** |
| **Owning officers** | CSO (PKI / key material / crypto) + CPO (product) |
| **Supporting** | CCO (standards-conformance claims), CIO (monorepo shape), CMO (framing) |
| **Team** | software-team — Rust+WASM+CLI+npm+web+VSCode (prefix `PL-`) |

## How it serves the goal

`pivlib` is the **PIV/PKI + biometric toolkit** (encoding detection, X.509/CSR/CRL/PKCS parsing, PIV
BER-TLV decoders, INCITS biometric records, CBEFF) — the **source of truth** that `app.pivlib` consumes.
It showcases deep crypto/identity engineering, a high-credibility differentiator, on the portfolio's
multi-target Rust+WASM pattern.

## Active focus (PI-01)

- `PI-01-007` (CPO · Career): grade — needs real-world PIV fixture coverage before tagging `v0.1.0`
  (per the project's open follow-ups).
- `PI-01-005` (CSO · Career): `trust-report` green; verify the crypto stack pins (RustCrypto crates) and
  no network calls.

## Constraints

- **No key material on the wire or in the repo** (CSO); the toolkit parses, it doesn't custody keys.
- **Accurate standards claims** — SP 800-73 / INCITS / FIPS-201 references must match implementation (CCO).
- This is the **canonical** biometric + PKI source; don't fork its logic into `app.pivlib`.
