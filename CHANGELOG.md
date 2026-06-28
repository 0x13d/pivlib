# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial workspace extracted from `app.pivlib`. Sibling shape to
  `netjson-diagrams` and `elsa-to-mermaid`.
- Rust core crate `pivlib` covering:
  - Encoding detection cascade (DER → PEM → base64-of-DER → hex-of-DER →
    gzip-of-DER → PKCS#7 → PKCS#12)
  - X.509 v3 cert parse + PIV key-role classifier (PivAuth, CardAuth,
    DigitalSignature, KeyManagement, ContentSigning)
  - PKCS#10 CSR parse
  - X.509 CRL parse
  - PKCS#8 private-key metadata (algorithm + parameters only — no key material)
  - PKCS#7 / CMS SignedData enumeration
  - PKCS#12 / PFX SafeBag enumeration
  - PIV CHUID, CCC, and Security Object BER-TLV decoders (SP 800-73 Part 1)
  - INCITS 385 portrait encoder (pure Rust, JPEG input)
  - INCITS 378 / 381 fingerprint encoders (NBIS-backed, WSQ input)
  - CBEFF multi-BDB container
- CLI crate `pivlib_cli` with the subcommand surface documented in
  [README.md](./README.md).
- npm package `pivlib` shipping WASM bindings (bundler + Node targets) and a
  TypeScript surface mirroring the Rust core.
- npm wrapper `pivlib-cli`.
- VS Code extension `ariugwu.pivlib` — drop a PKI/PIV file into an editor and
  get a side preview of what it is.
- Web app at `apps/web/` — toolkit grid covering every supported file type,
  running entirely in-browser via the WASM bundle.
- NBIS sources vendored under `crates/pivlib/nbis/`, lifted verbatim from
  `app.pivlib` (including the `__NBISLE__` build flag, the `wsq_free_buf` /
  `mindtct_mem_free` shims, and the WASI preview1 browser shim).
