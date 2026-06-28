# CLAUDE.md

Operational notes for future Claude sessions on `pivlib`. This is the **meta**
doc — how to work in this repo. For the **behavior contract**, see
[SPEC.md](./SPEC.md); for **release history**, see [CHANGELOG.md](./CHANGELOG.md);
for **user docs**, see [README.md](./README.md).

## Read order on a cold start

1. **Memory** — if you're Claude Code running for Ari, the auto-loaded
   `MEMORY.md` index should point you at `project_pivlib.md` (recent
   decisions, open follow-ups, app.pivlib integration state, version of the
   WASI wiring story). If for some reason memory isn't surfaced — different
   working directory, fresh agent, teammate's session — that file is at
   `~/.claude/projects/-Users-ariugwu-Projects/memory/project_pivlib.md`.
   Read it before deciding scope on anything non-trivial.
2. This file (CLAUDE.md) — operational orientation
3. [SPEC.md](./SPEC.md) — what the code actually has to do
4. [CHANGELOG.md](./CHANGELOG.md) — recent direction-of-travel
5. The file(s) the user is asking about — only after the above

## What this project is

A Rust core (compiled to native + WASM) that does two things side by side:

1. **PKI file wrangling** — sniff the encoding of a mystery file, parse and
   classify X.509 certs (with PIV key-role detection), CSRs, CRLs, PKCS#8
   keys, PKCS#7 envelopes, PKCS#12 bundles, and the SP 800-73 BER-TLV
   containers (CHUID, CCC, Security Object).
2. **Biometric encoding** — JPEG → INCITS 385 facial record, WSQ → INCITS 378
   minutiae + INCITS 381 image record, all wrapped in CBEFF.

The core is wrapped by a CLI binary, an npm package, a web demo, and a VS
Code extension. The same monorepo shape as `netjson-diagrams` and
`elsa-to-mermaid` — same release plumbing, same trust-report tooling.

`app.pivlib` (the FIPS 201-2 CRUD dashboard) consumes the `pivlib` npm package
for its biometric flows; the cert tools are *new* surface, not in app.pivlib.

## Repository layout

```text
crates/pivlib/                     # Rust core lib (cdylib + rlib)
  src/lib.rs                       # Public API
  src/error.rs                     # Single Error type
  src/encoding.rs                  # Format detection + transcoding cascade
  src/cert/                        # X.509 parse + PIV role classifier
  src/csr.rs                       # PKCS#10
  src/crl.rs                       # X.509 CRL
  src/key.rs                       # PKCS#8 (metadata only)
  src/pkcs7.rs                     # CMS SignedData enumeration
  src/pkcs12.rs                    # PFX SafeBag enumeration
  src/chuid.rs                     # SP 800-73 CHUID BER-TLV
  src/ccc.rs                       # SP 800-73 CCC BER-TLV
  src/security_object.rs           # SP 800-73 §3.5.5
  src/cbeff/                       # Moved from app.pivlib verbatim
  src/face/incits385.rs            # Moved from app.pivlib verbatim
  src/finger/{incits378,incits381,wsq}.rs   # Moved from app.pivlib
  src/wasm.rs                      # #[cfg(feature = "wasm")] surface
  build.rs                         # NBIS C compilation (moved from app.pivlib)
  nbis/                            # Vendored NIST Biometric Image Software
  tests/                           # Integration + snapshot tests
crates/pivlib_cli/                 # clap-based CLI
packages/pivlib/                   # npm package (WASM-backed)
  src/core.ts                      # Shared TS surface
  src/index.ts                     # Bundler entry (imports from ../wasm)
  src/index.node.ts                # Node entry (imports from ../wasm-node)
  scripts/smoke.mjs                # Node smoke test runner
packages/pivlib-cli/               # npm wrapper for the native CLI binary
apps/web/                          # Vite + React + Tailwind toolkit grid
apps/vscode-extension/             # VS Code extension
scripts/                           # Release & build tooling
  trust-report.sh                  # Vendored supply-chain trust report
tests/fixtures/                    # Canonical PKI + PIV fixtures
```

## Build commands

```bash
make test            # cargo test --workspace
make cli             # cargo build --release -p pivlib_cli
make wasm            # WASM build for bundlers   → packages/pivlib/wasm/
make wasm-node       # WASM build for Node       → packages/pivlib/wasm-node/
make all             # wasm + wasm-node + cli

make dist            # gather cli + wasm + npm + web + vsix under /dist/pivlib

# npm package
cd packages/pivlib && npx tsc                  # compile TS
cd packages/pivlib && node scripts/smoke.mjs   # Node smoke

# Web app
cd apps/web && npm install && npm run dev

# VS Code extension (requires `make wasm-node` first)
cd apps/vscode-extension && npm install && npm run build
cd apps/vscode-extension && npm run package    # → pivlib-X.Y.Z.vsix
```

`wasm-pack` is **not** in the build path. Install once with
`cargo install wasm-bindgen-cli --version 0.2.121`.

## Where to make a change

- **New encoding to sniff** — add a step in
  [`encoding.rs::detect`](crates/pivlib/src/encoding.rs); the cascade is
  ordered, so think about precedence vs other steps
- **New PIV role classification** —
  [`cert/piv_role.rs::classify`](crates/pivlib/src/cert/piv_role.rs) +
  evidence struct + a unit test
- **New BER-TLV tag in CHUID/CCC** — the tag table is in the head of the
  module; add the tag, decode logic, and the printable mapping
- **New cert extension to surface** — `cert/parse.rs::extract_extensions`
- **New CLI subcommand** —
  [`crates/pivlib_cli/src/main.rs`](crates/pivlib_cli/src/main.rs); each
  subcommand is a thin wrapper over a `pivlib::*` call
- **Web app tile** — `apps/web/src/components/ToolkitGrid.tsx`. Each tile is a
  small component under `apps/web/src/components/<Tool>.tsx`

## Pipeline summary

```text
bytes → encoding::detect → DER
                            ├─→ cert::parse + cert::piv_role::classify
                            ├─→ csr::parse
                            ├─→ crl::parse
                            ├─→ key::parse_metadata
                            ├─→ pkcs7::enumerate
                            ├─→ pkcs12::enumerate
                            └─→ ber_tlv (chuid | ccc | security_object)

JPEG → face::incits385 → CBEFF
WSQ  → finger::wsq::decode → (incits381 image + incits378 minutiae) → CBEFF multi-BDB
```

All non-NBIS stages are pure functions with no IO. Full behavior in
[SPEC.md](./SPEC.md).

## Versioning rules

Same lockstep model as `netjson-diagrams`. Rust crate, CLI crate, npm package,
npm CLI wrapper, **and the VS Code extension** version together. The web app
at `apps/web` rolls separately and is unversioned.

- **MAJOR** — break a public API or change `detect()` output for unchanged
  bytes
- **MINOR** — backwards-compatible additions (new subcommand, new role
  classification, new BER-TLV tag mapping that doesn't reclassify existing
  inputs)
- **PATCH** — bug fixes only

We start at `0.1.0`. Under semver §4, anything goes pre-1.0 — but the intent
holds: **MINOR for new features**, **PATCH for fixes**.

## Critical gotchas (inherited from app.pivlib)

These were load-bearing in app.pivlib and remain so here. They're flagged in
the NBIS / WASI integration paths:

### 1. `__NBISLE__` — WASM is always little-endian

`build.rs` defines `__NBISLE__` for all NBIS C compilation. Without it,
`getc_ushort` reads 2-byte WSQ markers without byte-swapping and every valid
WSQ file fails with `"No SOI marker"`.

### 2. WSQ lives in `imgtools`, not `commonnbis`

`wsq_decode_mem` and friends are in `nbis/imgtools/src/lib/wsq/`. Pull
adjacent deps: `jpegl/huff.c`, `jpegl/tableio.c`, `commonnbis/ioutil/dataio.c`,
`commonnbis/util/computil.c`, `commonnbis/fet/*.c`.

### 3. No bare `free()` in Rust FFI

A Rust `extern "C" { fn free(...) }` declaration would emit an unresolvable
`"env".free` WASM import. Use the `wsq_free_buf()` and `mindtct_mem_free()`
shims in `nbis/shims/`.

### 4. WASI preview1 browser shim

The web app and VS Code extension need `wasi_snapshot_preview1.js`
(at `apps/web/public/` and bundled into the extension media) plus an import
map pointing the bare specifier at it. `setWasmMemory(wasmExports.memory)`
must be called after init.

### 5. mindtct direction encoding

NBIS direction is 0–15 (NUM_DIRECTIONS=16 over a semicircle, 11.25° per step).
INCITS 378 is 0–179 (2° steps). Conversion: `incits_angle = round(nbis_dir * 5.625)`.

## RustCrypto dependency stack

The cert/key/CSR/CRL/PKCS surface is built on **RustCrypto**. Pinned in the
workspace `[workspace.dependencies]`:

- `der` 0.7 — ASN.1 codec, derive-based
- `spki` 0.7 — SubjectPublicKeyInfo
- `x509-cert` 0.2 — X.509 v3 + CSR + CRL
- `cms` 0.2 — PKCS#7 SignedData
- `pkcs8` 0.10 — Private-Key Info
- `pkcs12` 0.1 — PFX
- `const-oid` 0.9 — OID database (`db` feature; resolves common OIDs to text)

All WASM-compatible. Don't pull in a new ASN.1 parser — extend within this
stack.

## Pre-flight before any non-trivial change

```bash
make test
node packages/pivlib/scripts/smoke.mjs
```

If touching the web app or extension:

```bash
(cd apps/web && npm run build)
(cd apps/vscode-extension && npm run build)
```

Snapshot tests under `crates/pivlib/tests/` and the fixtures at
`tests/fixtures/` are the **output contract**. A diff there is a conversation
with the user, not a free update.

## Trust report

`scripts/trust-report.sh` is vendored from `/Users/ariugwu/Projects/_shared/trust-report/`.
Run `make trust-report` to regenerate `reports/trust/summary.md`. The summary
is the only artifact committed; raw evidence files are gitignored under
`reports/trust/`.

## Things to be careful about

- **Don't leak key material.** `key.rs` extracts algorithm + parameters
  (curve / modulus length / etc) and never the actual key bytes. Even debug
  formatting must elide. Same rule for `pkcs12.rs` shrouded-bag contents.
- **PIV role classifier evidence is part of the contract.** Tests assert that
  changing the inputs flips the right evidence bits. If you add a new
  classification, add a new evidence field rather than overloading existing
  ones.
- **BER-TLV is not DER.** CHUID and CCC are **BER**-encoded. Don't try to
  feed them through `der` crate without ber-compat mode — they may have
  indefinite lengths in the wild.
- **Encoding detector precedence matters.** `0x30 0x82` is the DER marker, but
  it's also valid base64. The cascade checks DER first to avoid false-positive
  base64 wrapping.
- **Don't `Read` a file you just edited to confirm.** Edit/Write would have
  errored if it dropped the change.
- **Hooks may block writes** — security hook flags `innerHTML`. Use
  `DOMParser` + `replaceChildren` like the netjson-diagrams pattern.
