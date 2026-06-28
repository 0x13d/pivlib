# NBIS — NIST Biometric Image Software

This directory must be populated before WSQ decoding and fingerprint minutiae
extraction will work.  The rest of the library compiles and runs without NBIS
(WSQ decode and minutiae extraction return stub errors until then).

## Directory layout expected after setup

```text
nbis/
├── an2k/include/              ← shared NBIS headers
├── commonnbis/
│   ├── include/               ← wsq.h, defs.h, etc.
│   └── src/lib/wsq/           ← WSQ codec C sources
├── mindtct/
│   ├── include/               ← lfs.h
│   └── src/lib/               ← LFS minutiae detector C sources
├── patches/
│   └── no_file_io.patch       ← documents the one-line change needed
└── shims/                     ← already present; do not modify
    ├── mem_io.h               ← portable fmemopen for WASM
    ├── wsq_mem.c              ← wsq_decode_mem() wrapper
    └── mindtct_mem.c/.h       ← mindtct_mem() wrapper
```

> **Note:** In NBIS 5.x, WSQ was moved into `commonnbis/` — there is no
> standalone `wsq/` top-level directory.

## Step 1 — Copy sources into nbis/

After unzipping the NBIS release (e.g. `Rel_5.0.0.zip`):

```bash
# From the repo root
unzip Rel_5.0.0.zip -d /tmp/nbis_extracted
SRC=/tmp/nbis_extracted/Rel_5.0.0

cp -r "$SRC/an2k/include"       nbis/an2k/
cp -r "$SRC/commonnbis/include" nbis/commonnbis/
cp -r "$SRC/commonnbis/src"     nbis/commonnbis/
cp -r "$SRC/mindtct/include"    nbis/mindtct/
cp -r "$SRC/mindtct/src"        nbis/mindtct/
```

## Step 2 — Apply the one-line patch (manual)

The `patch` command cannot apply `no_file_io.patch` directly because it is
a guide, not a machine-generated diff.  Apply it by hand — it is a single
word removal:

### 2a — Find the internal function name

```bash
grep -n "^static int wsq_decode" nbis/commonnbis/src/lib/wsq/dec.c
```

You will see output such as:

```text
312:static int wsq_decode_file_fp(unsigned char **odata, ...
```

### 2b — Remove `static` from that line

Open `nbis/commonnbis/src/lib/wsq/dec.c` in any editor.
On the line found above, change:

```c
static int wsq_decode_file_fp(unsigned char **odata, ...
```

to:

```c
int wsq_decode_file_fp(unsigned char **odata, ...
```

That is the entire change to NBIS source.

### 2c — Add the extern declaration to the header

Open `nbis/commonnbis/include/wsq.h` and add this line anywhere in the
public declarations section:

```c
/* Exposed for in-memory decode — called by nbis/shims/wsq_mem.c */
extern int wsq_decode_file_fp(unsigned char **odata, int *owidth,
                               int *oheight, int *odepth, int *oppmm,
                               const int rawflag, FILE *fp);
```

### 2d — If the function name differs from `wsq_decode_file_fp`

Update the matching call in [shims/wsq_mem.c](shims/wsq_mem.c) — search
for `wsq_decode_file_fp` and replace it with the name you found in step 2a.

No changes to mindtct are needed — `lfs_detect_minutiae_V2()` already
accepts a raw pixel buffer.

## Step 3 — Install the WASI SDK

`wasm32-unknown-unknown` is a bare-metal WASM target with **no libc**.
NBIS C code needs `math.h`, `string.h`, `stdlib.h`, etc.  The WASI SDK
provides a full POSIX-compatible sysroot for exactly this purpose.

```bash
# macOS — Homebrew
brew install wasi-sdk

# Manual — download from GitHub releases and place at /opt/wasi-sdk
# https://github.com/WebAssembly/wasi-sdk/releases
```

Then export the path (add to `~/.zshrc` to persist):

```bash
export WASI_SDK_PATH=/opt/wasi-sdk    # adjust if installed elsewhere
```

`build.rs` checks `WASI_SDK_PATH` first, then `/opt/wasi-sdk` and
`/usr/local/wasi-sdk`. If it cannot find the SDK it will print a clear
error explaining what is missing.

## Step 4 — Build

```bash
# Add wasm32 target if not already present
rustup target add wasm32-unknown-unknown

# Install wasm-pack if not already present
cargo install wasm-pack

# Build with NBIS enabled
wasm-pack build --target web --features nbis
```

The resulting `pkg/` directory is a ready-to-use npm package.

## Serve the demo

```bash
cd www
npx serve .
# Open http://localhost:3000
```
