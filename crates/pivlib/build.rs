use std::path::PathBuf;

fn main() {
    // Cargo sets CARGO_FEATURE_<NAME>=1 for every enabled feature. Gate the
    // entire NBIS C build on the `nbis` feature so that:
    //   - a default `cargo build` (any target) has no C compiler dependency
    //   - WASM CI / web deploys without WASI SDK still succeed
    //   - the Rust-side FFI in src/finger/{wsq,incits378}.rs is already
    //     `#[cfg(feature = "nbis")]`, so disabling it here just means the
    //     fingerprint surface returns the stub error
    if std::env::var("CARGO_FEATURE_NBIS").is_err() {
        println!(
            "cargo:warning=pivlib built without `nbis` feature — fingerprint encoding will return a stub error. \
             Build with `--features nbis` (requires WASI SDK on wasm32 targets) for the real pipeline."
        );
        return;
    }

    let nbis_dir = PathBuf::from("nbis");
    let shims_dir = nbis_dir.join("shims");

    let commonnbis_src = nbis_dir.join("commonnbis").join("src").join("lib");
    let commonnbis_inc = nbis_dir.join("commonnbis").join("include");
    let mindtct_lib_src = nbis_dir.join("mindtct").join("src").join("lib");
    let mindtct_inc = nbis_dir.join("mindtct").join("include");
    let an2k_inc = nbis_dir.join("an2k").join("include");
    let imgtools_inc = nbis_dir.join("imgtools").join("include");
    // WSQ decoder lives in imgtools in NBIS 5.x (not in commonnbis).
    let wsq_src = nbis_dir.join("imgtools").join("src").join("lib").join("wsq");

    // NBIS ships headers as .h.src; its Makefile just copies them.
    // Do that here so we don't depend on the NBIS build system.
    generate_headers_from_src(&nbis_dir);

    let have_wsq = wsq_src.exists();
    let have_mindtct = mindtct_lib_src.exists();

    if have_wsq {
        println!("cargo:rerun-if-changed=nbis/imgtools/src/lib/wsq");
        println!("cargo:rerun-if-changed=nbis/imgtools/src/lib/jpegl/huff.c");
        println!("cargo:rerun-if-changed=nbis/commonnbis/src/lib/ioutil/dataio.c");
        println!("cargo:rerun-if-changed=nbis/commonnbis/src/lib/fet");
        println!("cargo:rerun-if-changed=nbis/shims/wsq_mem.c");
        compile_wsq(
            &wsq_src,
            &commonnbis_src,
            &imgtools_inc,
            &commonnbis_inc,
            &shims_dir,
        );
    } else {
        println!(
            "cargo:warning=NBIS WSQ source not found — WSQ decoding stubbed. See nbis/README.md."
        );
    }

    if have_mindtct {
        println!("cargo:rerun-if-changed=nbis/mindtct/src/lib");
        println!("cargo:rerun-if-changed=nbis/shims/mindtct_mem.c");
        compile_mindtct(
            &mindtct_lib_src,
            &mindtct_inc,
            &commonnbis_inc,
            &an2k_inc,
            &imgtools_inc,
            &shims_dir,
        );
    } else {
        println!(
            "cargo:warning=NBIS mindtct source not found — minutiae extraction stubbed. See nbis/README.md."
        );
    }
}

// ---------------------------------------------------------------------------
// WASI SDK detection
//
// wasm32-unknown-unknown has no libc. NBIS C code needs math.h, string.h,
// stdlib.h, etc. The WASI SDK provides a full POSIX-compatible sysroot for
// exactly this purpose. Install it from:
//   https://github.com/WebAssembly/wasi-sdk/releases
// then set WASI_SDK_PATH, or install to /opt/wasi-sdk.
// ---------------------------------------------------------------------------

fn wasi_sdk() -> Option<PathBuf> {
    // 1. Explicit env var (highest priority)
    if let Ok(p) = std::env::var("WASI_SDK_PATH") {
        let pb = PathBuf::from(p);
        if pb.join("bin").join("clang").exists() {
            return Some(pb);
        }
    }
    // 2. Common install locations
    for candidate in ["/opt/wasi-sdk", "/usr/local/wasi-sdk"] {
        let pb = PathBuf::from(candidate);
        if pb.join("bin").join("clang").exists() {
            return Some(pb);
        }
    }
    None
}

fn is_wasm_target() -> bool {
    std::env::var("CARGO_CFG_TARGET_ARCH")
        .map(|a| a == "wasm32")
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Shared compiler configuration
// ---------------------------------------------------------------------------

fn apply_common_flags(build: &mut cc::Build) {
    build
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-implicit-function-declaration")
        .flag_if_supported("-Wno-deprecated-declarations")
        .flag_if_supported("-Wno-sign-compare")
        .flag_if_supported("-Wno-pointer-sign")
        .define("NBIS_NO_FILE_IO", None)
        // WebAssembly is always little-endian. NBIS uses __NBISLE__ to decide
        // whether to byte-swap 16/32-bit values read from big-endian WSQ/JPEG
        // streams (e.g. in getc_ushort in dataio.c). Without this define every
        // WSQ marker comparison fails, producing "No SOI marker" errors.
        .define("__NBISLE__", None);

    if is_wasm_target() {
        match wasi_sdk() {
            Some(sdk) => {
                let sysroot = sdk.join("share").join("wasi-sysroot");
                build
                    // Use WASI SDK's clang (knows the wasm32-wasi ABI + sysroot)
                    .compiler(sdk.join("bin").join("clang"))
                    // Point at the WASI libc/math/string headers
                    .flag(format!("--sysroot={}", sysroot.display()))
                    // Target wasm32-wasi so libc headers resolve correctly;
                    // the .o files link cleanly into wasm32-unknown-unknown.
                    .flag("--target=wasm32-wasi")
                    .flag("-mthread-model").flag("single")
                    // NBIS uses times() / clock(); opt into WASI emulation.
                    .define("_WASI_EMULATED_PROCESS_CLOCKS", None)
                    .define("_WASI_EMULATED_SIGNAL", None);

                // Tell the Rust linker where the WASI sysroot libraries live.
                let wasi_lib = sysroot.join("lib").join("wasm32-wasi");
                println!("cargo:rustc-link-search=native={}", wasi_lib.display());

                // Link WASI C standard library so C stdlib calls (malloc, free,
                // fprintf, strncmp, etc.) resolve internally instead of becoming
                // "env" imports that browsers cannot satisfy.
                println!("cargo:rustc-link-lib=static=c");
                println!("cargo:rustc-link-lib=static=m");

                // Link the WASI emulation stubs.
                println!("cargo:rustc-link-lib=static=wasi-emulated-process-clocks");
                println!("cargo:rustc-link-lib=static=wasi-emulated-signal");
            }
            None => {
                panic!(
                    "\n\nWASI SDK not found.\n\
                     NBIS C code requires a libc when targeting wasm32.\n\
                     \n\
                     Install the WASI SDK:\n\
                     \n\
                       macOS (Homebrew):  brew install wasi-sdk\n\
                       Manual:            https://github.com/WebAssembly/wasi-sdk/releases\n\
                     \n\
                     Then either:\n\
                       export WASI_SDK_PATH=/opt/wasi-sdk   # or wherever you installed it\n\
                     \n\
                     Or rebuild without NBIS (fingerprint extraction will be stubbed):\n\
                       wasm-pack build --target web\n"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// .h.src → .h header generation
//
// NBIS ships some headers with a .h.src extension. Its Makefile copies them
// verbatim to .h. We replicate that here so we don't depend on NBIS make.
// ---------------------------------------------------------------------------

fn generate_headers_from_src(nbis_dir: &PathBuf) {
    for entry in glob::glob(&format!("{}/**/*.h.src", nbis_dir.display()))
        .expect("glob failed")
        .flatten()
    {
        let dest = entry.with_extension("").with_extension("h");
        // Only copy if the .h doesn't already exist (avoid overwriting patches)
        if !dest.exists() {
            std::fs::copy(&entry, &dest).unwrap_or_else(|e| {
                panic!("Failed to generate {:?} from {:?}: {}", dest, entry, e)
            });
            println!("cargo:warning=Generated {:?} from .h.src", dest);
        }
        println!("cargo:rerun-if-changed={}", entry.display());
    }
}

// ---------------------------------------------------------------------------
// WSQ
//
// The NBIS imgtools WSQ decoder depends on:
//   - imgtools/src/lib/jpegl/huff.c    (huffman utilities)
//   - commonnbis/src/lib/ioutil/dataio.c (getc_byte, getc_ushort, etc.)
//   - commonnbis/src/lib/fet/*.c        (FET metadata: extractfet_ret etc.)
// These are compiled into the same libwsq to avoid duplicate-symbol issues.
// ---------------------------------------------------------------------------

fn compile_wsq(
    wsq_src: &PathBuf,
    commonnbis_src: &PathBuf,
    imgtools_inc: &PathBuf,
    commonnbis_inc: &PathBuf,
    shims: &PathBuf,
) {
    let mut build = cc::Build::new();
    apply_common_flags(&mut build);

    // WSQ decoder + encoder sources.
    for entry in glob::glob(&format!("{}/**/*.c", wsq_src.display()))
        .expect("glob failed")
        .flatten()
    {
        build.file(entry);
    }

    let imgtools_lib = wsq_src.parent().unwrap(); // imgtools/src/lib

    // jpegl/huff.c: build_huffsizes, build_huffcodes, gen_decode_table,
    //               getc_huffman_table — used by the WSQ huffman decoder.
    build.file(imgtools_lib.join("jpegl").join("huff.c"));

    // jpegl/tableio.c: getc_comment — used by wsq/tableio.c marker parsing.
    build.file(imgtools_lib.join("jpegl").join("tableio.c"));

    // commonnbis/ioutil/dataio.c: getc_byte, getc_ushort, getc_uint — low-level
    //   memory I/O primitives used by the huffman and marker parsers.
    build.file(commonnbis_src.join("ioutil").join("dataio.c"));

    // commonnbis/util/computil.c: getc_skip_marker_segment — skips unknown
    //   WSQ marker segments during decoding.
    build.file(commonnbis_src.join("util").join("computil.c"));

    // commonnbis/fet/*.c: extractfet_ret, freefet, string2fet — used by
    //   wsq/ppi.c to extract PPI from WSQ metadata (FET records).
    for entry in glob::glob(&format!(
        "{}/**/*.c",
        commonnbis_src.join("fet").display()
    ))
    .expect("glob failed")
    .flatten()
    {
        build.file(entry);
    }

    // wsq_mem.c provides wsq_free_buf(), a C wrapper around free() so that
    // the Rust FFI does not need a bare `extern "C" { fn free() }` import
    // (which would become an unresolvable "env" import in the browser).
    build.file(shims.join("wsq_mem.c"));

    build
        .include(imgtools_inc)   // wsq.h, jpegl.h, dataio.h, ioutil.h, swap.h
        .include(commonnbis_inc) // defs.h, fet.h
        .include(shims)
        .compile("wsq");

    println!("cargo:rustc-link-lib=static=wsq");
}

// ---------------------------------------------------------------------------
// mindtct LFS library
// ---------------------------------------------------------------------------

fn compile_mindtct(
    mindtct_lib_src: &PathBuf,
    mindtct_inc: &PathBuf,
    commonnbis_inc: &PathBuf,
    an2k_inc: &PathBuf,
    imgtools_inc: &PathBuf,
    shims: &PathBuf,
) {
    let mut build = cc::Build::new();
    apply_common_flags(&mut build);

    for entry in glob::glob(&format!("{}/**/*.c", mindtct_lib_src.display()))
        .expect("glob failed")
        .flatten()
    {
        build.file(entry);
    }
    build.file(shims.join("mindtct_mem.c"));

    build
        .include(mindtct_inc)
        .include(commonnbis_inc)
        .include(an2k_inc)
        .include(imgtools_inc)  // sunrast.h (used by results.c)
        .include(shims)
        .compile("mindtct");

    println!("cargo:rustc-link-lib=static=mindtct");
}
