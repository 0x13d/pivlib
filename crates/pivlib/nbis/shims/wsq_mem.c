/*
 * wsq_mem.c — WASM compatibility shim for WSQ decoding.
 *
 * NBIS imgtools already provides wsq_decode_mem() directly in
 * imgtools/src/lib/wsq/decoder.c, so no file-I/O wrapper is needed.
 *
 * This file only provides wsq_free_buf(), a thin wrapper around free().
 * Rust's `extern "C" { fn free() }` would create a WASM import from the
 * "env" module (which browsers cannot resolve).  Calling wsq_free_buf()
 * instead keeps the symbol inside the compiled WASM binary.
 */

#include <stdlib.h>

void wsq_free_buf(void *ptr)
{
    free(ptr);
}

/*
 * Provide the `debug` symbol that NBIS WSQ decoder/encoder reference.
 *
 * NBIS expects the consuming application to define `int debug` — the
 * declaration in nbis/imgtools/src/lib/wsq/globals.c is commented out.
 * Setting it to 0 keeps NBIS's tracing prints quiet by default.
 */
int debug = 0;
