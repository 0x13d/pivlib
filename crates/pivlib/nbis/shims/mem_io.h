/*
 * mem_io.h — portable fmemopen for environments that lack it.
 *
 * fmemopen(3) is POSIX.1-2008 and is available on:
 *   macOS 10.13+, Linux glibc 2.2+, emscripten, wasm32-wasi (via WASI libc).
 *
 * For wasm32-unknown-unknown (no-std, no OS), a minimal fallback is provided
 * below that implements just enough of the FILE interface for sequential reads
 * (which is all NBIS WSQ decode needs).
 */

#ifndef NBIS_MEM_IO_H
#define NBIS_MEM_IO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__wasm__) && !defined(__wasi__)
/* ------------------------------------------------------------------ *
 * Minimal in-memory FILE shim for bare wasm32-unknown-unknown.        *
 *                                                                      *
 * Only supports sequential fread/fgetc/fseek/ftell/rewind/feof/fclose.*
 * ------------------------------------------------------------------ */

typedef struct {
    const unsigned char *buf;
    size_t               len;
    size_t               pos;
    int                  eof;
} _MemFile;

static FILE *_mem_fopen_table[16];   /* slots for open memory streams */
static _MemFile _mem_file_data[16];

static FILE *nbis_fmemopen(const void *buf, size_t size, const char *mode) {
    (void)mode;
    for (int i = 0; i < 16; i++) {
        if (_mem_fopen_table[i] == NULL) {
            _mem_file_data[i].buf = (const unsigned char *)buf;
            _mem_file_data[i].len = size;
            _mem_file_data[i].pos = 0;
            _mem_file_data[i].eof = 0;
            /* Return a non-NULL sentinel; actual I/O is intercepted via
             * the macros below before reaching libc. */
            _mem_fopen_table[i] = (FILE *)(void *)&_mem_file_data[i];
            return _mem_fopen_table[i];
        }
    }
    return NULL; /* no free slots */
}

static _MemFile *_memfile_of(FILE *fp) {
    for (int i = 0; i < 16; i++) {
        if (_mem_fopen_table[i] == fp)
            return &_mem_file_data[i];
    }
    return NULL;
}

static size_t _mem_fread(void *ptr, size_t size, size_t nmemb, FILE *fp) {
    _MemFile *m = _memfile_of(fp);
    if (!m) return 0;
    size_t want = size * nmemb;
    size_t avail = m->len - m->pos;
    size_t got = want < avail ? want : avail;
    memcpy(ptr, m->buf + m->pos, got);
    m->pos += got;
    if (got < want) m->eof = 1;
    return got / (size ? size : 1);
}

static int _mem_fgetc(FILE *fp) {
    _MemFile *m = _memfile_of(fp);
    if (!m || m->pos >= m->len) { if (m) m->eof = 1; return EOF; }
    return (unsigned char)m->buf[m->pos++];
}

static int _mem_fseek(FILE *fp, long offset, int whence) {
    _MemFile *m = _memfile_of(fp);
    if (!m) return -1;
    long newpos;
    if      (whence == SEEK_SET) newpos = offset;
    else if (whence == SEEK_CUR) newpos = (long)m->pos + offset;
    else                          newpos = (long)m->len + offset;
    if (newpos < 0 || (size_t)newpos > m->len) return -1;
    m->pos = (size_t)newpos;
    m->eof = 0;
    return 0;
}

static long _mem_ftell(FILE *fp) {
    _MemFile *m = _memfile_of(fp);
    return m ? (long)m->pos : -1L;
}

static int _mem_feof(FILE *fp) {
    _MemFile *m = _memfile_of(fp);
    return m ? m->eof : 1;
}

static int _mem_fclose(FILE *fp) {
    for (int i = 0; i < 16; i++) {
        if (_mem_fopen_table[i] == fp) {
            _mem_fopen_table[i] = NULL;
            return 0;
        }
    }
    return EOF;
}

/* Intercept NBIS file calls when compiling with NBIS_NO_FILE_IO */
#define fmemopen  nbis_fmemopen
#define fread     _mem_fread
#define fgetc     _mem_fgetc
#define fseek     _mem_fseek
#define ftell     _mem_ftell
#define feof      _mem_feof
#define fclose    _mem_fclose

#else
/* glibc / macOS / emscripten / WASI — fmemopen is native */
#define nbis_fmemopen fmemopen
#endif /* bare wasm32 fallback */

#endif /* NBIS_MEM_IO_H */
