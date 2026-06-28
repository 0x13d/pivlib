/**
 * Minimal WASI snapshot_preview1 shim for the browser.
 *
 * The pivlib WASM binary is compiled with WASI SDK for the C portions
 * (NBIS WSQ / mindtct).  WASI SDK's libc uses these syscalls for stdio
 * and process management.  This shim provides just enough for the binary
 * to load and run in a browser:
 *
 *   • fd_write    — routes stderr/stdout to console.warn
 *   • fd_prestat* — return EBADF (no pre-opened directories)
 *   • others      — return ENOSYS / EBADF as appropriate
 *
 * Wire up WASM memory immediately after init() so fd_write can read iovecs:
 *
 *   const exports = await init();
 *   setWasmMemory(exports.memory);
 */

const ERRNO_SUCCESS = 0;
const ERRNO_BADF = 8;
const ERRNO_NOSYS = 52;

let _mem = null;

/** Call this right after init() with the wasm memory export. */
export function setWasmMemory(memory) {
    _mem = memory;
}

export function fd_write(fd, iovs, iovs_len, nwritten) {
    if (!_mem) return ERRNO_NOSYS;

    const view = new DataView(_mem.buffer);
    let written = 0;
    let text = '';

    for (let i = 0; i < iovs_len; i++) {
        const ptr = view.getUint32(iovs + i * 8, true);
        const len = view.getUint32(iovs + i * 8 + 4, true);
        text += new TextDecoder().decode(new Uint8Array(_mem.buffer, ptr, len));
        written += len;
    }

    if (text.trim()) {
        // Route all WASI stdio to the browser console so NBIS warnings are visible.
        console.warn('[wasm-c]', text.trimEnd());
    }

    view.setUint32(nwritten, written, true);
    return ERRNO_SUCCESS;
}

export function fd_close(_fd) {
    return ERRNO_SUCCESS;
}

export function fd_fdstat_get(_fd, _buf) {
    return ERRNO_BADF;
}

export function fd_prestat_get(_fd, _buf) {
    // Returning EBADF tells WASI libc there are no pre-opened directories.
    return ERRNO_BADF;
}

export function fd_prestat_dir_name(_fd, _path, _path_len) {
    return ERRNO_BADF;
}

export function fd_seek(_fd, _lo, _hi, _whence, _newoffset) {
    return ERRNO_NOSYS;
}

export function proc_exit(code) {
    throw new Error('[wasm] proc_exit(' + code + ')');
}
