// Lazy WASM loader — avoids paying the WASM cost on every page load.
//
// The bindings live behind the npm package's bundler entry point. Vite's
// `vite-plugin-wasm` resolves the `.wasm` file at build time.
//
// After import we call `wireWasi()` so the WASI snapshot_preview1 shim has a
// handle to WASM memory. NBIS's `fd_write` calls (only fire when its `debug`
// flag is non-zero) decode iovecs out of WASM memory; without wiring they'd
// silently return ENOSYS. The happy path never trips this, but wiring early
// means an NBIS warning will actually surface in the console.

import type * as Pivlib from 'pivlib';

let cached: Promise<typeof Pivlib> | null = null;

export function loadPivlib(): Promise<typeof Pivlib> {
  if (!cached) {
    cached = (async () => {
      const [pivlib, wasi] = await Promise.all([
        import('pivlib'),
        import('wasi_snapshot_preview1'),
      ]);
      pivlib.wireWasi(wasi as unknown as Parameters<typeof pivlib.wireWasi>[0]);
      return pivlib;
    })();
  }
  return cached;
}
