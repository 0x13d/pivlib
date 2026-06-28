/// <reference types="vite/client" />

// Resolved via the `resolve.alias` in vite.config.ts to the browser shim at
// apps/web/public/wasi_snapshot_preview1.js — declared here so tsc accepts the
// bare specifier.
declare module 'wasi_snapshot_preview1' {
  export function setWasmMemory(memory: WebAssembly.Memory): void;
  export function fd_write(fd: number, iovs: number, iovs_len: number, nwritten: number): number;
}
