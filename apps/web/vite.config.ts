import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import react from '@vitejs/plugin-react';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [react(), wasm()],
  resolve: {
    alias: {
      // NBIS-built WASM imports `wasi_snapshot_preview1` as a bare module
      // specifier. Resolve it to the browser shim under public/ so Rollup can
      // bundle it. The shim lives at apps/web/public/wasi_snapshot_preview1.js
      // (served at /wasi_snapshot_preview1.js in dev, copied to dist/ in prod).
      wasi_snapshot_preview1: resolve(__dirname, 'public/wasi_snapshot_preview1.js'),
    },
  },
  build: {
    // Native top-level await — same rationale as netjson-diagrams.
    target: 'esnext',
  },
  server: {
    fs: { allow: ['../..'] },
    // OPFS / SharedArrayBuffer headers — needed when the web app eventually
    // wires up the SQLite-backed local store. Cheap to add now.
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
  },
  optimizeDeps: {
    exclude: ['pivlib'],
  },
});
