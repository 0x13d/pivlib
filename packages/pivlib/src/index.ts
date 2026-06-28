import * as wasm from '../wasm/pivlib.js';
// Direct WASM import — vite-plugin-wasm exposes the raw exports (including
// `memory`) so wireWasi can hand it to a WASI shim. Both imports share Vite's
// module cache, so this is the same instance pivlib.js already initialized.
import * as wasmRaw from '../wasm/pivlib_bg.wasm';
import { makeBindings } from './core.js';

export type * from './types.js';

const bindings = makeBindings(
  wasm as unknown as Parameters<typeof makeBindings>[0],
  () => (wasmRaw as unknown as { memory: WebAssembly.Memory }).memory,
);

export const detect = bindings.detect;
export const parseCert = bindings.parseCert;
export const classifyPivRole = bindings.classifyPivRole;
export const parseCsr = bindings.parseCsr;
export const parseCrl = bindings.parseCrl;
export const parseKeyMetadata = bindings.parseKeyMetadata;
export const enumeratePkcs7 = bindings.enumeratePkcs7;
export const enumeratePkcs12 = bindings.enumeratePkcs12;
export const parseChuid = bindings.parseChuid;
export const parseCcc = bindings.parseCcc;
export const parseSecurityObject = bindings.parseSecurityObject;
export const processFace = bindings.processFace;
export const processFingerprint = bindings.processFingerprint;
export const wireWasi = bindings.wireWasi;
export type { WasiShim } from './core.js';
