import * as wasm from '../wasm-node/pivlib.js';
import { makeBindings } from './core.js';

export type * from './types.js';

// In the Node target, wasm-bindgen emits CommonJS with `wasm` set to the
// instantiated module object — `(wasm as any).memory` is the linear memory.
const bindings = makeBindings(
  wasm as unknown as Parameters<typeof makeBindings>[0],
  () => (wasm as unknown as { memory: WebAssembly.Memory }).memory,
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
