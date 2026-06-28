import type {
  Ccc,
  CertSummary,
  Chuid,
  Classification,
  CrlSummary,
  CsrSummary,
  DetectResult,
  KeySummary,
  Pkcs12Summary,
  Pkcs7Summary,
  SecurityObject,
} from './types.js';

export interface WasmBindings {
  detect(bytes: Uint8Array): unknown;
  parse_cert(der: Uint8Array): unknown;
  classify_piv_role(der: Uint8Array): unknown;
  parse_csr(der: Uint8Array): unknown;
  parse_crl(der: Uint8Array): unknown;
  parse_key_metadata(der: Uint8Array): unknown;
  enumerate_pkcs7(der: Uint8Array): unknown;
  enumerate_pkcs12(der: Uint8Array): unknown;
  parse_chuid(bytes: Uint8Array): unknown;
  parse_ccc(bytes: Uint8Array): unknown;
  parse_security_object(der: Uint8Array): unknown;
  process_face(jpeg: Uint8Array, landmarksJson?: string | undefined): Uint8Array;
  process_fingerprint(wsq: Uint8Array, position: number, impression: number): Uint8Array;
}

/**
 * Shape of the browser WASI shim — anything with a `setWasmMemory` setter.
 * The bundled NBIS WASM imports `wasi_snapshot_preview1.fd_write` for
 * diagnostic stdio. fd_write needs to read iovecs out of WASM linear memory,
 * which it can't do until you hand it the memory export. `wireWasi` does
 * that without coupling this package to a specific shim file.
 */
export interface WasiShim {
  setWasmMemory(memory: WebAssembly.Memory): void;
}

/** Per-target factory hook for `wireWasi` so the bundler vs node entries can
 * each grab the raw `WebAssembly.Memory` from their own WASM import. */
export type MemoryProvider = () => WebAssembly.Memory;

export function makeBindings(wasm: WasmBindings, memoryProvider?: MemoryProvider) {
  function asBytes(input: Uint8Array | ArrayBuffer | string): Uint8Array {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    return new TextEncoder().encode(input);
  }

  return {
    /** Sniff the encoding of arbitrary bytes. Returns format + normalized DER. */
    detect(input: Uint8Array | ArrayBuffer | string): DetectResult {
      return wasm.detect(asBytes(input)) as DetectResult;
    },
    /** Parse an X.509 v3 certificate from DER. Run `detect()` first for any other encoding. */
    parseCert(der: Uint8Array): CertSummary {
      return wasm.parse_cert(der) as CertSummary;
    },
    /** Classify a cert as PivAuth / CardAuth / DigitalSignature / KeyManagement / ContentSigning / Unknown, with evidence. */
    classifyPivRole(der: Uint8Array): Classification {
      return wasm.classify_piv_role(der) as Classification;
    },
    parseCsr(der: Uint8Array): CsrSummary {
      return wasm.parse_csr(der) as CsrSummary;
    },
    parseCrl(der: Uint8Array): CrlSummary {
      return wasm.parse_crl(der) as CrlSummary;
    },
    /** PKCS#8 metadata only — algorithm + parameters. Never returns key material. */
    parseKeyMetadata(der: Uint8Array): KeySummary {
      return wasm.parse_key_metadata(der) as KeySummary;
    },
    enumeratePkcs7(der: Uint8Array): Pkcs7Summary {
      return wasm.enumerate_pkcs7(der) as Pkcs7Summary;
    },
    enumeratePkcs12(der: Uint8Array): Pkcs12Summary {
      return wasm.enumerate_pkcs12(der) as Pkcs12Summary;
    },
    parseChuid(bytes: Uint8Array): Chuid {
      return wasm.parse_chuid(bytes) as Chuid;
    },
    parseCcc(bytes: Uint8Array): Ccc {
      return wasm.parse_ccc(bytes) as Ccc;
    },
    parseSecurityObject(der: Uint8Array): SecurityObject {
      return wasm.parse_security_object(der) as SecurityObject;
    },
    /** JPEG → CBEFF-wrapped INCITS 385 facial record. */
    processFace(jpeg: Uint8Array, landmarksJson?: string): Uint8Array {
      return wasm.process_face(jpeg, landmarksJson);
    },
    /** WSQ → CBEFF-wrapped INCITS 378 minutiae + INCITS 381 image. */
    processFingerprint(
      wsq: Uint8Array,
      position: number,
      impression = 0,
    ): Uint8Array {
      return wasm.process_fingerprint(wsq, position, impression);
    },
    /**
     * Wire the WASM module's linear memory into a WASI shim so that NBIS
     * diagnostic stdio (`fd_write`) can decode iovecs out of WASM memory and
     * route NBIS log lines to the host console.
     *
     * Optional — the happy path through pivlib never calls fd_write (NBIS's
     * `debug` flag is hard-coded to 0 in the shim). Call this if you want to
     * surface NBIS warnings during development, or if you've flipped `debug`
     * on for tracing. Throws if the entry point didn't pass a memory provider.
     *
     * @example
     * ```ts
     * import * as pivlib from 'pivlib';
     * import * as wasi from './wasi_snapshot_preview1.js';
     * pivlib.wireWasi(wasi);
     * ```
     */
    wireWasi(shim: WasiShim): void {
      if (!memoryProvider) {
        throw new Error(
          'wireWasi: this pivlib entry point was built without a memory provider.',
        );
      }
      shim.setWasmMemory(memoryProvider());
    },
  };
}
