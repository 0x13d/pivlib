import { useState } from 'react';
import { FileDrop } from './FileDrop';
import { LoadSampleBar } from './LoadSampleBar';
import { loadPivlib } from '../../lib/wasm';
import { SAMPLES } from '../../samples';

export function PortraitEncoder() {
  const [result, setResult] = useState<{ size: number; base64: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(bytes: Uint8Array) {
    setError(null);
    setResult(null);
    try {
      const pivlib = await loadPivlib();
      const cbeff = pivlib.processFace(bytes);
      setResult({ size: cbeff.length, base64: bytesToBase64(cbeff) });
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-[15px] text-inkSoft max-w-2xl">
        Drop a portrait JPEG. pivlib encodes it as an INCITS 385 / ISO 19794-5
        facial record and wraps it in a CBEFF container — the same shape PIV
        issuance pipelines store under the facial image data object.
      </p>
      <LoadSampleBar samples={SAMPLES.portrait} onLoad={onFile} />
      <FileDrop onFile={onFile} accept="image/jpeg" hint="JPEG only — INCITS 385 / ISO 19794-5" />
      {error ? <pre className="field text-red-700">{error}</pre> : null}
      {result ? (
        <div className="space-y-3">
          <p className="text-[13px] text-inkSoft">
            CBEFF record · {result.size} bytes
          </p>
          <textarea
            readOnly
            className="field w-full h-48 whitespace-pre-wrap break-all"
            value={result.base64}
          />
        </div>
      ) : null}
    </div>
  );
}

function bytesToBase64(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s);
}
