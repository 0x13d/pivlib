import { useState } from 'react';
import { FileDrop } from './FileDrop';
import { LoadSampleBar } from './LoadSampleBar';
import { loadPivlib } from '../../lib/wasm';
import { SAMPLES } from '../../samples';

export function EncodingDetector() {
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(bytes: Uint8Array) {
    setError(null);
    setResult(null);
    try {
      const pivlib = await loadPivlib();
      setResult(pivlib.detect(bytes));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-[15px] text-inkSoft max-w-2xl">
        Drop in any file — a cert, a key, a chain, a CHUID dump — and pivlib
        will walk the cascade (DER → PEM → base64-of-DER → hex-of-DER →
        gzip-of-DER → PKCS#7 → PKCS#12) and tell you what it is.
      </p>
      <LoadSampleBar samples={SAMPLES.encoding} onLoad={onFile} />
      <FileDrop onFile={onFile} hint="Any encoding · any binary or text input" />
      {error ? <pre className="field text-red-700">{error}</pre> : null}
      {result ? (
        <pre className="field whitespace-pre-wrap">{JSON.stringify(result, null, 2)}</pre>
      ) : null}
    </div>
  );
}
