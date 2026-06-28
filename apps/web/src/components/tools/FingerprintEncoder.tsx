import { useState } from 'react';
import { FileDrop } from './FileDrop';
import { LoadSampleBar } from './LoadSampleBar';
import { loadPivlib } from '../../lib/wasm';
import { SAMPLES } from '../../samples';

const POSITIONS: { code: number; label: string }[] = [
  { code: 2, label: 'Right Index (2)' },
  { code: 7, label: 'Left Index (7)' },
  { code: 1, label: 'Right Thumb (1)' },
  { code: 6, label: 'Left Thumb (6)' },
  { code: 3, label: 'Right Middle (3)' },
  { code: 8, label: 'Left Middle (8)' },
  { code: 4, label: 'Right Ring (4)' },
  { code: 9, label: 'Left Ring (9)' },
  { code: 5, label: 'Right Little (5)' },
  { code: 10, label: 'Left Little (10)' },
];

export function FingerprintEncoder() {
  const [position, setPosition] = useState(2);
  const [result, setResult] = useState<{ size: number; base64: string } | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(bytes: Uint8Array) {
    setError(null);
    setResult(null);
    try {
      const pivlib = await loadPivlib();
      const cbeff = pivlib.processFingerprint(bytes, position, 0);
      setResult({ size: cbeff.length, base64: bytesToBase64(cbeff) });
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-[15px] text-inkSoft max-w-2xl">
        Drop a WSQ-encoded fingerprint image. pivlib decodes it via NBIS, runs
        mindtct for minutiae, and wraps both an INCITS 381 image record and an
        INCITS 378 minutiae record in a single multi-BDB CBEFF container.
      </p>
      <label className="block">
        <span className="text-[11px] uppercase tracking-[0.18em] text-inkSoft">
          Finger position (INCITS 378 Table 5)
        </span>
        <select
          value={position}
          onChange={(e) => setPosition(Number(e.target.value))}
          className="mt-1 block w-full sm:w-72 border border-ink/15 rounded-md px-3 py-2 bg-paper text-ink"
        >
          {POSITIONS.map((p) => (
            <option key={p.code} value={p.code}>
              {p.label}
            </option>
          ))}
        </select>
      </label>
      <LoadSampleBar samples={SAMPLES.fingerprint} onLoad={onFile} />
      <FileDrop onFile={onFile} accept=".wsq" hint="WSQ — IAFIS / NBIS encoding" />
      {error ? <pre className="field text-red-700">{error}</pre> : null}
      {result ? (
        <div className="space-y-3">
          <p className="text-[13px] text-inkSoft">CBEFF record · {result.size} bytes (image + minutiae)</p>
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
