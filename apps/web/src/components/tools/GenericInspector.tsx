import { useState } from 'react';
import { FileDrop } from './FileDrop';
import { LoadSampleBar } from './LoadSampleBar';
import { loadPivlib } from '../../lib/wasm';
import type * as Pivlib from 'pivlib';
import type { Sample } from '../../samples';

interface GenericInspectorProps {
  description: string;
  hint?: string;
  /** Normalise the dropped bytes to DER via `detect()` first. Default true. */
  normalize?: boolean;
  /** The pivlib call to run on the (normalised) bytes. */
  run: (api: typeof Pivlib, bytes: Uint8Array) => Promise<unknown>;
  /** Optional Load Sample bar shown above the FileDrop. */
  samples?: readonly Sample[];
}

export function GenericInspector({
  description,
  hint,
  normalize = true,
  run,
  samples,
}: GenericInspectorProps) {
  const [result, setResult] = useState<unknown>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(bytes: Uint8Array) {
    setError(null);
    setResult(null);
    try {
      const pivlib = await loadPivlib();
      const input = normalize
        ? decodeBase64(pivlib.detect(bytes).normalized_der)
        : bytes;
      setResult(await run(pivlib, input));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-[15px] text-inkSoft max-w-2xl">{description}</p>
      {samples && samples.length > 0 ? (
        <LoadSampleBar samples={samples} onLoad={onFile} />
      ) : null}
      <FileDrop onFile={onFile} hint={hint} />
      {error ? <pre className="field text-red-700">{error}</pre> : null}
      {result ? (
        <pre className="field whitespace-pre-wrap">{JSON.stringify(result, null, 2)}</pre>
      ) : null}
    </div>
  );
}

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
