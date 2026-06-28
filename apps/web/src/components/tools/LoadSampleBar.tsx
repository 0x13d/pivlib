import { useState } from 'react';
import { fetchSampleBytes, type Sample } from '../../samples';

interface Props {
  samples: readonly Sample[];
  onLoad: (bytes: Uint8Array) => void | Promise<void>;
}

export function LoadSampleBar({ samples, onLoad }: Props) {
  const [loading, setLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (samples.length === 0) return null;

  async function pick(sample: Sample) {
    setError(null);
    setLoading(sample.label);
    try {
      const bytes = await fetchSampleBytes(sample);
      await onLoad(bytes);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(null);
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[11px] uppercase tracking-[0.18em] text-inkSoft">
          Load sample
        </span>
        {samples.map((s) => (
          <button
            key={s.label}
            type="button"
            onClick={() => pick(s)}
            disabled={loading !== null}
            title={s.description}
            className="px-3 py-1 text-[12.5px] border border-ink/15 rounded-md bg-paper hover:bg-ink/[0.04] disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {loading === s.label ? 'Loading…' : s.label}
          </button>
        ))}
      </div>
      {error ? <pre className="field text-red-700 text-[12px]">{error}</pre> : null}
    </div>
  );
}
