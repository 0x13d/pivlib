import { useState } from 'react';
import type { CertSummary, Classification } from 'pivlib';
import { FileDrop } from './FileDrop';
import { LoadSampleBar } from './LoadSampleBar';
import { loadPivlib } from '../../lib/wasm';
import { SAMPLES } from '../../samples';

export function CertInspector() {
  const [summary, setSummary] = useState<CertSummary | null>(null);
  const [classification, setClassification] = useState<Classification | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onFile(bytes: Uint8Array) {
    setError(null);
    setSummary(null);
    setClassification(null);
    try {
      const pivlib = await loadPivlib();
      const detected = pivlib.detect(bytes);
      const der = decodeBase64(detected.normalized_der);
      setSummary(pivlib.parseCert(der));
      setClassification(pivlib.classifyPivRole(der));
    } catch (e) {
      setError(String(e));
    }
  }

  return (
    <div className="space-y-6">
      <p className="text-[15px] text-inkSoft max-w-2xl">
        Drop an X.509 certificate in any encoding. pivlib normalizes it, then
        classifies its PIV role from the policy OIDs, EKU, KeyUsage, and SAN
        OIDs — and shows you the evidence it used.
      </p>
      <LoadSampleBar samples={SAMPLES.cert} onLoad={onFile} />
      <FileDrop onFile={onFile} hint="DER / PEM / base64-of-DER / hex-of-DER" />
      {error ? <pre className="field text-red-700">{error}</pre> : null}
      {classification ? (
        <div className="border border-ink/15 rounded-lg p-5">
          <div className="text-[11px] uppercase tracking-[0.18em] text-inkSoft">PIV role</div>
          <div className="mt-1 text-[28px] font-display tracking-tightest text-ember">
            {classification.role}
          </div>
          <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-[13px]">
            <Field k="Policy OIDs" v={classification.evidence.policy_oids.join('  ·  ') || '—'} />
            <Field k="EKUs" v={classification.evidence.extended_key_usages.join('  ·  ') || '—'} />
            <Field k="Key usage" v={classification.evidence.key_usage.join(', ') || '—'} />
            <Field k="SAN OIDs" v={classification.evidence.san_oids.join('  ·  ') || '—'} />
            <Field k="FASC-N in SAN" v={classification.evidence.fascn_present ? 'yes' : 'no'} />
            <Field
              k="PIV card UUID in SAN"
              v={classification.evidence.piv_card_uuid_present ? 'yes' : 'no'}
            />
          </div>
        </div>
      ) : null}
      {summary ? (
        <pre className="field whitespace-pre-wrap">{JSON.stringify(summary, null, 2)}</pre>
      ) : null}
    </div>
  );
}

function Field({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="text-[11px] uppercase tracking-[0.16em] text-inkSoft">{k}</div>
      <div className="mt-0.5 font-mono text-[12.5px] text-ink break-all">{v}</div>
    </div>
  );
}

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
