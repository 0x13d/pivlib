import { useState } from 'react';
import { EncodingDetector } from './tools/EncodingDetector';
import { CertInspector } from './tools/CertInspector';
import { CsrInspector } from './tools/CsrInspector';
import { CrlInspector } from './tools/CrlInspector';
import { KeyInspector } from './tools/KeyInspector';
import { Pkcs7Inspector } from './tools/Pkcs7Inspector';
import { Pkcs12Inspector } from './tools/Pkcs12Inspector';
import { ChuidDecoder } from './tools/ChuidDecoder';
import { CccDecoder } from './tools/CccDecoder';
import { SecurityObjectDecoder } from './tools/SecurityObjectDecoder';
import { PortraitEncoder } from './tools/PortraitEncoder';
import { FingerprintEncoder } from './tools/FingerprintEncoder';

const TOOLS = [
  { id: 'detect', label: 'Encoding detector', tag: 'sniff', Component: EncodingDetector },
  { id: 'cert', label: 'X.509 cert + PIV role', tag: 'inspect', Component: CertInspector },
  { id: 'csr', label: 'PKCS#10 CSR', tag: 'inspect', Component: CsrInspector },
  { id: 'crl', label: 'X.509 CRL', tag: 'inspect', Component: CrlInspector },
  { id: 'key', label: 'PKCS#8 key metadata', tag: 'inspect', Component: KeyInspector },
  { id: 'pkcs7', label: 'PKCS#7 / CMS', tag: 'enumerate', Component: Pkcs7Inspector },
  { id: 'pkcs12', label: 'PKCS#12 / PFX', tag: 'enumerate', Component: Pkcs12Inspector },
  { id: 'chuid', label: 'PIV CHUID', tag: 'decode', Component: ChuidDecoder },
  { id: 'ccc', label: 'PIV CCC', tag: 'decode', Component: CccDecoder },
  { id: 'security-object', label: 'PIV Security Object', tag: 'decode', Component: SecurityObjectDecoder },
  { id: 'face', label: 'Portrait → CBEFF', tag: 'encode', Component: PortraitEncoder },
  { id: 'finger', label: 'Fingerprint → CBEFF', tag: 'encode', Component: FingerprintEncoder },
] as const;

type ToolId = (typeof TOOLS)[number]['id'];

export function ToolkitGrid() {
  const [active, setActive] = useState<ToolId | null>(null);

  if (active) {
    const tool = TOOLS.find((t) => t.id === active);
    if (tool) {
      const { Component } = tool;
      return (
        <section id="toolkit" className="mx-auto max-w-6xl px-6 sm:px-8 py-16">
          <div className="flex items-center justify-between mb-6">
            <button
              type="button"
              onClick={() => setActive(null)}
              className="text-[13px] text-inkSoft hover:text-ink transition-colors"
            >
              ← Back to toolkit
            </button>
            <span className="pill">{tool.tag}</span>
          </div>
          <h2
            className="font-display text-[clamp(1.75rem,3.5vw,2.5rem)] tracking-tightest mb-6"
            style={{ fontVariationSettings: '"opsz" 144, "SOFT" 30' }}
          >
            {tool.label}
          </h2>
          <Component />
        </section>
      );
    }
  }

  return (
    <section id="toolkit" className="mx-auto max-w-6xl px-6 sm:px-8 py-16">
      <div className="flex items-center gap-3 text-xs uppercase tracking-[0.22em] text-inkSoft">
        <span className="inline-block w-6 h-px bg-ink/30" />
        <span>Toolkit</span>
      </div>
      <h2
        className="mt-6 font-display text-[clamp(2rem,4vw,3rem)] leading-[1.04] tracking-tightest"
        style={{ fontVariationSettings: '"opsz" 144, "SOFT" 30' }}
      >
        Pick a tool.
      </h2>
      <p className="mt-4 max-w-xl text-[15px] leading-[1.65] text-inkSoft">
        Each tile runs the same Rust core compiled to WASM. Files stay in your
        browser.
      </p>
      <div className="mt-10 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {TOOLS.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setActive(t.id)}
            className="text-left p-5 border border-ink/15 rounded-lg hover:border-ember hover:bg-paperDim/60 transition-colors group"
          >
            <div className="flex items-center justify-between text-[11px] uppercase tracking-[0.18em] text-inkSoft">
              <span>{t.tag}</span>
              <span className="opacity-0 group-hover:opacity-100 transition-opacity text-ember">→</span>
            </div>
            <div className="mt-2 text-[16px] text-ink font-medium">{t.label}</div>
          </button>
        ))}
      </div>
    </section>
  );
}
