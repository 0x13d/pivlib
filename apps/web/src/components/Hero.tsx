function scrollToId(id: string) {
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function Hero() {
  return (
    <section id="top" className="relative mx-auto max-w-6xl px-6 sm:px-8 pt-20 pb-14 sm:pt-28 sm:pb-20">
      <div className="flex items-center gap-3 text-xs uppercase tracking-[0.22em] text-inkSoft animate-fadeIn">
        <span className="inline-block w-6 h-px bg-ink/30" />
        <span>PIV / PKI toolkit</span>
      </div>

      <h1
        className="mt-6 font-display text-[clamp(2.5rem,6.5vw,5rem)] leading-[0.96] tracking-tightest text-balance animate-riseIn"
        style={{ fontVariationSettings: '"opsz" 144, "SOFT" 30' }}
      >
        Cards, certs,
        <br />
        <em
          className="not-italic text-ember"
          style={{ fontVariationSettings: '"opsz" 144, "SOFT" 100, "WONK" 1' }}
        >
          decoded.
        </em>
      </h1>

      <p
        className="mt-7 max-w-xl text-[17px] leading-[1.6] text-inkSoft text-pretty animate-riseIn"
        style={{ animationDelay: '120ms' }}
      >
        A pocket toolkit for the people who actually wrangle the files. Drop in
        a mystery X.509 cert in some weird encoding, a PKCS#12 bundle, a PIV
        CHUID container, a portrait JPEG, or a fingerprint WSQ — pivlib will
        tell you what it is, classify the role, and hand you a canonical form.
        Same engine drives the CLI, the npm package, and the VS Code extension.
        Runs locally in WebAssembly.
      </p>

      <div
        className="mt-10 flex flex-wrap items-center gap-3 text-sm animate-riseIn"
        style={{ animationDelay: '220ms' }}
      >
        <button
          type="button"
          onClick={() => scrollToId('toolkit')}
          className="px-5 py-2.5 rounded-full bg-ink text-paper font-medium hover:bg-ember transition-colors"
        >
          Open the toolkit
        </button>
        <button
          type="button"
          onClick={() => scrollToId('how')}
          className="px-5 py-2.5 rounded-full border border-ink/15 hover:border-ink/40 transition-colors text-ink"
        >
          How it works →
        </button>
      </div>

      <div
        className="mt-14 grid grid-cols-2 sm:grid-cols-4 gap-x-8 gap-y-4 max-w-3xl animate-fadeIn"
        style={{ animationDelay: '380ms' }}
      >
        {[
          ['Inputs', 'DER · PEM · base64 · hex · PKCS#7/12'],
          ['Tools', 'cert · csr · crl · key · CHUID · CCC'],
          ['Biometrics', 'INCITS 378/381/385 → CBEFF'],
          ['Engine', 'Rust → WASM'],
        ].map(([k, v]) => (
          <div key={k} className="border-t border-ink/15 pt-3">
            <div className="text-[11px] uppercase tracking-[0.18em] text-inkSoft">{k}</div>
            <div className="text-[14px] mt-0.5 text-ink">{v}</div>
          </div>
        ))}
      </div>
    </section>
  );
}
