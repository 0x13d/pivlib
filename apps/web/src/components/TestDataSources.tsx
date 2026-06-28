// Pointers to places that publish real-world biometric test data. The demo
// samples are synthetic on purpose — a 1×1 white-pixel JPEG isn't a face and
// nothing here is a real fingerprint — but if you want to exercise pivlib
// against actual captures, these are the canonical public sources.

export function TestDataSources() {
  return (
    <section id="test-data" className="mx-auto max-w-6xl px-6 sm:px-8 py-20 border-t border-ink/10">
      <div className="flex items-center gap-3 text-xs uppercase tracking-[0.22em] text-inkSoft">
        <span className="inline-block w-6 h-px bg-ink/30" />
        <span>Test data</span>
      </div>
      <h2
        className="mt-6 font-display text-[clamp(1.5rem,3vw,2.25rem)] leading-[1.1] tracking-tightest"
        style={{ fontVariationSettings: '"opsz" 144, "SOFT" 30' }}
      >
        Want to throw real biometrics at it?
      </h2>
      <p className="mt-5 max-w-2xl text-[15px] text-inkSoft leading-[1.65]">
        The bundled samples are synthetic so we don't ship anyone's fingerprints
        or face online. The PKI side doesn't need real data either — synthetic
        certs exercise the parser just as well. For biometric inputs, these are
        the canonical public corpuses:
      </p>
      <div className="mt-10 grid grid-cols-1 md:grid-cols-3 gap-8 text-[14px] leading-[1.6]">
        <Source
          kind="WSQ"
          name="Cognaxon WSQ Library"
          href="https://www.cognaxon.com/index.php?page=download_wsqlibrary"
          note="Free downloadable WSQ samples for testing decoders + minutiae extractors."
        />
        <Source
          kind="Fingerprint"
          name="NIST Special Database 4 / 14 / 302"
          href="https://www.nist.gov/itl/iad/image-group/nist-special-database-fingerprint-databases"
          note="Public-domain U.S. government fingerprint corpora. SD-4 is the classic NFIQ baseline; SD-302 is multi-finger."
        />
        <Source
          kind="Portrait"
          name="NIST FERET / FRGC"
          href="https://www.nist.gov/itl/iad/image-group"
          note="Face image datasets — licensing varies, some require attestation. Use INCITS 385 conformance data if available."
        />
      </div>
      <p className="mt-10 text-[13px] text-inkSoft leading-[1.6]">
        pivlib never uploads what you drop. All processing — detection,
        parsing, classification, biometric encoding — happens in WebAssembly
        inside this tab. The fixtures and any file you supply stay local.
      </p>
    </section>
  );
}

function Source({ kind, name, href, note }: { kind: string; name: string; href: string; note: string }) {
  return (
    <div className="border-t border-ink/15 pt-5">
      <div className="text-[11px] uppercase tracking-[0.18em] text-inkSoft">{kind}</div>
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-2 inline-block font-display text-[18px] text-ember hover:underline tracking-tightest"
      >
        {name} →
      </a>
      <p className="mt-2 text-ink/85">{note}</p>
    </div>
  );
}
