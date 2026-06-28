export function HowItWorks() {
  return (
    <section id="how" className="mx-auto max-w-6xl px-6 sm:px-8 py-20">
      <div className="flex items-center gap-3 text-xs uppercase tracking-[0.22em] text-inkSoft">
        <span className="inline-block w-6 h-px bg-ink/30" />
        <span>How it works</span>
      </div>
      <h2
        className="mt-6 font-display text-[clamp(2rem,4vw,3rem)] leading-[1.04] tracking-tightest"
        style={{ fontVariationSettings: '"opsz" 144, "SOFT" 30' }}
      >
        One core. One trip through the cascade. No round-trip to a server.
      </h2>
      <div className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-8 text-[15px] leading-[1.65]">
        <Step
          number="1"
          title="Detect"
          body={
            <>
              Any bytes go through <span className="font-mono text-[13px]">encoding::detect</span>:
              ASN.1 magic → PEM armor → base64-of-DER → hex-of-DER → gzip → PKCS#7 → PKCS#12.
              Returns the matched format plus a canonical DER form.
            </>
          }
        />
        <Step
          number="2"
          title="Parse"
          body={
            <>
              The canonical DER is handed to a typed parser per tool: cert,
              CSR, CRL, PKCS#8 key, PKCS#7 envelope, PKCS#12 bundle, or one of
              the SP 800-73 BER-TLV containers (CHUID, CCC, Security Object).
            </>
          }
        />
        <Step
          number="3"
          title="Classify"
          body={
            <>
              For X.509 certs, the PIV role classifier reads policy OIDs, EKU,
              KeyUsage, and PIV-specific SAN OIDs and returns one of{' '}
              <em>PivAuth · CardAuth · DigitalSignature · KeyManagement ·
                ContentSigning</em> — with the evidence it used.
            </>
          }
        />
      </div>
    </section>
  );
}

function Step({ number, title, body }: { number: string; title: string; body: React.ReactNode }) {
  return (
    <div className="border-t border-ink/15 pt-5">
      <div className="text-[11px] uppercase tracking-[0.18em] text-inkSoft flex items-center gap-2">
        <span className="font-mono text-ember">{number}</span>
        <span>{title}</span>
      </div>
      <p className="mt-3 text-ink text-pretty">{body}</p>
    </div>
  );
}
