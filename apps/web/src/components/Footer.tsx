export function Footer() {
  return (
    <footer className="border-t border-ink/10 mt-24">
      <div className="mx-auto max-w-6xl px-6 sm:px-8 py-8 text-[13px] text-inkSoft flex flex-wrap items-center justify-between gap-3">
        <span>
          pivlib · Rust core compiled to WASM · runs locally in your browser, no third-party servers.
        </span>
        <a
          href="https://github.com/ariugwu/pivlib"
          target="_blank"
          rel="noreferrer"
          className="hover:text-ink transition-colors"
        >
          github.com/ariugwu/pivlib →
        </a>
      </div>
    </footer>
  );
}
