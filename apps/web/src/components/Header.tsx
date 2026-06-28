import { Logo } from './Logo';

const NAV = [
  { href: '#toolkit', label: 'Toolkit' },
  { href: '#how', label: 'How it works' },
  { href: 'https://github.com/ariugwu/pivlib', label: 'GitHub', external: true },
];

function scrollToId(id: string) {
  const el = document.getElementById(id);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function Header() {
  return (
    <header className="sticky top-0 z-50">
      <div className="glass border-b border-ink/10">
        <div 
        className="mx-auto max-w-6xl px-6 sm:px-8 h-12 flex items-center justify-between text-[13px]"
        style={{ background: "#B7BEAF", boxShadow: "2px 2px 13px 2px"}}
        >
          <a
            href="#top"
            onClick={(e) => {
              e.preventDefault();
              window.scrollTo({ top: 0, behavior: 'smooth' });
            }}
            className="flex items-center gap-2 text-ink hover:text-ember transition-colors"
          >
            <Logo size={20} />
            <span className="font-medium tracking-tight">pivlib</span>
          </a>
          <nav className="flex items-center gap-6">
            {NAV.map((item) =>
              item.external ? (
                <a
                  key={item.href}
                  href={item.href}
                  target="_blank"
                  rel="noreferrer"
                  className="text-inkSoft hover:text-ink transition-colors"
                >
                  {item.label}
                </a>
              ) : (
                <a
                  key={item.href}
                  href={item.href}
                  onClick={(e) => {
                    e.preventDefault();
                    scrollToId(item.href.slice(1));
                  }}
                  className="text-inkSoft hover:text-ink transition-colors"
                >
                  {item.label}
                </a>
              ),
            )}
          </nav>
        </div>
      </div>
    </header>
  );
}
