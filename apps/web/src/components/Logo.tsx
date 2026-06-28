interface LogoProps {
  size?: number;
  className?: string;
  ariaLabel?: string;
}

/**
 * Brand mark — a card silhouette with a chip + a key channel, riffing on
 * the PIV card form factor without aping any specific agency seal.
 */
export function Logo({ size = 28, className, ariaLabel = 'pivlib' }: LogoProps) {
  return (
    <svg
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="none"
      stroke="currentColor"
      strokeWidth={1.6}
      strokeLinecap="round"
      strokeLinejoin="round"
      role="img"
      aria-label={ariaLabel}
      className={className}
    >
      <rect x="4" y="7" width="24" height="18" rx="2.5" />
      <rect x="7.5" y="11" width="6" height="5" rx="1" stroke="#1E4FB8" />
      <path d="M16.5 13 L25 13" />
      <path d="M16.5 17 L25 17" />
      <path d="M7.5 20.5 L25 20.5" strokeDasharray="1.5 1.5" stroke="#1E4FB8" />
    </svg>
  );
}
