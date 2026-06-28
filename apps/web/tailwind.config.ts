import type { Config } from 'tailwindcss';

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        display: ['Fraunces', 'ui-serif', 'Georgia', 'serif'],
        sans: ['Geist', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Geist Mono"', 'ui-monospace', 'SFMono-Regular', 'monospace'],
      },
      colors: {
        paper: '#F7F4EE',
        paperDim: '#EDE8DC',
        ink: '#0E0F12',
        inkSoft: '#2A2B30',
        rule: '#1F2024',
        // Pivlib's accent: a deeper steel / federal blue, distinct from
        // elsa-to-mermaid's ember orange and netjson-diagrams's network blue.
        ember: '#1E4FB8',
      },
      letterSpacing: {
        tightest: '-0.045em',
      },
      keyframes: {
        riseIn: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
      },
      animation: {
        riseIn: 'riseIn 700ms cubic-bezier(0.22, 1, 0.36, 1) both',
        fadeIn: 'fadeIn 600ms ease-out both',
      },
    },
  },
  plugins: [],
} satisfies Config;
