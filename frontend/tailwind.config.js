/** @type {import('tailwindcss').Config} */
// Colors resolve to CSS variables defined in src/index.css (single source of truth for the theme).
const token = (name) => `rgb(var(--c-${name}) / <alpha-value>)`;

const palette = {
  forest: token('forest'),         // #54766A primary
  bluegrey: token('bluegrey'),     // #8296A5 secondary
  sage: token('sage'),             // #D6DFDA soft sage grey
  mist: token('mist'),             // #ECEFEA page background
  surface: token('surface'),       // #FFFFFF cards / inputs
  ink: token('ink'),               // #334155 headings + primary text
  muted: token('muted'),           // #64748B secondary text
  good: token('good'),             // #7C9B83 success
  amber: token('amber'),           // #C5A66D warning / pending
  bad: token('bad'),               // #C87878 error / destructive
  // Darker text-safe shades of the status colors (contrast on white/sage)
  'bluegrey-ink': token('bluegrey-ink'),
  'good-ink': token('good-ink'),
  'amber-ink': token('amber-ink'),
  'bad-ink': token('bad-ink'),
};

export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        ...palette,
        // Legacy aliases so existing `aurora-*` / `cyber-*` classes follow the new theme
        aurora: {
          bg: token('mist'), secondary: token('sage'), card: token('surface'), surface: token('surface'),
          panel: token('sage'), primary: token('forest'), blue: token('bluegrey'), teal: token('forest'),
          purple: token('bluegrey'), violet: token('bluegrey'), text: token('ink'), muted: token('muted'),
          border: token('bluegrey'), success: token('good'), warning: token('amber'), error: token('bad'),
        },
        cyber: {
          bg: token('mist'), secondary: token('sage'), card: token('surface'), panel: token('sage'),
          cyan: token('forest'), blue: token('bluegrey'), green: token('good'), amber: token('amber'),
          red: token('bad'), purple: token('bluegrey'), text: token('ink'), muted: token('muted'),
          border: token('bluegrey'),
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'Monaco', 'monospace'],
        sans: ['"Inter"', 'system-ui', '-apple-system', 'sans-serif'],
      },
      // Restrained shadows (old glow / neumorphic names kept so existing classes still resolve)
      boxShadow: {
        soft: '0 1px 2px rgba(51, 65, 85, 0.06), 0 2px 8px rgba(51, 65, 85, 0.05)',
        'aurora-card': '0 1px 2px rgba(51, 65, 85, 0.06), 0 2px 8px rgba(51, 65, 85, 0.05)',
        'aurora-glass': '0 1px 2px rgba(51, 65, 85, 0.06), 0 2px 8px rgba(51, 65, 85, 0.05)',
        'aurora-btn': '0 1px 2px rgba(51, 65, 85, 0.10)',
        'aurora-primary': 'none',
        'aurora-teal': 'none',
        'aurora-purple': 'none',
        'aurora-coral': 'none',
        'neumorph-sm': '0 1px 2px rgba(51, 65, 85, 0.06)',
        'neumorph-btn': '0 1px 2px rgba(51, 65, 85, 0.10)',
        'neumorph-inset': 'inset 0 1px 2px rgba(51, 65, 85, 0.06)',
        'cyan-glow': 'none',
        'cyan-glow-lg': 'none',
        'red-glow': 'none',
        'green-glow': 'none',
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        fadeIn: 'fadeIn 0.15s ease-out',
        slideIn: 'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn: { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideIn: { '0%': { transform: 'translateX(16px)', opacity: '0' }, '100%': { transform: 'translateX(0)', opacity: '1' } },
      },
    },
  },
  plugins: [],
}
