/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Hybrid Aurora Core Palette
        aurora: {
          bg: "#18263B",        // Main background
          secondary: "#253750", // Secondary background
          card: "#2B3F59",      // Card background
          panel: "#1E2F46",     // Panel / elevated background
          primary: "#5B8DEF",   // Primary accent (Aurora Blue)
          teal: "#43D6C5",      // Secondary accent (Aurora Teal)
          purple: "#B3A0FF",    // Additional accent (Aurora Violet)
          text: "#F3F6FC",      // Primary text
          muted: "#B8C5D8",     // Secondary text
          border: "#364D6E",    // Subtle blue-grey border
          success: "#43D6A5",   // Success (Teal-Green)
          warning: "#F5BD61",   // Warning (Warm Amber)
          error: "#FF7185",     // Error (Soft Coral Red)
        },
        // Cyber alias mapped to Hybrid Aurora to maintain full compatibility across codebase
        cyber: {
          bg: "#18263B",
          secondary: "#253750",
          card: "#2B3F59",
          panel: "#1E2F46",
          cyan: "#43D6C5",       // Map cyan to Aurora Teal
          blue: "#5B8DEF",       // Map blue to Aurora Blue
          green: "#43D6A5",      // Map green to Aurora Success
          amber: "#F5BD61",      // Map amber to Aurora Warning
          red: "#FF7185",        // Map red to Aurora Coral Error
          purple: "#B3A0FF",     // Aurora Violet
          text: "#F3F6FC",       // Aurora Primary Text
          muted: "#B8C5D8",      // Aurora Secondary Text
          border: "rgba(91, 141, 239, 0.20)",
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'Monaco', 'monospace'],
        sans: ['"Inter"', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'aurora-card': '0 8px 24px -4px rgba(10, 18, 30, 0.4), 0 2px 6px -2px rgba(10, 18, 30, 0.3)',
        'aurora-glass': '0 8px 32px 0 rgba(10, 18, 30, 0.37)',
        'aurora-primary': '0 0 20px rgba(91, 141, 239, 0.22)',
        'aurora-teal': '0 0 20px rgba(67, 214, 197, 0.22)',
        'aurora-purple': '0 0 20px rgba(179, 160, 255, 0.20)',
        'aurora-coral': '0 0 20px rgba(255, 113, 133, 0.22)',
        'neumorph-sm': '2px 2px 5px rgba(13, 21, 33, 0.45), -1px -1px 3px rgba(255, 255, 255, 0.05)',
        'neumorph-btn': '3px 3px 8px rgba(12, 19, 31, 0.5), -1.5px -1.5px 4px rgba(255, 255, 255, 0.06)',
        'neumorph-inset': 'inset 2px 2px 5px rgba(10, 16, 26, 0.55), inset -1px -1px 3px rgba(255, 255, 255, 0.05)',
        'cyan-glow': '0 0 15px rgba(67, 214, 197, 0.20)',
        'cyan-glow-lg': '0 0 25px rgba(67, 214, 197, 0.30)',
        'red-glow': '0 0 15px rgba(255, 113, 133, 0.25)',
        'green-glow': '0 0 15px rgba(67, 214, 165, 0.25)',
      },
      animation: {
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'aurora-flow': 'aurora 12s ease infinite alternate',
      },
      keyframes: {
        aurora: {
          '0%': { backgroundPosition: '0% 50%' },
          '100%': { backgroundPosition: '100% 50%' },
        }
      }
    },
  },
  plugins: [],
}
