/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#050816",
          secondary: "#0B1120",
          card: "#0F172A",
          panel: "#111C31",
          cyan: "#00F5FF",
          blue: "#3B82F6",
          green: "#00FFA3",
          amber: "#FFB020",
          red: "#FF355E",
          text: "#E6F1FF",
          muted: "#94A3B8",
          border: "rgba(0, 245, 255, 0.18)",
        }
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'Monaco', 'monospace'],
        sans: ['"Inter"', 'system-ui', '-apple-system', 'sans-serif'],
      },
      boxShadow: {
        'cyan-glow': '0 0 15px rgba(0, 245, 255, 0.25)',
        'cyan-glow-lg': '0 0 25px rgba(0, 245, 255, 0.4)',
        'red-glow': '0 0 15px rgba(255, 53, 94, 0.3)',
        'green-glow': '0 0 15px rgba(0, 255, 163, 0.3)',
      },
      animation: {
        'scan': 'scan 4s linear infinite',
        'pulse-subtle': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        scan: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(1000%)' },
        }
      }
    },
  },
  plugins: [],
}
