/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#06080f', 900: '#0a0e1a', 850: '#0d1322', 800: '#111a2e',
          700: '#1a2438', 600: '#24304a', 500: '#33415e', 400: '#4a5b80',
        },
        accent: { DEFAULT: '#a855f7', soft: '#c084fc', dim: '#7e22ce' },
        sev: {
          critical: '#f43f5e', high: '#fb923c', medium: '#facc15',
          low: '#38bdf8', info: '#94a3b8',
        },
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'Consolas', 'monospace'],
      },
      boxShadow: {
        glow: '0 0 24px -6px rgba(168, 85, 247, 0.45)',
        card: '0 4px 24px -8px rgba(0,0,0,0.5)',
      },
      animation: { 'pulse-slow': 'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite' },
    },
  },
  plugins: [],
}
