/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#070A12',
          900: '#0B0F19',
          850: '#0E1424',
          800: '#131B2E',
          700: '#1E293B',
          600: '#334155'
        },
        cyan: {
          400: '#38BDF8',
          500: '#0EA5E9',
          600: '#0284C7'
        },
        emerald: {
          400: '#34D399',
          500: '#10B981'
        },
        crimson: {
          500: '#EF4444',
          600: '#DC2626'
        },
        amber: {
          500: '#F59E0B'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif']
      }
    },
  },
  plugins: [],
}
