/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        brutal: {
          bg: '#F4F0EA',
          paper: '#FFFDF9',
          yellow: '#FFE600',
          cyan: '#00F0FF',
          lime: '#00E599',
          pink: '#FF3366',
          orange: '#FF8800',
          purple: '#A855F7',
          dark: '#121212',
          muted: '#E5E0D8'
        },
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
      boxShadow: {
        'brutal-sm': '2px 2px 0px 0px #000000',
        'brutal': '4px 4px 0px 0px #000000',
        'brutal-lg': '6px 6px 0px 0px #000000',
        'brutal-xl': '8px 8px 0px 0px #000000',
        'brutal-yellow': '4px 4px 0px 0px #FFE600',
        'brutal-cyan': '4px 4px 0px 0px #00F0FF',
        'brutal-pink': '4px 4px 0px 0px #FF3366',
      },
      borderWidth: {
        '3': '3px',
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'Courier New', 'monospace'],
        sans: ['Space Grotesk', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
        display: ['Space Grotesk', 'sans-serif']
      }
    },
  },
  plugins: [],
}
