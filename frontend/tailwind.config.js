/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        surface: {
          900: '#0c0e12',
          800: '#13161c',
          700: '#272b34',
          600: '#414753',
        },
      },
    },
  },
  plugins: [],
}
