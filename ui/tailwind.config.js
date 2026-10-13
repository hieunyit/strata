/** @type {import('tailwindcss').Config} */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        paper: v('paper'),
        surface: v('surface'),
        sunken: v('sunken'),
        line: v('line'),
        ink: v('ink'),
        muted: v('muted'),
        faint: v('faint'),
        accent: v('accent'),
        'accent-ink': v('accent-ink'),
        rail: v('rail'),
        'rail-ink': v('rail-ink'),
        'rail-hover': v('rail-hover'),
        block: v('block'),
        shadow: v('shadow'),
        other: v('other'),
        ok: v('ok'),
      },
    },
  },
  plugins: [],
};
