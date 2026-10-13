import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import vi from './locales/vi.json';
import en from './locales/en.json';
import { readPref, writePref } from '../lib/prefs';

// English by default; the choice made in the header is remembered.
const saved = readPref('lang');

i18n.use(initReactI18next).init({
  resources: {
    vi: { translation: vi },
    en: { translation: en },
  },
  lng: saved === 'vi' || saved === 'en' ? saved : 'en',
  fallbackLng: 'en',
  interpolation: {
    escapeValue: false,
  },
});

i18n.on('languageChanged', (lng) => {
  writePref('lang', lng);
  document.documentElement.lang = lng;
});

export default i18n;
