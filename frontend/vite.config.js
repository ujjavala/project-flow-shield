import { defineConfig, transformWithOxc } from 'vite';
import react from '@vitejs/plugin-react';

const backendTarget = process.env.VITE_PROXY_TARGET || 'http://localhost:8000';
const jsxInJavaScript = {
  name: 'flowshield-js-as-jsx',
  enforce: 'pre',
  async transform(code, id) {
    if (!/\/src\/.*\.js$/.test(id)) return null;
    return transformWithOxc(code, id, { lang: 'jsx', jsx: { runtime: 'automatic' } });
  },
};

export default defineConfig({
  plugins: [jsxInJavaScript, react({ include: /\.[jt]sx?$/ })],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '^/(api|user|oauth2|bff|admin|dashboard|behavioral-analytics|health)(/|$)': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: '0.0.0.0',
    port: 3000,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: './src/setupTests.js',
    testTimeout: 10000,
    css: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json-summary', 'lcov'],
      include: ['src/**/*.{js,jsx}'],
      exclude: ['src/main.jsx', 'src/index.js', 'src/setupTests.js'],
      thresholds: {
        statements: 13,
        branches: 12,
        functions: 11,
        lines: 14,
        'src/services/bffService.js': {
          statements: 60,
          branches: 70,
          functions: 50,
          lines: 65,
        },
      },
    },
  },
});
