import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
// The site reads ../level-*/ results, snapshots, logs and docs at build time, so every number on the page is generated, never typed.
export default defineConfig({
  base: '/cyber-range-lab/',
  plugins: [react()],
  server: { fs: { allow: ['..'] } },
});
