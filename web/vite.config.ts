import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // GenLayerJS is loaded only when the registry boundary performs a live
    // read or write. Its optional wallet chunk is intentionally separate.
    chunkSizeWarningLimit: 600,
  },
  server: {
    fs: {
      allow: ['..'],
    },
    proxy: {
      '/api': 'http://127.0.0.1:8765',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
  },
})
