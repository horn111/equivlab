import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // GenLayerJS is isolated behind the post-analysis lazy boundary. Its
    // optional wallet chunk is ~547 kB minified / ~118 kB gzip.
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
