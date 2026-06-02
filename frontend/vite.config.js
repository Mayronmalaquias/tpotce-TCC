import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://192.168.56.101:8000',
      '/ws':  { target: 'ws://192.168.56.101:8000', ws: true },
    },
  },
})
