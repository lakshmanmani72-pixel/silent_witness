import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
        changeOrigin: true,
        configure: (proxy, _options) => {
          proxy.on('error', (err, _req, _res) => {
            // Gracefully ignore normal client disconnects, socket aborts, and resets
            if (err.code !== 'ECONNABORTED' && err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
              console.warn('[Vite Proxy WS Error]:', err.message);
            }
          });
          proxy.on('proxyReqWs', (proxyReq, _req, socket) => {
            socket.on('error', (err) => {
              if (err.code !== 'ECONNABORTED' && err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
                console.warn('[Vite WS Socket Error]:', err.message);
              }
            });
            proxyReq.on('error', (err) => {
              if (err.code !== 'ECONNABORTED' && err.code !== 'ECONNRESET' && err.code !== 'EPIPE') {
                console.warn('[Vite WS Req Error]:', err.message);
              }
            });
          });
        },
      }
    }
  }
})
