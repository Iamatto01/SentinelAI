import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const backendTarget = env.VITE_BACKEND_TARGET || 'http://localhost:5000'
  const proxySecure = env.VITE_PROXY_SECURE !== 'false'

  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0',
      proxy: {
        '/api': {
          target: backendTarget,
          changeOrigin: true,
          secure: proxySecure,
          timeout: 30000,
          proxyTimeout: 30000,
        },
        '/socket.io': {
          target: backendTarget,
          ws: true,
          changeOrigin: true,
          secure: proxySecure,
          timeout: 30000,
          proxyTimeout: 30000,
        },
      },
    },
  }
})
