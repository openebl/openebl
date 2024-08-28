import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'
import path from 'path'
import UnoCSS from 'unocss/vite' // unocss
import { presetAttributify, presetIcons, presetUno } from 'unocss' // unocss presets

// https://vitejs.dev/config/
export default defineConfig({
  build: {
    minify: true,
    rollupOptions: {
      output: {
        entryFileNames: `assets/${process.env.npm_package_name}-${process.env.npm_package_version}.js`,
        chunkFileNames: `assets/${process.env.npm_package_name}-${process.env.npm_package_version}.js`,
        assetFileNames: `assets/${process.env.npm_package_name}-${process.env.npm_package_version}.[ext]`,
      },
    },
  },
  plugins: [
    svelte(),
    UnoCSS({
      presets: [presetUno(), presetIcons(), presetAttributify()],
    }),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@components': path.resolve(__dirname, './src/components'),
      '@stores': path.resolve(__dirname, './src/stores'),
      '@views': path.resolve(__dirname, './src/views'),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 9000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8081',
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, '/api/'),
      },
    },
  },
})
