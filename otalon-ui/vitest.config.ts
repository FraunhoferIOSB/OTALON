import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'

export default defineConfig({
  plugins: [vue()],
  test: {
    environment: 'happy-dom',
    globals: true,
    setupFiles: ['./tests/setup.ts'],
    include: ['tests/**/*.test.ts'],
  },
  resolve: {
    alias: {
      '~': resolve(__dirname, './app'),
      '~~': resolve(__dirname, '.'),
      '#imports': resolve(__dirname, './tests/mocks/nuxt-imports.ts'),
      '#app': resolve(__dirname, './tests/mocks/nuxt-imports.ts'),
      '#shared': resolve(__dirname, './shared'),
    },
  },
})
