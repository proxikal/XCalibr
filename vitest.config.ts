import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    setupFiles: ['src/setupTests.ts'],
    clearMocks: true,
    restoreMocks: true,
    globals: true
  }
});
