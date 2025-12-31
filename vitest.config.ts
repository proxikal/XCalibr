import { defineConfig } from 'vitest/config';

export default defineConfig({
  cacheDir: 'node_modules/.vite',
  test: {
    environment: 'jsdom',
    setupFiles: ['src/setupTests.ts'],
    clearMocks: true,
    restoreMocks: true,
    globals: true,
    // Performance optimizations - threads pool is faster
    pool: 'threads',
    poolOptions: {
      threads: {
        singleThread: false,
        isolate: true,
        maxThreads: 10,
        minThreads: 2
      }
    },
    // Faster test isolation - disable isolate for faster runs with threads
    isolate: false,
    // Reduce unnecessary reruns
    passWithNoTests: true,
    // Optimize file watching
    forceRerunTriggers: ['**/vitest.config.ts', '**/setupTests.ts'],
    // Optimize module resolution
    deps: {
      optimizer: {
        web: {
          enabled: true
        }
      }
    },
    // Disable coverage for faster runs (enable explicitly when needed)
    coverage: {
      enabled: false
    },
    // Optimize test file discovery
    include: ['src/**/*.test.{ts,tsx}'],
    exclude: ['node_modules', 'dist', '.wxt']
  }
});
