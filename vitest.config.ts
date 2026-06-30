import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // `pnpm test` runs each file in its own process via run-tests.mjs (see that file for why z3-solver
    // forces this). This config governs single-file runs (`pnpm test:watch`, or `vitest run <file>`):
    // forks so the wasm worker dies with the process, and a generous timeout for the heavier solves.
    pool: 'forks',
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
