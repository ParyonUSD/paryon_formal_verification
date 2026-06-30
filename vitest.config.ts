import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // z3-solver boots a large wasm instance per test file; running files in
    // parallel (or all in one shared process) keeps several instances alive at
    // once and exhausts memory. Run files sequentially in isolated forks so at
    // most one Z3 instance is live at a time.
    pool: 'forks',
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
