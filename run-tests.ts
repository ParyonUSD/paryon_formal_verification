// Runs each test file in its OWN vitest process.
//
// Why this exists (it is load-bearing, not incidental): z3-solver allocates a large
// WebAssembly.Memory per Z3 init and NEVER frees it, and a Z3 Context accumulates AST/solver state
// as it is reused. Within a single process this is unrecoverable, so any "all files in one process"
// arrangement degrades and eventually times out:
//   - reusing one fork across files re-inits Z3 per file -> wasm instances pile up;
//   - sharing one Z3 context across all tests -> the context bloats and later solves crawl;
//   - many parallel forks -> concurrent wasm instances exhaust memory.
// A fresh process per file reclaims everything on exit (and avoids the wasm worker's unclean
// teardown, which otherwise makes vitest exit non-zero even when all tests pass). Each file then runs
// at isolation speed. Use `pnpm test:watch` while iterating on a single file.
import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const files = readdirSync('tests')
  .filter((entry) => entry.endsWith('.test.ts'))
  .sort()
  .map((entry) => `tests/${entry}`);

let failed = false;
for (const file of files) {
  console.log(`\n=== ${file} ===`);
  const result = spawnSync('pnpm', ['exec', 'vitest', 'run', file], { stdio: 'inherit', shell: true });
  if (result.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
