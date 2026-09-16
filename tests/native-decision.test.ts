import { chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { checkNative, getContext, modelNative, newSolver, type Z3, type Z3Solver } from '../src/z3.js';

/**
 * The native decision procedure must fail loudly, never quietly.
 *
 * Every proof in this repo is an expected `unsat`, so a decision that answers "unsat" when z3 did not
 * actually run — a timeout, an out-of-memory kill, a malformed query, a missing or wrong binary —
 * would pass every check in the suite without running any of them. These tests drive both entry points
 * with stub binaries that misbehave in each of those ways and require an exception.
 */
let z3: Z3;
let dir: string;
beforeAll(async () => {
  z3 = await getContext();
  dir = mkdtempSync(join(tmpdir(), 'paryon-z3-stub-'));
});

const original = process.env['Z3_BIN'];
afterEach(() => {
  if (original === undefined) delete process.env['Z3_BIN'];
  else process.env['Z3_BIN'] = original;
});

/** Install a stub "z3" that prints `output` and exits with `code`. */
function stub(name: string, output: string, code = 0): void {
  const path = join(dir, name);
  writeFileSync(path, `#!/bin/sh\ncat <<'STUB_OUTPUT'\n${output}\nSTUB_OUTPUT\nexit ${code}\n`);
  chmodSync(path, 0o755);
  process.env['Z3_BIN'] = path;
}

/** A trivially satisfiable query, so any verdict the stub gives is the stub's doing. */
function trivialSolver(): Z3Solver {
  const solver = newSolver(z3);
  solver.add(z3.Int.const('x').eq(1));
  return solver;
}

const decisions: [string, (s: Z3Solver, label: string) => Promise<unknown>][] = [
  ['checkNative', checkNative],
  ['modelNative', modelNative],
];

describe.each(decisions)('%s rejects anything that is not a verdict', (name, decide) => {
  it('a binary that exits 0 printing nothing', async () => {
    stub(`${name}-silent`, '');
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a binary that exits non-zero printing nothing', async () => {
    stub(`${name}-fail`, '', 1);
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a binary that reports an error instead of a verdict', async () => {
    stub(`${name}-error`, '(error "line 1 column 10: unknown constant")\n');
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a binary that prints a verdict-shaped word that is not a verdict', async () => {
    stub(`${name}-junk`, 'satisfiable\n');
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a `sat` that came with a failed exit (a truncated model is not a decision)', async () => {
    stub(`${name}-partial`, 'sat\n(\n  (define-fun x () Int 1)\n', 1);
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a binary killed mid-answer', async () => {
    // What an out-of-memory kill looks like from here: a signal exit and no usable output.
    stub(`${name}-killed`, '', 137);
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });

  it('a wrong binary that happens to succeed', async () => {
    // Z3_BIN pointing at something that is not z3 at all (the reviewer's /bin/true probe).
    process.env['Z3_BIN'] = '/bin/true';
    await expect(decide(trivialSolver(), 'stub')).rejects.toThrow();
  });
});

describe('the verdicts that are accepted', () => {
  it('sat, with the model parsed', async () => {
    stub('ok-sat', 'sat\n(\n  (define-fun x () Int 1)\n  (define-fun b () Bool true)\n)\n');
    const result = await modelNative(trivialSolver(), 'stub');
    expect(result.verdict).toBe('sat');
    expect(result.verdict === 'sat' && result.model.get('x')).toBe('1');
    expect(result.verdict === 'sat' && result.model.get('b')).toBe('true');
  });

  it('unsat, even though z3 exits non-zero on the (get-model) that follows it', async () => {
    stub('ok-unsat', 'unsat\n(error "line 9 column 10: model is not available")\n', 1);
    expect((await modelNative(trivialSolver(), 'stub')).verdict).toBe('unsat');
    expect(await checkNative(trivialSolver(), 'stub')).toBe('unsat');
  });

  it('the real z3 decides the trivial query', async () => {
    expect(await checkNative(trivialSolver(), 'real')).toBe('sat');
    expect((await modelNative(trivialSolver(), 'real')).verdict).toBe('sat');
  });
});
