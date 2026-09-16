import { execFile } from 'node:child_process';
import { accessSync, constants, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { init, type Context } from 'z3-solver';

/**
 * The Z3 context, pinned to a single name. Everything in this project shares
 * one context name so expressions are interoperable.
 */
export type Z3 = Context<'main'>;

/** A Z3 arithmetic (Int) expression in our context. */
export type Num = ReturnType<Z3['Int']['const']>;
/** A Z3 boolean expression in our context. */
export type Bool = ReturnType<Z3['Bool']['const']>;
/** A Z3 solver instance in our context. */
export type Z3Solver = InstanceType<Z3['Solver']>;

// Memoise on `process`, not a module local or globalThis. z3-solver's init() builds a fresh
// WebAssembly.Memory that is never freed, so Z3 must boot at most once per process. vitest resets the
// module registry / globalThis between test files, so those memos would not survive isolation and Z3
// would re-init (and leak wasm) per file; `process` does survive it. run-tests.mjs gives each file its
// own process, so this boots Z3 once per file and reclaims it when the file's process exits.
const KEY = '__z3_solver_ts_context__';
type ProcessWithZ3 = NodeJS.Process & { [KEY]?: Promise<Z3> };

/**
 * Initialise Z3 once per process and reuse the context (its wasm build is expensive to boot).
 *
 * `enable_concurrent_dec_ref` is essential: z3-solver's expression wrappers drop their Z3 reference
 * from a garbage-collection finalizer on the main thread, while `check()` runs in a worker thread, and
 * the Z3 API is not thread-safe. Without it, long checks under allocation pressure showed corrupted
 * ASTs ("sort is null"), heap corruption and out-of-bounds aborts. With it, Z3 queues the drops and
 * applies them at a safe point.
 */
export async function getContext(): Promise<Z3> {
  const p = process as ProcessWithZ3;
  p[KEY] ??= init().then(({ Context, Z3: lowLevel }) => {
    const ctx = Context('main');
    lowLevel.enable_concurrent_dec_ref(ctx.ptr);
    return ctx;
  });
  return p[KEY];
}

/**
 * A solver for this project's problems. Everything the model emits is linear integer arithmetic
 * over booleans (finite-domain ids, counts, If-sums), so the solver is pinned to QF_LIA. Z3's default
 * auto-configuration was observed to stall for minutes on the manage build once other builds had
 * run in the same context, while QF_LIA decides every query in well under a second.
 */
export function newSolver(z3: Z3): Z3Solver {
  const solver = new z3.Solver('QF_LIA');
  solver.set('arith.solver', 2); // the classic simplex: ~25% faster than the default on these problems
  return solver;
}

/**
 * Decide a solver's assertions in a *native* z3 process, from SMT-LIB text.
 *
 * The wasm bindings are kept for building expressions and for the small oracle/unit queries, but the
 * artifact proofs do not run in them: z3-solver drops references from a garbage-collection finalizer
 * while `check()` runs in its worker thread, and under the larger builds this produced hangs, heap
 * corruption ("supplied sort is null") and out-of-memory aborts that depended on process history.
 * A native process per query is deterministic, isolated, ignores no timeout, and leaves the `.smt2`
 * file as an audit artifact any SMT solver can re-check (`Z3_SMT_DIR` chooses where; default a temp
 * directory per process).
 */
export async function checkNative(solver: Z3Solver, label: string): Promise<'sat' | 'unsat' | 'unknown'> {
  const file = writeQuery(solver, label, '(check-sat)\n');
  const { stdout } = await runZ3(file);
  return readVerdict(stdout, file);
}

/**
 * The verdict of a native run: the FIRST token of z3's output, and nothing else will do.
 *
 * A decision procedure that answers "unsat" when it did not run is worse than useless: every proof in
 * this repo is an expected `unsat`, so a timeout, an out-of-memory kill, a malformed `.smt2` or a
 * missing binary would silently pass every check. Anything that is not exactly `sat`, `unsat` or
 * `unknown` therefore throws, with the query file named so the failure can be reproduced by hand.
 */
function readVerdict(stdout: string, file: string): 'sat' | 'unsat' | 'unknown' {
  const first = stdout.trimStart().split(/\s+/, 1)[0];
  if (first === 'sat' || first === 'unsat' || first === 'unknown') return first;
  throw new Error(`z3 gave no verdict for ${file}: ${stdout.slice(0, 500) || '<no output>'}`);
}

/**
 * Run z3 on a query file. A non-zero exit is only tolerated when stdout still carries a *negative*
 * verdict: `(get-model)` after an unsat `(check-sat)` is an error ("model is not available") that z3
 * reports with exit code 1, and that run decided the query. A `sat` that also failed is never
 * tolerated — its model may be truncated — and a killed process (the timeout) never is.
 */
async function runZ3(file: string): Promise<{ stdout: string }> {
  try {
    return await execFileAsync(z3Binary(), ['-smt2', file], { timeout: NATIVE_TIMEOUT_MS, maxBuffer: 1 << 26 });
  } catch (e) {
    const err = e as NodeJS.ErrnoException & { stdout?: string; killed?: boolean };
    if (err.killed === true || typeof err.stdout !== 'string') throw e;
    const first = err.stdout.trimStart().split(/\s+/, 1)[0];
    if (first === 'unsat' || first === 'unknown') return { stdout: err.stdout };
    throw e;
  }
}
/**
 * Decide a solver's assertions natively *and*, when satisfiable, bring back the assignment.
 *
 * A counterexample is only useful if it can be read: this returns the model as a flat
 * `constant name -> value` map (`Int` as a decimal string, `Bool` as `true`/`false`), which the
 * caller turns back into UTXO fields by name. Same isolation as {@link checkNative}.
 */
export async function modelNative(
  solver: Z3Solver, label: string,
): Promise<{ verdict: 'unsat' | 'unknown' } | { verdict: 'sat'; model: Map<string, string> }> {
  const file = writeQuery(solver, label, '(check-sat)\n(get-model)\n');
  const { stdout } = await runZ3(file);
  const verdict = readVerdict(stdout, file);
  if (verdict !== 'sat') return { verdict };
  return { verdict: 'sat', model: parseModel(stdout) };
}

/** Parse z3's `(define-fun name () Sort value)` model output into a name -> value map. */
function parseModel(text: string): Map<string, string> {
  const out = new Map<string, string>();
  const re = /\(define-fun\s+([^\s()]+)\s*\(\s*\)\s*(?:Int|Bool)\s+/g;
  for (let m = re.exec(text); m !== null; m = re.exec(text)) {
    let at = re.lastIndex, depth = 0;
    while (at < text.length) {
      const ch = text[at]!;
      if (ch === '(') depth++;
      else if (ch === ')') { if (depth === 0) break; depth--; }
      at++;
    }
    const raw = text.slice(re.lastIndex, at).trim();
    // Negative integers come back as `(- 5)`.
    out.set(m[1]!, /^\(\s*-\s*\d+\s*\)$/.test(raw) ? `-${raw.replace(/[^\d]/g, '')}` : raw);
  }
  return out;
}

function writeQuery(solver: Z3Solver, label: string, tail: string): string {
  const dir = process.env['Z3_SMT_DIR'] ?? join(tmpdir(), 'paryon-fv', String(process.pid));
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${++queryCounter}-${label.replace(/[^A-Za-z0-9_.-]+/g, '_')}.smt2`);
  writeFileSync(file, `(set-logic QF_LIA)\n${solver.toString()}\n${tail}`);
  return file;
}

const execFileAsync = promisify(execFile);
let queryCounter = 0;
/** Generous: a native query here takes milliseconds; anything longer is a bug to see, not to hide. */
const NATIVE_TIMEOUT_MS = 300_000;

/** The native z3 binary: `Z3_BIN`, else the project-local install, else `z3` on PATH. */
export function z3Binary(): string {
  const local = join(dirname(fileURLToPath(import.meta.url)), '..', '.tools', 'z3', 'bin', 'z3');
  for (const candidate of [process.env['Z3_BIN'], local]) {
    if (!candidate) continue;
    try { accessSync(candidate, constants.X_OK); return candidate; } catch { /* next */ }
  }
  return 'z3'; // PATH; a missing binary surfaces as ENOENT from execFile with the install hint below
}
export const Z3_INSTALL_HINT = 'no native z3 found: run scripts/install-z3.sh (or set Z3_BIN)';

/** Sum a list of Int expressions, returning 0 for the empty list. */
export function sum(z3: Z3, terms: Num[]): Num {
  return terms.reduce<Num>((acc, t) => acc.add(t), z3.Int.val(0));
}

/** Count how many of the given conditions hold (sum of 1-or-0). */
export function countIf(z3: Z3, conds: Bool[]): Num {
  return sum(
    z3,
    conds.map((c) => z3.If(c, z3.Int.val(1), z3.Int.val(0))),
  );
}

/** Logical OR over a list, returning `false` for the empty list. */
export function any(z3: Z3, conds: Bool[]): Bool {
  if (conds.length === 0) return z3.Bool.val(false);
  return z3.Or(...conds);
}
