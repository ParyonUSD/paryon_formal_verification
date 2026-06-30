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

/** Initialise Z3 once per process and reuse the context (its wasm build is expensive to boot). */
export async function getContext(): Promise<Z3> {
  const p = process as ProcessWithZ3;
  p[KEY] ??= init().then(({ Context }) => Context('main'));
  return p[KEY];
}

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
