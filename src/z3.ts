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

// Memoise on globalThis (not a module local): vitest may re-evaluate this module
// once per test file even in a single fork, and each fresh Z3 instance holds a
// large WebAssembly.Memory. Sharing one promise across re-evaluations keeps the
// whole run to a single Z3 instance.
const GLOBAL_KEY = '__z3_solver_ts_context__';
type GlobalWithZ3 = typeof globalThis & { [GLOBAL_KEY]?: Promise<Z3> };

/** Initialise Z3 once and reuse the context (its wasm build is expensive to boot). */
export async function getContext(): Promise<Z3> {
  const g = globalThis as GlobalWithZ3;
  g[GLOBAL_KEY] ??= init().then(({ Context }) => Context('main'));
  return g[GLOBAL_KEY];
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
