import { expect } from 'vitest';
import type { SymbolicTx } from '../src/model.js';
import type { BuiltArtifact } from '../src/script/fromArtifact.js';
import { leakWitness, preservationWitness, preservedInputsOnlyAt, type LeakPolicy } from '../src/policy.js';
import { checkNative, Z3_INSTALL_HINT, type Bool, type Z3, type Z3Solver } from '../src/z3.js';

/**
 * `check()` with `'unknown'` turned into a hard failure. Z3 answers `'unknown'` at resource limits; a
 * witness query that reads it as "not sat" would silently pass a control that should have found a leak.
 */
export async function decide(s: Z3Solver): Promise<'sat' | 'unsat'> {
  const result = await s.check();
  if (result === 'unknown') throw new Error(`Z3 returned unknown: ${s.reasonUnknown()}`);
  return result;
}

/** Decide an artifact query in a native z3 process (see `checkNative`); `unknown` is a hard failure. */
export async function decideNative(s: Z3Solver, label: string): Promise<'sat' | 'unsat'> {
  let result: 'sat' | 'unsat' | 'unknown';
  try {
    result = await checkNative(s, label);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    throw new Error(err.code === 'ENOENT' ? Z3_INSTALL_HINT : err.message);
  }
  if (result === 'unknown') throw new Error(`native z3 returned unknown for ${label}`);
  return result;
}

/** Assert the base transaction is satisfiable (the model is not vacuously over-constrained). */
export async function expectSat(s: Z3Solver): Promise<void> {
  expect(await decide(s)).toBe('sat');
}

/** Assert no privileged capability can leak: consensus + covenants + leak is UNSAT. */
export async function expectNoLeak(z3: Z3, s: Z3Solver, tx: SymbolicTx, policy: LeakPolicy): Promise<void> {
  s.add(leakWitness(z3, tx, policy));
  expect(await decide(s)).toBe('unsat');
}

/** Assert a leak IS reachable (used to show a missing-composition / missing-check artefact). */
export async function expectLeak(z3: Z3, s: Z3Solver, tx: SymbolicTx, policy: LeakPolicy): Promise<void> {
  s.add(leakWitness(z3, tx, policy));
  expect(await decide(s)).toBe('sat');
}

/**
 * Assert an artifact-derived build is safe: at least one path is realisable
 * (non-vacuous), EVERY path is leak-free, and (when the policy lists preservation
 * rules) every path recreates the function NFTs it spends.
 */
export async function expectArtifactSafe(z3: Z3, built: BuiltArtifact): Promise<void> {
  expect(built.paths.length).toBeGreaterThan(0);

  let anySat = false;
  for (let p = 0; p < built.paths.length; p++) {
    if ((await decideNative(built.solverFor(p), `path${p}-base`)) === 'sat') anySat = true;
  }
  expect(anySat).toBe(true); // non-vacuity

  // One expression per witness, shared across the path queries (allocation-light for z3-solver).
  const leak = leakWitness(z3, built.tx, built.policy);
  const restrict = preservedInputsOnlyAt(z3, built.tx, built.policy, built.governedInputs);
  const preserved = preservationWitness(z3, built.tx, built.policy);
  for (let p = 0; p < built.paths.length; p++) {
    const q = (extra: Bool[], label: string) => decideNative(built.solverFor(p, extra), `path${p}-${label}`);
    expect(await q([leak], 'leak')).toBe('unsat'); // leak-free on every path
    if (built.policy.preserve?.length) {
      expect(await q([restrict, preserved], 'preservation'), 'a function NFT is not recreated').toBe('unsat');
    }
  }
}

/** Assert at least one path of an artifact-derived build CAN leak (composition-matters control). */
export async function expectArtifactLeaks(z3: Z3, built: BuiltArtifact): Promise<void> {
  // One leaking path is enough; stop on the first (no need to solve the remaining paths).
  const leak = leakWitness(z3, built.tx, built.policy);
  for (let p = 0; p < built.paths.length; p++) {
    if ((await decideNative(built.solverFor(p, [leak]), `path${p}-leak`)) === 'sat') return;
  }
  expect.fail('expected at least one path to leak, but none did');
}
