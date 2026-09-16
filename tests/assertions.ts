import { expect } from 'vitest';
import type { SymbolicTx } from '../src/model.js';
import { leakWitness, preservationWitness, preservedInputsOnlyAt, type LeakPolicy } from '../src/policy.js';
import type { Z3, Z3Solver } from '../src/z3.js';

/**
 * `check()` with `'unknown'` turned into a hard failure. Z3 answers `'unknown'` at resource limits; a
 * witness query that reads it as "not sat" would silently pass a control that should have found a leak.
 */
export async function decide(s: Z3Solver): Promise<'sat' | 'unsat'> {
  const result = await s.check();
  if (result === 'unknown') throw new Error(`Z3 returned unknown: ${s.reasonUnknown()}`);
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
export async function expectArtifactSafe(
  z3: Z3,
  built: { tx: SymbolicTx; policy: LeakPolicy; solvers: Z3Solver[]; governedInputs: number[] },
): Promise<void> {
  expect(built.solvers.length).toBeGreaterThan(0);

  let anySat = false;
  for (const s of built.solvers) {
    if ((await decide(s)) === 'sat') anySat = true;
  }
  expect(anySat).toBe(true); // non-vacuity

  for (const s of built.solvers) {
    s.push();
    s.add(leakWitness(z3, built.tx, built.policy));
    expect(await decide(s)).toBe('unsat'); // leak-free on every path
    s.pop();
    if (built.policy.preserve?.length) {
      s.push();
      s.add(preservedInputsOnlyAt(z3, built.tx, built.policy, built.governedInputs));
      s.add(preservationWitness(z3, built.tx, built.policy));
      expect(await decide(s), 'a function NFT is not recreated').toBe('unsat');
      s.pop();
    }
  }
}

/** Assert at least one path of an artifact-derived build CAN leak (composition-matters control). */
export async function expectArtifactLeaks(
  z3: Z3,
  built: { tx: SymbolicTx; policy: LeakPolicy; solvers: Z3Solver[] },
): Promise<void> {
  // One leaking path is enough; stop on the first (no need to solve the remaining paths).
  for (const s of built.solvers) {
    s.add(leakWitness(z3, built.tx, built.policy));
    if ((await decide(s)) === 'sat') return;
  }
  expect.fail('expected at least one path to leak, but none did');
}
