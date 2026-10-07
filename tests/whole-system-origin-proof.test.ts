import { beforeAll, describe, expect, it } from 'vitest';
import { CAT, TALLIED_CATEGORIES, SCRIPT, SINGLE_USE_POLICY } from '../src/covenants/common.js';
import { SYSTEM_REGISTRY, unmodelledCovenantScripts } from '../src/covenants/registry.js';
import { singleUseWitness } from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import { getContext, type Bool, type Z3 } from '../src/z3.js';
import { CAPACITY, decideWhole } from './wholeSystemReport.js';

/**
 * The loanKey origin proof must be used once (the `singleUse` clause of `SINGLE_USE_POLICY`).
 *
 * `LoanKeyOriginEnforcer` accepts the factory's immutable NFT one outpoint on as proof that the factory
 * created its loanKey category, checking category and position only. No capability moves when a proof
 * outlives its borrow, so the leak witness is blind to it; this clause is what sees it.
 *
 * The published `borrow` pins outputs 0 and 2 to 6, the price contract's `sharePrice` recreates itself
 * at output 1, and any non-paryon token may go to the free outputs 7 to 9, so the clause does not hold.
 * Of the covenants every borrow runs, only the price contract's code can change, so the second case
 * states the rule a price contract would have to enforce for the clause to hold. That rule is written
 * into the query here, not compiled from bytecode: it shows the rule is enough alongside the published
 * `sharePrice` (which keeps output 1), not that any price contract enforces it. And `migrateContract` is
 * excluded from the registry, so even a price contract that does enforce it only closes the clause for
 * as long as the oracle migration key keeps the price threads on that code.
 */
let z3: Z3;
let built: BuiltWholeSystem;
beforeAll(async () => {
  z3 = await getContext();
  built = buildWholeSystem(z3, {
    ...CAPACITY,
    categories: TALLIED_CATEGORIES,
    policy: SINGLE_USE_POLICY,
    registry: SYSTEM_REGISTRY,
    unmodelledScripts: unmodelledCovenantScripts(SYSTEM_REGISTRY),
  });
});

/** In a transaction with the Borrowing contract at input 0, no output from 7 on carries the factory category. */
function borrowFreeOutputsCarryNoProof(): Bool {
  const borrowing = built.tx.inputs[0]!;
  return z3.Implies(
    z3.And(borrowing.present, borrowing.script.eq(SCRIPT.BORROWING)),
    z3.And(...built.tx.outputs.slice(7).map((out) =>
      z3.Or(z3.Not(out.present), z3.Not(out.category.eq(CAT.LOANKEY_FACTORY))))),
  );
}

describe('loanKey origin proofs are single-use', () => {
  it('the published contracts: a borrow can keep its origin proof', async () => {
    const { verdict, report } = await decideWhole(
      built, 'origin-proof-kept', [singleUseWitness(z3, built.tx, SINGLE_USE_POLICY)],
    );
    console.log(report); // the counterexample is the transaction that keeps the proof
    expect(verdict).toBe('sat');
    // The only transaction that spends a proof is a borrow: the proof runs `attach` next to the
    // enforcer, which requires the Borrowing contract at input 0
    expect(report).toContain('Borrowing.borrow');
    expect(report).toContain('LoanKeyOriginEnforcer.enforce');
  });

  it('a borrow whose free outputs carry no factory token burns the proof, and the positive control fires', async () => {
    const extra = [singleUseWitness(z3, built.tx, SINGLE_USE_POLICY), borrowFreeOutputsCarryNoProof()];
    const { verdict, report } = await decideWhole(built, 'origin-proof-guarded', extra);
    expect(verdict, report).toBe('unsat');
    const control = await decideWhole(built, 'control-origin-proof-guarded', extra, { withoutCovenants: true });
    expect(control.verdict).toBe('sat');
  });
});
