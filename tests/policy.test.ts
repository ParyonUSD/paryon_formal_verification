import { beforeAll, describe, expect, it } from 'vitest';
import { compose, type Covenant } from './covenant.js';
import { addConsensusRules } from '../src/consensus.js';
import { Capability, Script, declareTx } from '../src/model.js';
import { leakWitness, preservationWitness } from '../src/policy.js';
import { getContext, newSolver, type Z3, type Z3Solver } from '../src/z3.js';

const PARYON = 1;
const LOAN_SCRIPT = Script.FIRST_COVENANT; // id 2

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * Two toy "loan" covenants over the same shape:
 *  - safeLoan recreates the spent mutable loan NFT back to the loan script.
 *  - leakyLoan omits that output check (the classic missing-output bug).
 * Both spend a mutable PARYON loan NFT at input 0.
 */
function setup(z3: Z3, nOut: number, withSecondInput = false) {
  const s = newSolver(z3);
  const tx = declareTx(z3, 2, nOut);
  addConsensusRules(z3, s, tx, [PARYON]);
  // Input 0: the loan, a mutable PARYON NFT controlled by the loan covenant.
  s.add(tx.inputs[0]!.present, tx.inputs[0]!.category.eq(PARYON), tx.inputs[0]!.capability.eq(Capability.MUTABLE), tx.inputs[0]!.script.eq(LOAN_SCRIPT));
  if (!withSecondInput) s.add(z3.Not(tx.inputs[1]!.present));
  return { s, tx };
}

const safeLoan: Covenant = {
  name: 'safeLoan',
  constrain(z3, s, tx) {
    // Recreate the loan mutable NFT at output 0, pinned to the loan script.
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MUTABLE), tx.outputs[0]!.script.eq(LOAN_SCRIPT));
  },
};

describe('capability-leak policy', () => {
  const policy = {
    internalAuthorityCategories: [PARYON],
    ownership: [{ category: PARYON, capability: Capability.MUTABLE, scripts: [LOAN_SCRIPT] }],
  };

  it('safe covenant: the mutable loan NFT cannot leak (unsat)', async () => {
    const { s, tx } = setup(z3, 3);
    compose(z3, s, tx, [safeLoan]);
    s.add(leakWitness(z3, tx, policy));
    expect(await s.check()).toBe('unsat');
  });

  it('leaky covenant: with no output pinning, the NFT can reach an attacker (sat)', async () => {
    const { s, tx } = setup(z3, 3);
    // No covenant constraints on outputs at all -> the single mutable slot is free.
    s.add(leakWitness(z3, tx, policy));
    expect(await s.check()).toBe('sat');
  });

  it('moving the loan NFT to a covenant that does not own it breaks the invariant (sat)', async () => {
    const { s, tx } = setup(z3, 3);
    // Recreated faithfully, but on another system covenant: not an attacker output, yet the next
    // transaction's inductive hypothesis would be false, so the witness must fire.
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MUTABLE), tx.outputs[0]!.script.eq(LOAN_SCRIPT + 1));
    s.add(leakWitness(z3, tx, policy));
    expect(await s.check()).toBe('sat');
  });

  it('preservation: a spent function NFT that is not recreated in place is caught (sat), recreated is fine (unsat)', async () => {
    const FN_SCRIPT = LOAN_SCRIPT + 1;
    const withRules = { ...policy, preserve: [{ category: PARYON, scripts: [FN_SCRIPT] }] };
    const fnInput = (s: Z3Solver, tx: ReturnType<typeof declareTx>) =>
      s.add(tx.inputs[1]!.present, tx.inputs[1]!.category.eq(PARYON), tx.inputs[1]!.capability.eq(Capability.IMMUTABLE), tx.inputs[1]!.script.eq(FN_SCRIPT), tx.inputs[1]!.commitment.eq(2));
    // Not recreated: only the loan output is pinned.
    let { s, tx } = setup(z3, 3, true);
    fnInput(s, tx);
    compose(z3, s, tx, [safeLoan]);
    s.add(preservationWitness(z3, tx, withRules));
    expect(await s.check()).toBe('sat');
    // Recreated in place with the same commitment.
    ({ s, tx } = setup(z3, 3, true));
    fnInput(s, tx);
    compose(z3, s, tx, [safeLoan]);
    s.add(tx.outputs[1]!.present, tx.outputs[1]!.category.eq(PARYON), tx.outputs[1]!.capability.eq(Capability.IMMUTABLE), tx.outputs[1]!.script.eq(FN_SCRIPT), tx.outputs[1]!.commitment.eq(2));
    s.add(preservationWitness(z3, tx, withRules));
    expect(await s.check()).toBe('unsat');
  });

  it('burning the loan NFT to OP_RETURN is also leak-free (unsat)', async () => {
    const { s, tx } = setup(z3, 3);
    // Send the mutable NFT to a provably-unspendable burn instead of recreating.
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MUTABLE), tx.outputs[0]!.script.eq(Script.BURN));
    s.add(leakWitness(z3, tx, policy));
    expect(await s.check()).toBe('unsat');
  });
});
