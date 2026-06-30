import { beforeAll, describe, expect, it } from 'vitest';
import { addConsensusRules } from '../src/consensus.js';
import { Capability, NO_CATEGORY, Script, declareTx } from '../src/model.js';
import { getContext, type Z3 } from '../src/z3.js';

const PARYON = 1; // a single category id under test

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

describe('consensus base', () => {
  it('is NOT vacuous: a minimal 1-in/1-out BCH transaction is sat', async () => {
    const s = new z3.Solver();
    const tx = declareTx(z3, 2, 2);
    addConsensusRules(z3, s, tx, [PARYON]);

    s.add(tx.inputs[0]!.present, tx.inputs[0]!.value.eq(10_000), tx.inputs[0]!.category.eq(NO_CATEGORY));
    s.add(z3.Not(tx.inputs[1]!.present));
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(NO_CATEGORY));
    s.add(z3.Not(tx.outputs[1]!.present));

    expect(await s.check()).toBe('sat');
  });

  it('cannot create a minting NFT without a minting input', async () => {
    const s = new z3.Solver();
    const tx = declareTx(z3, 2, 2);
    addConsensusRules(z3, s, tx, [PARYON]);

    // Input carries only fungible PARYON (no minting NFT anywhere).
    s.add(tx.inputs[0]!.present, tx.inputs[0]!.category.eq(PARYON), tx.inputs[0]!.fts.eq(1000), tx.inputs[0]!.capability.eq(Capability.NONE));
    s.add(z3.Not(tx.inputs[1]!.present));
    // Try to produce a minting PARYON NFT in an output.
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MINTING));

    expect(await s.check()).toBe('unsat');
  });

  it('THE FIX: cannot create more mutable NFTs than there were mutable inputs', async () => {
    const s = new z3.Solver();
    const tx = declareTx(z3, 2, 3);
    addConsensusRules(z3, s, tx, [PARYON]);

    // Exactly one mutable PARYON input, no minting input.
    s.add(tx.inputs[0]!.present, tx.inputs[0]!.category.eq(PARYON), tx.inputs[0]!.capability.eq(Capability.MUTABLE));
    s.add(z3.Not(tx.inputs[1]!.present));
    // Demand TWO mutable PARYON outputs (the duplication a missing tally allows).
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MUTABLE));
    s.add(tx.outputs[1]!.present, tx.outputs[1]!.category.eq(PARYON), tx.outputs[1]!.capability.eq(Capability.MUTABLE));

    expect(await s.check()).toBe('unsat');
  });

  it('THE FIX: cannot fabricate a mutable NFT from a category with no NFT inputs', async () => {
    const s = new z3.Solver();
    const tx = declareTx(z3, 2, 2);
    addConsensusRules(z3, s, tx, [PARYON]);

    // Only fungible PARYON in, no PARYON NFT input at all.
    s.add(tx.inputs[0]!.present, tx.inputs[0]!.category.eq(PARYON), tx.inputs[0]!.fts.eq(1000), tx.inputs[0]!.capability.eq(Capability.NONE));
    s.add(z3.Not(tx.inputs[1]!.present));
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MUTABLE));

    expect(await s.check()).toBe('unsat');
  });

  it('a minting input DOES allow producing extra NFTs (sanity: tally is not over-strict)', async () => {
    const s = new z3.Solver();
    const tx = declareTx(z3, 2, 3);
    addConsensusRules(z3, s, tx, [PARYON]);

    // One minting PARYON input.
    s.add(tx.inputs[0]!.present, tx.inputs[0]!.category.eq(PARYON), tx.inputs[0]!.capability.eq(Capability.MINTING));
    s.add(z3.Not(tx.inputs[1]!.present));
    // Recreate the minting NFT and also mint a fresh mutable one.
    s.add(tx.outputs[0]!.present, tx.outputs[0]!.category.eq(PARYON), tx.outputs[0]!.capability.eq(Capability.MINTING), tx.outputs[0]!.script.eq(Script.FIRST_COVENANT));
    s.add(tx.outputs[1]!.present, tx.outputs[1]!.category.eq(PARYON), tx.outputs[1]!.capability.eq(Capability.MUTABLE), tx.outputs[1]!.script.eq(Script.FIRST_COVENANT));

    expect(await s.check()).toBe('sat');
  });
});
