import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability } from '../src/model.js';
import { CAT, LOAN_CATEGORIES, LoanFunction, POLICY, SCRIPT, functionNftInput, loanInput, loanSidecarInput, pin } from '../src/covenants/common.js';
import { buildFromArtifact, type Artifact } from '../src/script/fromArtifact.js';
import { getContext, type Z3 } from '../src/z3.js';
import { priceContract } from './partners.js';
import { expectArtifactLeaks, expectArtifactSafe } from './assertions.js';
import manageBuggy from './fixtures/manageBuggy.js';

/**
 * Regression test against a REAL historical capability leak.
 *
 * An earlier `manage.cash` closed a loan (full repayment) without burning or recreating the loan's
 * mutable NFT (`paryonTokenId + 0x01`). On the close branch the loan is not recreated, so that
 * mutable NFT's single output slot was left free for an attacker to direct to their own UTXO, which
 * forges loan/price authority across the whole system. The fix added a `closeLoan` block that burns
 * it to an OP_RETURN. `fixtures/manageBuggy.ts` is the pre-fix contract, compiled with the project's
 * `cashc -S -L`. We confirm the current model UNSAT (safe) on the fixed artifact and SAT (leak) on
 * the buggy one, i.e. the repo would have caught this bug.
 */
const fixedManage = paryonArtifacts.loanContractFunctions.artifactFunctionManage;

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

function buildManageClose(z3: Z3, artifact: Artifact) {
  return buildFromArtifact(z3, [
    { artifact, activeIndex: 3 },
    priceContract(0),
  ], {
    nInputs: 8, nOutputs: 9, categories: LOAN_CATEGORIES, policy: POLICY.manage, designatedInputs: [0, 1],
    setup: (_z3, s, tx) => {
      pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
      loanInput(s, tx.inputs[1]!);
      loanSidecarInput(s, tx.inputs[2]!, CAT.LOANKEY);
      functionNftInput(s, tx.inputs[3]!, SCRIPT.FN_MANAGE, LoanFunction.MANAGE_LOAN);
      pin(s, tx.inputs[4]!, { category: CAT.LOANKEY, capability: Capability.MINTING });
      s.add(tx.inputs[1]!.category.eq(CAT.PARYON));
    },
  });
}

describe('historical leak: manage-close must burn the mutable loan NFT', () => {
  it('FIXED manage (burns the loan NFT): no leak (unsat)', async () => {
    await expectArtifactSafe(z3, buildManageClose(z3, fixedManage));
  });

  it('BUGGY pre-fix manage (no burn): the model CATCHES the leak (sat)', async () => {
    await expectArtifactLeaks(z3, buildManageClose(z3, manageBuggy as Artifact));
  });
});
