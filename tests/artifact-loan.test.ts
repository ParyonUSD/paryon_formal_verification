import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability } from '../src/model.js';
import {
  CAT, LoanFunction, POLICY, SCRIPT, functionNftInput, loanInput, loanSidecarInput, pin,
} from '../src/covenants/common.js';
import { buildFromArtifact } from '../src/script/fromArtifact.js';
import { seedCategory, seedScript } from '../src/script/interpreter.js';
import { getContext, type Z3 } from '../src/z3.js';
import { priceContract } from './partners.js';
import { expectArtifactSafe } from './assertions.js';

const fns = paryonArtifacts.loanContractFunctions;
const sp = paryonArtifacts.stabilityPool;

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * The non-redemption loan functions, with output pins derived from artifact bytecode. The
 * redemption functions live in artifact-redemption.test.ts and the stability-pool functions
 * (incl. the full `liquidate`) in artifact-pool.test.ts. PriceContract.sharePrice is the only
 * remaining hand-modelled partner here (it is multi-function — selector support already exists,
 * deriving it is a small follow-up).
 */
describe('loan functions — output pins from artifact bytecode', () => {
  it('changeInterest (08)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: fns.artifactFunctionChangeInterest, activeIndex: 2 },
    ], {
      nInputs: 6, nOutputs: 6, policy: POLICY.changeInterest, designatedInputs: [0],
      setup: (z3, s, tx) => {
        loanInput(s, tx.inputs[0]!);
        loanSidecarInput(s, tx.inputs[1]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[2]!, SCRIPT.FN_CHANGE_INTEREST, LoanFunction.CHANGE_INTEREST);
        pin(s, tx.inputs[3]!, { category: CAT.LOANKEY });
        s.add(tx.inputs[0]!.category.eq(CAT.PARYON));
      },
    }));
  });

  it('manage (02) — close + non-close', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: fns.artifactFunctionManage, activeIndex: 3 },
      priceContract(0),
    ], {
      nInputs: 8, nOutputs: 9, policy: POLICY.manage, designatedInputs: [0, 1],
      setup: (z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        loanInput(s, tx.inputs[1]!);
        loanSidecarInput(s, tx.inputs[2]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[3]!, SCRIPT.FN_MANAGE, LoanFunction.MANAGE_LOAN);
        pin(s, tx.inputs[4]!, { category: CAT.LOANKEY, capability: Capability.MINTING });
        s.add(tx.inputs[1]!.category.eq(CAT.PARYON));
      },
    }));
  });

  it('payInterest (07) + Collector.collect', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: fns.artifactFunctionPayInterest, activeIndex: 3, seeds: [seedCategory(CAT.POOL)] },
      // Collector at input 4, collect = abi 0; ctor: paryonTokenId, lockingBytecodeProtocolFee
      { artifact: sp.artifactCollector, activeIndex: 4, abiIndex: 0, seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.PROTOCOL_FEE)] },
      priceContract(0),
    ], {
      nInputs: 6, nOutputs: 6, policy: POLICY.payInterest, designatedInputs: [0, 1, 4],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        loanInput(s, tx.inputs[1]!);
        loanSidecarInput(s, tx.inputs[2]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[3]!, SCRIPT.FN_PAY_INTEREST, LoanFunction.PAY_INTEREST);
        pin(s, tx.inputs[4]!, { category: CAT.POOL, capability: Capability.MUTABLE, script: SCRIPT.COLLECTOR });
        s.add(tx.inputs[1]!.category.eq(CAT.PARYON));
      },
    }));
  });
});
