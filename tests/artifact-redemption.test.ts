import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability, NO_CATEGORY } from '../src/model.js';
import {
  CAT, LoanFunction, POLICY, SCRIPT, functionNftInput, loanInput, loanSidecarInput, pin,
} from '../src/covenants/common.js';
import { buildFromArtifact, type CovenantSpec } from '../src/script/fromArtifact.js';
import { seedCategory, seedOpaque, seedScript } from '../src/script/interpreter.js';
import { getContext, type Z3 } from '../src/z3.js';
import { loanSidecar, priceContract } from './partners.js';
import { expectArtifactLeaks, expectArtifactSafe } from './assertions.js';

const fns = paryonArtifacts.loanContractFunctions;
const red = paryonArtifacts.redeemer;

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * The full redemption system, with BOTH the loan function and the redemption-system
 * partner covenants (Redeemer, Redemption finalize + swap) derived from artifact
 * bytecode. Only PriceContract.sharePrice and LoanTokenSidecar remain hand-modelled
 * (RedemptionSidecar.attach only checks input adjacency — no output pins, no
 * capability effect — so it is omitted).
 */
describe('redemption system — partners derived from artifact bytecode', () => {
  // --- startRedemption: loan fn + Redeemer.createRedemption (minting authority) ---
  function startRedemption(z3: Z3, withRedeemer: boolean) {
    const specs: CovenantSpec[] = [
      { artifact: fns.artifactFunctionStartRedemption, activeIndex: 3, seeds: [seedCategory(CAT.REDEEMER)] },
      priceContract(0),
      loanSidecar(2),
    ];
    if (withRedeemer) {
      specs.push({
        artifact: red.artifactRedeemer, activeIndex: 4,
        // constructor: paryonTokenId, redemptionLockingScript, tokenSidecarLockingScript
        seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.REDEMPTION), seedScript(SCRIPT.REDEMPTION_SIDECAR)],
      });
    }
    return buildFromArtifact(z3, specs, {
      nInputs: 7, nOutputs: 11, policy: POLICY.startRedemption, designatedInputs: [0, 1, 4],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        loanInput(s, tx.inputs[1]!);
        loanSidecarInput(s, tx.inputs[2]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[3]!, SCRIPT.FN_START_REDEMPTION, LoanFunction.START_REDEMPTION);
        pin(s, tx.inputs[4]!, { category: CAT.REDEEMER, capability: Capability.MINTING, script: SCRIPT.REDEEMER });
        pin(s, tx.inputs[5]!, { category: CAT.PARYON, capability: Capability.NONE });
        s.add(tx.inputs[1]!.category.eq(CAT.PARYON));
      },
    });
  }

  it('startRedemption (04) + Redeemer.createRedemption', async () => {
    await expectArtifactSafe(z3, startRedemption(z3, true));
  });
  it('startRedemption — composition matters: without the Redeemer covenant a redeemer-minting NFT leaks', async () => {
    await expectArtifactLeaks(z3, startRedemption(z3, false));
  });

  // --- finalize: redeem loan fn + Redemption.finalizeRedemption (abi 0) ---
  function finalize(z3: Z3, withRedemption: boolean) {
    const specs: CovenantSpec[] = [
      // redeem constructor: redemptionTokenId, timelock, startBlock, periodLength
      { artifact: fns.artifactFunctionRedeem, activeIndex: 2, seeds: [seedCategory(CAT.REDEEMER), seedOpaque, seedOpaque, seedOpaque] },
    ];
    specs.push(loanSidecar(1));
    if (withRedemption) {
      specs.push({ artifact: red.artifactRedemption, activeIndex: 3, abiIndex: 0, seeds: [seedCategory(CAT.PARYON)] });
    }
    return buildFromArtifact(z3, specs, {
      nInputs: 7, nOutputs: 8, policy: POLICY.redeem, designatedInputs: [0, 3],
      setup: (_z3, s, tx) => {
        loanInput(s, tx.inputs[0]!);
        loanSidecarInput(s, tx.inputs[1]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[2]!, SCRIPT.FN_REDEEM, LoanFunction.REDEEMED);
        pin(s, tx.inputs[3]!, { category: CAT.REDEEMER, capability: Capability.MUTABLE, script: SCRIPT.REDEMPTION });
        pin(s, tx.inputs[4]!, { category: CAT.REDEEMER, capability: Capability.IMMUTABLE, script: SCRIPT.REDEMPTION_SIDECAR });
        pin(s, tx.inputs[5]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.REDEMPTION_SIDECAR });
        s.add(tx.inputs[0]!.category.eq(CAT.PARYON));
      },
    });
  }

  it('redeem finalize/cancel (03) + Redemption.finalizeRedemption', async () => {
    await expectArtifactSafe(z3, finalize(z3, true));
  });
  it('finalize — composition matters: without the Redemption covenant the redemption mutable NFT leaks', async () => {
    await expectArtifactLeaks(z3, finalize(z3, false));
  });

  // --- swap: swapOut + swapIn loan fns + Redemption.swapTargetLoan (abi 1) ---
  function swap(z3: Z3, withRedemption: boolean) {
    const specs: CovenantSpec[] = [
      { artifact: fns.artifactFunctionSwapOutRedemption, activeIndex: 2, seeds: [seedCategory(CAT.REDEEMER)] },
      { artifact: fns.artifactFunctionSwapInRedemption, activeIndex: 8, seeds: [seedCategory(CAT.REDEEMER)] },
    ];
    specs.push(loanSidecar(1), loanSidecar(7));
    if (withRedemption) {
      specs.push({ artifact: red.artifactRedemption, activeIndex: 3, abiIndex: 1, seeds: [seedCategory(CAT.PARYON)] });
    }
    return buildFromArtifact(z3, specs, {
      nInputs: 10, nOutputs: 11, policy: POLICY.swap, designatedInputs: [0, 3, 6],
      setup: (_z3, s, tx) => {
        loanInput(s, tx.inputs[0]!);
        loanSidecarInput(s, tx.inputs[1]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[2]!, SCRIPT.FN_SWAP_OUT, LoanFunction.SWAP_OUT_REDEMPTION);
        pin(s, tx.inputs[3]!, { category: CAT.REDEEMER, capability: Capability.MUTABLE, script: SCRIPT.REDEMPTION });
        pin(s, tx.inputs[4]!, { category: CAT.REDEEMER, capability: Capability.IMMUTABLE, script: SCRIPT.REDEMPTION_SIDECAR });
        pin(s, tx.inputs[5]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.REDEMPTION_SIDECAR });
        loanInput(s, tx.inputs[6]!);
        loanSidecarInput(s, tx.inputs[7]!, CAT.LOANKEY_2);
        functionNftInput(s, tx.inputs[8]!, SCRIPT.FN_SWAP_IN, LoanFunction.SWAP_IN_REDEMPTION);
        s.add(tx.inputs[0]!.category.eq(CAT.PARYON));
        s.add(tx.inputs[6]!.category.eq(CAT.PARYON));
      },
    });
  }

  it('swapIn (05) + swapOut (06) + Redemption.swapTargetLoan', async () => {
    await expectArtifactSafe(z3, swap(z3, true));
  });
  it('swap — composition matters: without the Redemption covenant the redemption mutable NFT leaks', async () => {
    await expectArtifactLeaks(z3, swap(z3, false));
  });
});
