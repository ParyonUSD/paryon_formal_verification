import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability } from '../src/model.js';
import {
  CAT, LOAN_CATEGORIES, LoanFunction, POLICY, PoolFunction, SCRIPT, functionNftInput, loanInput, loanSidecarInput, pin,
} from '../src/covenants/common.js';
import { buildFromArtifact, type CovenantSpec } from '../src/script/fromArtifact.js';
import { seedCategory, seedOpaque, seedScript } from '../src/script/interpreter.js';
import { getContext, type Z3 } from '../src/z3.js';
import { poolSidecar, priceContract, stabilityPool } from './partners.js';
import { expectArtifactLeaks, expectArtifactSafe } from './assertions.js';

const sp = paryonArtifacts.stabilityPool;
const pf = sp.poolContractFunctions;
const loanFns = paryonArtifacts.loanContractFunctions;

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * The stability-pool subsystem, with each pool function + Collector + Payout AND the recreation
 * partners (StabilityPool.interact, StabilityPoolSidecar) all derived from artifact bytecode.
 * StabilityPool.interact / StabilityPoolSidecar pick their output index from the adjacent function
 * NFT's commitment (which we don't model) — the wrong branch self-eliminates because it would pin
 * the pool/sidecar onto an output the pool function already pins to something else (UNSAT).
 */
describe('stability-pool subsystem — derived from artifact bytecode', () => {
  it('AddLiquidity (stake)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: pf.artifactFunctionAddLiquidity, activeIndex: 2, seeds: [seedCategory(CAT.PARYON)] },
      stabilityPool(0), poolSidecar(1),
    ], {
      nInputs: 5, nOutputs: 7, categories: LOAN_CATEGORIES, policy: POLICY.addLiquidity, designatedInputs: [0],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.STABILITY_POOL });
        pin(s, tx.inputs[1]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.POOL_SIDECAR });
        pin(s, tx.inputs[2]!, { category: CAT.POOL, capability: Capability.IMMUTABLE, script: SCRIPT.FN_ADD_LIQUIDITY, commitment: PoolFunction.ADD_LIQUIDITY });
      },
    }));
  });

  it('WithdrawFromPool (unstake)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: pf.artifactFunctionWithdrawFromPool, activeIndex: 2 },
      stabilityPool(0), poolSidecar(1),
    ], {
      nInputs: 5, nOutputs: 7, categories: LOAN_CATEGORIES, policy: POLICY.withdraw, designatedInputs: [0],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.STABILITY_POOL });
        pin(s, tx.inputs[1]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.POOL_SIDECAR });
        pin(s, tx.inputs[2]!, { category: CAT.POOL, capability: Capability.IMMUTABLE, script: SCRIPT.FN_WITHDRAW, commitment: PoolFunction.WITHDRAW_LIQUIDITY });
        pin(s, tx.inputs[3]!, { category: CAT.POOL, capability: Capability.IMMUTABLE }); // staking receipt (user-held immutable)
      },
    }));
  });

  it('Payout.claimPayout', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      { artifact: sp.artifactPayout, activeIndex: 0 },
    ], {
      nInputs: 3, nOutputs: 4, categories: LOAN_CATEGORIES, policy: POLICY.payout, designatedInputs: [0],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.PAYOUT });
        pin(s, tx.inputs[1]!, { category: CAT.POOL, capability: Capability.IMMUTABLE }); // staking receipt
      },
    }));
  });

  it('NewPeriodPool (+ Collector.payToStabilityPool)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      // constructor: payoutLockingScript, collectorLockingScript, startBlockHeight, periodLengthBlocks
      { artifact: pf.artifactFunctionNewPeriodPool, activeIndex: 2, seeds: [seedScript(SCRIPT.PAYOUT), seedScript(SCRIPT.COLLECTOR), seedOpaque, seedOpaque] },
      // Collector at input 3, payToStabilityPool = abi 1; ctor: paryonTokenId, lockingBytecodeProtocolFee
      { artifact: sp.artifactCollector, activeIndex: 3, abiIndex: 1, seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.PROTOCOL_FEE)] },
      stabilityPool(0), poolSidecar(1),
    ], {
      nInputs: 5, nOutputs: 8, categories: LOAN_CATEGORIES, policy: POLICY.newPeriod, designatedInputs: [0, 3],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.STABILITY_POOL });
        pin(s, tx.inputs[1]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.POOL_SIDECAR });
        pin(s, tx.inputs[2]!, { category: CAT.POOL, capability: Capability.IMMUTABLE, script: SCRIPT.FN_NEW_PERIOD, commitment: PoolFunction.NEW_PERIOD });
        pin(s, tx.inputs[3]!, { category: CAT.POOL, capability: Capability.MUTABLE, script: SCRIPT.COLLECTOR });
      },
    }));
  });

  // --- full liquidate: loan-side `liquidate` + pool-side `LiquidateLoan`, all partners derived ---
  function liquidate(z3: Z3, withLiquidateLoan: boolean) {
    const specs: CovenantSpec[] = [
      { artifact: loanFns.artifactFunctionLiquidate, activeIndex: 3, seeds: [seedCategory(CAT.POOL)] },
      priceContract(0), stabilityPool(4), poolSidecar(5),
    ];
    if (withLiquidateLoan) {
      specs.push({ artifact: pf.artifactFunctionLiquidateLoan, activeIndex: 6, seeds: [seedCategory(CAT.PARYON)] });
    }
    return buildFromArtifact(z3, specs, {
      nInputs: 8, nOutputs: 8, categories: LOAN_CATEGORIES, policy: POLICY.liquidate, designatedInputs: [0, 1, 4, 6], // 6: the pool function NFT stays governed even when LiquidateLoan is dropped
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        loanInput(s, tx.inputs[1]!);
        loanSidecarInput(s, tx.inputs[2]!, CAT.LOANKEY);
        functionNftInput(s, tx.inputs[3]!, SCRIPT.FN_LIQUIDATE, LoanFunction.LIQUIDATED);
        pin(s, tx.inputs[4]!, { category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.STABILITY_POOL });
        pin(s, tx.inputs[5]!, { category: CAT.PARYON, capability: Capability.NONE, script: SCRIPT.POOL_SIDECAR });
        pin(s, tx.inputs[6]!, { category: CAT.POOL, capability: Capability.IMMUTABLE, script: SCRIPT.FN_LIQUIDATELOAN, commitment: PoolFunction.LIQUIDATE_LOAN });
        s.add(tx.inputs[1]!.category.eq(CAT.PARYON));
      },
    });
  }

  it('liquidate (01) + LiquidateLoan', async () => {
    await expectArtifactSafe(z3, liquidate(z3, true));
  });
  it('liquidate — composition matters: without LiquidateLoan the loan mutable + pool capability leak', async () => {
    await expectArtifactLeaks(z3, liquidate(z3, false));
  });
});
