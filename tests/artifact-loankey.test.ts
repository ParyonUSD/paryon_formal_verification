import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability, NO_CATEGORY } from '../src/model.js';
import { CAT, LOAN_CATEGORIES, POLICY, SCRIPT, pin } from '../src/covenants/common.js';
import { buildFromArtifact, type CovenantSpec } from '../src/script/fromArtifact.js';
import { seedOpaque, seedScript } from '../src/script/interpreter.js';
import { getContext, type Z3 } from '../src/z3.js';
import { priceContract } from './partners.js';
import { expectArtifactLeaks, expectArtifactSafe } from './assertions.js';

const lk = paryonArtifacts.loanKey;

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * The borrowing + loanKey-factory subsystem, derived from artifact bytecode.
 *
 * `Borrowing` is multi-function (borrow / updatePeriodState) and a paryon minting authority;
 * `LoanKeyFactory.create` genesis-mints a brand-new per-loan loanKey category. The
 * `LoanKeyOriginEnforcer`/`LoanKeyOriginProof` covenants are auth/adjacency-only (no output pins),
 * so they contribute nothing to the leak property and are omitted. Only `PriceContract.sharePrice`
 * remains hand-modelled in `borrow`.
 */
describe('borrowing + loanKey factory — derived from artifact bytecode', () => {
  // --- borrow: Borrowing.borrow (abi 0) + PriceContract.sharePrice ---
  function borrow(z3: Z3, withPrice: boolean) {
    const specs: CovenantSpec[] = [
      {
        artifact: paryonArtifacts.artifactBorrowing, activeIndex: 0, abiIndex: 0,
        // constructor: loanLockingScript, loanTokensidecarLockingScript, borrowingFeeLockingScript,
        //              loanKeyOriginEnforcerLockingScript, startBlockHeight, periodLengthBlocks
        seeds: [
          seedScript(SCRIPT.LOAN), seedScript(SCRIPT.LOAN_SIDECAR), seedScript(SCRIPT.FEE),
          seedScript(SCRIPT.ORIGIN_ENFORCER), seedOpaque, seedOpaque,
        ],
      },
    ];
    if (withPrice) specs.push(priceContract(1)); // PriceContract.sharePrice recreates the price at output 1
    return buildFromArtifact(z3, specs, {
      nInputs: 5, nOutputs: 11, categories: LOAN_CATEGORIES, policy: POLICY.borrow, designatedInputs: [0, 1],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MINTING, script: SCRIPT.BORROWING });
        pin(s, tx.inputs[1]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        // loanKeyOriginEnforcer: the prepared loanKey (a user-facing category) as a minting NFT.
        pin(s, tx.inputs[2]!, { category: CAT.LOANKEY, capability: Capability.MINTING, script: SCRIPT.ORIGIN_ENFORCER });
        s.add(tx.inputs[0]!.category.eq(CAT.PARYON));
      },
    });
  }

  it('borrow + PriceContract.sharePrice', async () => {
    await expectArtifactSafe(z3, borrow(z3, true));
  });
  it('borrow — composition matters: without the price covenant a paryon-minting NFT leaks at output 1', async () => {
    await expectArtifactLeaks(z3, borrow(z3, false));
  });

  // --- updatePeriodState: Borrowing (abi 1) alone, the minting NFT with only a fee input ---
  it('Borrowing.updatePeriodState (output cap protects the minting NFT)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [{
      artifact: paryonArtifacts.artifactBorrowing, activeIndex: 0, abiIndex: 1,
      seeds: [seedScript(SCRIPT.LOAN), seedScript(SCRIPT.LOAN_SIDECAR), seedScript(SCRIPT.FEE), seedScript(SCRIPT.ORIGIN_ENFORCER), seedOpaque, seedOpaque],
    }], {
      nInputs: 2, nOutputs: 4, categories: LOAN_CATEGORIES, policy: POLICY.borrow, designatedInputs: [0],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MINTING, script: SCRIPT.BORROWING });
        pin(s, tx.inputs[1]!, { category: NO_CATEGORY }); // fee BCH
      },
    }));
  });

  it('LoanKeyFactory.create (genesis-mints a loanKey)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      // constructor: loanKeyOriginEnforcerLockingScript, loanKeyOriginProofLockingScript
      { artifact: lk.artifactLoanKeyFactory, activeIndex: 1, seeds: [seedScript(SCRIPT.ORIGIN_ENFORCER), seedScript(SCRIPT.ORIGIN_PROOF)] },
    ], {
      nInputs: 3, nOutputs: 7, categories: LOAN_CATEGORIES, policy: POLICY.loanKeyFactory, designatedInputs: [1],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: NO_CATEGORY }); // vout0 genesis-source UTXO (BCH only)
        pin(s, tx.inputs[1]!, { category: CAT.LOANKEY_FACTORY, capability: Capability.MINTING, script: SCRIPT.LOANKEY_FACTORY });
      },
    }));
  });
});
