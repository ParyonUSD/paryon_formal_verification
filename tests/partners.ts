import { paryonArtifacts } from '@paryonusd/contracts';
import { CAT } from '../src/covenants/common.js';
import type { CovenantSpec } from '../src/script/fromArtifact.js';
import { seedCategory, seedOpaque } from '../src/script/interpreter.js';

/**
 * CovenantSpecs for the recreation/sidecar partner covenants, derived from their artifact
 * bytecode. These replace the hand-modelled `priceShare` / `poolRecreate` / `poolSidecarRecreate`
 * helpers and the hand loan-sidecar output pins. The transaction `setup` still pins each partner's
 * INPUT (the transaction shape); these specs derive the OUTPUT recreations from bytecode.
 */

/** `PriceContract.sharePrice` (abi 1) recreates the price contract at its own output index. */
export function priceContract(activeIndex: number): CovenantSpec {
  // constructor: oraclePublicKey, tokenIdMigrationKey (unused by sharePrice)
  return { artifact: paryonArtifacts.artifactPriceContract, activeIndex, abiIndex: 1, seeds: [seedOpaque, seedOpaque] };
}

/** `StabilityPool.interact` recreates the pool (lockingBytecode + tokenCategory) at its output index. */
export function stabilityPool(activeIndex: number): CovenantSpec {
  return { artifact: paryonArtifacts.stabilityPool.artifactStabilityPool, activeIndex };
}

/** `LoanTokenSidecar.attach` recreates the loan sidecar when the loan is recreated. */
export function loanSidecar(activeIndex: number): CovenantSpec {
  return { artifact: paryonArtifacts.artifactLoanSidecar, activeIndex };
}

/** `StabilityPoolSidecar.attach` recreates the pool sidecar (paryon-or-none) at its output index. */
export function poolSidecar(activeIndex: number): CovenantSpec {
  // constructor: paryonTokenId
  return { artifact: paryonArtifacts.stabilityPool.artifactStabilityPoolSidecar, activeIndex, seeds: [seedCategory(CAT.PARYON)] };
}
