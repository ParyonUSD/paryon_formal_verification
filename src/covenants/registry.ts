import { paryonArtifacts } from '@paryonusd/contracts';
import type { Artifact } from '../script/artifact.js';
import { seedCategory, seedOpaque, seedScript, type SVal } from '../script/interpreter.js';
import { CAT, SCRIPT } from './ids.js';

/**
 * Which locking script runs which contract code — the deployment registry, and together with
 * `SYSTEM_POLICY` the only hand-written input to the whole-system proof (`src/script/wholeSystem.ts`).
 *
 * There is no transaction shape in here. A registry entry says "an input whose locking script is this
 * covenant runs this artifact with these constructor arguments, wherever it sits"; the solver decides
 * everything else. Constructor seeds bind a script-typed parameter to the script id of the contract it
 * names and a tokenId parameter to a category id; anything that cannot feed a capability comparison
 * (public keys, block heights, timelocks) is opaque. These are exactly the bindings
 * `verify_contract_deployment` checks on chain, which is what makes the registry reviewable.
 */
export interface RegisteredCovenant {
  artifact: Artifact;
  /** Constructor-arg seeds (bottom of stack), in declaration order. */
  seeds?: SVal[];
  /**
   * The ABI functions modelled for this script. Defaults to all of them; every function left out must
   * appear in {@link RegisteredCovenant.excluded} with a reason, so nothing is silently dropped
   * (`tests/coverage.test.ts` is the ledger that enforces it).
   */
  abiIndices?: number[];
  /** ABI index -> why that function is not modelled (a trust assumption, not an oversight). */
  excluded?: Record<number, string>;
}

export type CovenantRegistry = Map<number, RegisteredCovenant>;

const A = paryonArtifacts;
const lk = A.loanKey;
const loanFns = A.loanContractFunctions;
const sp = A.stabilityPool;
const pf = sp.poolContractFunctions;
const red = A.redeemer;

/**
 * Every covenant of the deployed system: the loan and its sidecar, the eight loan functions, the
 * price contract, the borrowing contract and the loanKey factory chain, the stability pool with its
 * sidecar, functions, Collector and Payout, and the redemption chain.
 *
 * `unmodelledCovenantScripts` is empty for this registry, so the whole-system build constrains every
 * covenant UTXO a transaction can spend and the proof needs no scope restriction on its inputs.
 */
export const SYSTEM_REGISTRY: CovenantRegistry = new Map<number, RegisteredCovenant>([
  // ---- loan ----
  [SCRIPT.LOAN, { artifact: A.artifactLoan }],
  [SCRIPT.LOAN_SIDECAR, { artifact: A.artifactLoanSidecar }],
  // constructor: oraclePublicKey, tokenIdMigrationKey
  [SCRIPT.PRICE, {
    artifact: A.artifactPriceContract,
    seeds: [seedOpaque, seedOpaque],
    abiIndices: [0, 1], // updatePrice, sharePrice
    excluded: {
      2: 'migrateContract: the oracle migration key may move the price authority to new contract code '
        + 'by design — a documented admin trust assumption of the system, not a property to prove',
    },
  }],
  [SCRIPT.FN_MANAGE, { artifact: loanFns.artifactFunctionManage }],
  [SCRIPT.FN_CHANGE_INTEREST, { artifact: loanFns.artifactFunctionChangeInterest }],
  // constructor: stabilityPoolTokenId
  [SCRIPT.FN_PAY_INTEREST, { artifact: loanFns.artifactFunctionPayInterest, seeds: [seedCategory(CAT.POOL)] }],
  [SCRIPT.FN_LIQUIDATE, { artifact: loanFns.artifactFunctionLiquidate, seeds: [seedCategory(CAT.POOL)] }],
  // constructor: redemptionTokenId, timelockRedemption, startBlockHeight, periodLengthBlocks
  [SCRIPT.FN_REDEEM, {
    artifact: loanFns.artifactFunctionRedeem,
    seeds: [seedCategory(CAT.REDEEMER), seedOpaque, seedOpaque, seedOpaque],
  }],
  // constructor: redeemerTokenId / redemptionTokenId
  [SCRIPT.FN_START_REDEMPTION, {
    artifact: loanFns.artifactFunctionStartRedemption, seeds: [seedCategory(CAT.REDEEMER)],
  }],
  [SCRIPT.FN_SWAP_IN, { artifact: loanFns.artifactFunctionSwapInRedemption, seeds: [seedCategory(CAT.REDEEMER)] }],
  [SCRIPT.FN_SWAP_OUT, { artifact: loanFns.artifactFunctionSwapOutRedemption, seeds: [seedCategory(CAT.REDEEMER)] }],

  // ---- borrowing + loanKey factory ----
  // constructor: loanLockingScript, loanTokensidecarLockingScript, borrowingFeeLockingScript,
  //              loanKeyOriginEnforcerLockingScript, startBlockHeight, periodLengthBlocks
  [SCRIPT.BORROWING, {
    artifact: A.artifactBorrowing,
    seeds: [
      seedScript(SCRIPT.LOAN), seedScript(SCRIPT.LOAN_SIDECAR), seedScript(SCRIPT.FEE),
      seedScript(SCRIPT.ORIGIN_ENFORCER), seedOpaque, seedOpaque,
    ],
    abiIndices: [0, 1], // borrow, updatePeriodState
  }],
  // constructor: loanKeyOriginEnforcerLockingScript, loanKeyOriginProofLockingScript
  [SCRIPT.LOANKEY_FACTORY, {
    artifact: lk.artifactLoanKeyFactory,
    seeds: [seedScript(SCRIPT.ORIGIN_ENFORCER), seedScript(SCRIPT.ORIGIN_PROOF)],
  }],
  // constructor: loanKeyFactoryTokenId, paryonTokenId
  [SCRIPT.ORIGIN_ENFORCER, {
    artifact: lk.artifactLoanKeyOriginEnforcer,
    seeds: [seedCategory(CAT.LOANKEY_FACTORY), seedCategory(CAT.PARYON)],
  }],
  [SCRIPT.ORIGIN_PROOF, { artifact: lk.artifactLoanKeyOriginProof }],

  // ---- stability pool ----
  [SCRIPT.STABILITY_POOL, { artifact: sp.artifactStabilityPool }],
  // constructor: paryonTokenId
  [SCRIPT.POOL_SIDECAR, { artifact: sp.artifactStabilityPoolSidecar, seeds: [seedCategory(CAT.PARYON)] }],
  [SCRIPT.PAYOUT, { artifact: sp.artifactPayout }],
  // constructor: paryonTokenId, lockingBytecodeProtocolFee
  [SCRIPT.COLLECTOR, {
    artifact: sp.artifactCollector,
    seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.PROTOCOL_FEE)],
    abiIndices: [0, 1], // collect, payToStabilityPool
  }],
  [SCRIPT.FN_ADD_LIQUIDITY, { artifact: pf.artifactFunctionAddLiquidity, seeds: [seedCategory(CAT.PARYON)] }],
  [SCRIPT.FN_LIQUIDATELOAN, { artifact: pf.artifactFunctionLiquidateLoan, seeds: [seedCategory(CAT.PARYON)] }],
  // constructor: payoutLockingScript, collectorLockingScript, startBlockHeight, periodLengthBlocks
  [SCRIPT.FN_NEW_PERIOD, {
    artifact: pf.artifactFunctionNewPeriodPool,
    seeds: [seedScript(SCRIPT.PAYOUT), seedScript(SCRIPT.COLLECTOR), seedOpaque, seedOpaque],
  }],
  [SCRIPT.FN_WITHDRAW, { artifact: pf.artifactFunctionWithdrawFromPool }],

  // ---- redemption ----
  // constructor: paryonTokenId, redemptionLockingScript, tokenSidecarLockingScript
  [SCRIPT.REDEEMER, {
    artifact: red.artifactRedeemer,
    seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.REDEMPTION), seedScript(SCRIPT.REDEMPTION_SIDECAR)],
  }],
  // constructor: paryonTokenId
  [SCRIPT.REDEMPTION, {
    artifact: red.artifactRedemption,
    seeds: [seedCategory(CAT.PARYON)],
    abiIndices: [0, 1], // finalizeRedemption, swapTargetLoan
  }],
  [SCRIPT.REDEMPTION_SIDECAR, { artifact: red.artifactRedemptionSidecar }],
]);

/**
 * Locking scripts that are not covenants: plain payout addresses the contracts send BCH to. They carry
 * no code, so an input on one is unconstrained — exactly like an attacker script. They are listed only
 * so `unmodelledCovenantScripts` does not mistake them for a subsystem the registry forgot.
 */
export const NON_COVENANT_SCRIPTS: number[] = [SCRIPT.FEE, SCRIPT.PROTOCOL_FEE];

/**
 * The covenant scripts a registry does not model: every id in the deployment registry that is neither
 * registered nor a plain payout address. **Empty for {@link SYSTEM_REGISTRY}**, which is what makes
 * the whole-system proof unconditional on its inputs.
 *
 * A non-empty result is a scope restriction, not a modelling choice: an input on such a script would
 * run contract code the build cannot execute, so the build would leave its outputs unconstrained and
 * report leaks the missing covenant in fact prevents. `buildWholeSystem` therefore keeps those scripts
 * off the inputs, which scopes the proof to "transactions that spend only the registered covenants'
 * UTXOs" — useful for a subsystem-sized build, and unnecessary here.
 */
export function unmodelledCovenantScripts(registry: CovenantRegistry): number[] {
  return Object.values(SCRIPT).filter((id) => !registry.has(id) && !NON_COVENANT_SCRIPTS.includes(id));
}

/** The name of an artifact's ABI function, for diagnostics and the coverage ledger. */
export function functionName(entry: RegisteredCovenant, abiIndex: number): string {
  return `${entry.artifact.contractName}.${entry.artifact.abi[abiIndex]?.name ?? abiIndex}`;
}
