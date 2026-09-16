import { paryonArtifacts } from '@paryonusd/contracts';
import type { Artifact } from '../script/fromArtifact.js';
import { seedCategory, seedOpaque, seedScript, type SVal } from '../script/interpreter.js';
import { CAT, SCRIPT } from './ids.js';

/**
 * Which locking script runs which contract code — the ParyonUSD instantiation of the whole-system
 * model (`src/script/wholeSystem.ts`).
 *
 * The per-transaction templates say "this artifact runs at input 3"; a registry says "an input whose
 * locking script is this covenant runs this artifact, wherever it sits". That is the whole hand-written
 * input left: a map from a deployed script to its artifact and its constructor arguments, exactly as
 * `verify_contract_deployment` checks them on chain. There is no transaction shape in here.
 *
 * Constructor seeds are the same bindings the templates use (grep `seeds:` in tests/): a script-typed
 * parameter binds to the script id of the contract it names, a tokenId parameter to a category id, and
 * anything that cannot feed a capability comparison (public keys, block heights) is opaque.
 */
export interface RegisteredCovenant {
  artifact: Artifact;
  /** Constructor-arg seeds (bottom of stack), in declaration order. */
  seeds?: SVal[];
  /**
   * The ABI functions modelled for this script; every function not listed must be listed in
   * {@link RegisteredCovenant.excluded} with a reason, so nothing is silently dropped.
   */
  abiIndices?: number[];
  /** ABI index -> why that function is not modelled (a trust assumption, not an oversight). */
  excluded?: Record<number, string>;
}

export type CovenantRegistry = Map<number, RegisteredCovenant>;

const sp = paryonArtifacts.stabilityPool;
const loanFns = paryonArtifacts.loanContractFunctions;

/**
 * The loan subsystem: the loan itself, its sidecar, the three loan functions that are not part of the
 * redemption or stability-pool flows, the price contract they read, and the Collector `payInterest`
 * pays into. The redemption, stability-pool and borrowing subsystems are deliberately left out of this
 * pilot (see `unmodelledCovenantScripts`, which keeps their UTXOs out of the modelled transactions).
 */
export const LOAN_SUBSYSTEM_REGISTRY: CovenantRegistry = new Map<number, RegisteredCovenant>([
  [SCRIPT.LOAN, { artifact: paryonArtifacts.artifactLoan }],
  [SCRIPT.LOAN_SIDECAR, { artifact: paryonArtifacts.artifactLoanSidecar }],
  [SCRIPT.FN_MANAGE, { artifact: loanFns.artifactFunctionManage }],
  [SCRIPT.FN_CHANGE_INTEREST, { artifact: loanFns.artifactFunctionChangeInterest }],
  // constructor: stabilityPoolTokenId
  [SCRIPT.FN_PAY_INTEREST, { artifact: loanFns.artifactFunctionPayInterest, seeds: [seedCategory(CAT.POOL)] }],
  // constructor: paryonTokenId, lockingBytecodeProtocolFee
  [SCRIPT.COLLECTOR, {
    artifact: sp.artifactCollector,
    seeds: [seedCategory(CAT.PARYON), seedScript(SCRIPT.PROTOCOL_FEE)],
    abiIndices: [0, 1], // collect, payToStabilityPool
  }],
  // constructor: oraclePublicKey, tokenIdMigrationKey
  [SCRIPT.PRICE, {
    artifact: paryonArtifacts.artifactPriceContract,
    seeds: [seedOpaque, seedOpaque],
    abiIndices: [0, 1], // updatePrice, sharePrice
    excluded: {
      2: 'migrateContract: the oracle migration key may move the price authority to new contract code '
        + 'by design — a documented admin trust assumption of the system, not a property to prove',
    },
  }],
]);

/**
 * Locking scripts that are not covenants: plain payout addresses the contracts send BCH to. They carry
 * no code, so an input on one is unconstrained — exactly like an attacker script. They are listed only
 * so `unmodelledCovenantScripts` does not mistake them for a subsystem this build forgot.
 */
export const NON_COVENANT_SCRIPTS: number[] = [SCRIPT.FEE, SCRIPT.PROTOCOL_FEE];

/**
 * The covenant scripts this registry does not model: every id in the deployment registry that is
 * neither registered nor a plain payout address.
 *
 * An input on one of them would run contract code the build cannot execute, so the build would let its
 * outputs go anywhere and report leaks that the missing covenant in fact prevents. `buildWholeSystem`
 * therefore keeps them off the inputs, which scopes the proof to "transactions that spend only the
 * registered subsystem's UTXOs". This is the pilot's one remaining scope assumption, and it is derived
 * from the registry rather than written per transaction: register every subsystem and the set is empty.
 */
export function unmodelledCovenantScripts(registry: CovenantRegistry): number[] {
  return Object.values(SCRIPT).filter((id) => !registry.has(id) && !NON_COVENANT_SCRIPTS.includes(id));
}

/** The name of an artifact's ABI function, for diagnostics. */
export function functionName(entry: RegisteredCovenant, abiIndex: number): string {
  return `${entry.artifact.contractName}.${entry.artifact.abi[abiIndex]?.name ?? abiIndex}`;
}
