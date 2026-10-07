import { Capability } from '../model.js';
import {
  type AdjacencyRule, type FunctionNftRule, type LeakPolicy, type OwnershipRule, type SingleUseRule,
  type StateShapeRule,
} from '../policy.js';
import { CAT, SCRIPT } from './ids.js';

// Abstract category/script identity ids live in ./ids.js (arbitrary, equality-only).
export { CAT, SCRIPT } from './ids.js';

/**
 * The security *specification* of the ParyonUSD deployment: the identifiers the contracts
 * authenticate each other by, and the five invariants `SYSTEM_POLICY` assumes of a transaction's
 * inputs. With `covenants/registry.ts` this is the whole hand-written input to the proof — there is no
 * contract logic here, only facts about the deployment that `verify_contract_deployment` establishes
 * at genesis and the whole-system witnesses re-establish on every transaction's outputs.
 */

/**
 * Function-NFT commitment identifiers (the single-byte ids the contracts authenticate by) — mirrors
 * the canonical enums in @paryonusd/contracts, so the policy names a function rather than a magic
 * number. Modelled as numbers because commitments are integers in this model.
 */
export const LoanFunction = {
  LIQUIDATED: 0x01,
  MANAGE_LOAN: 0x02,
  REDEEMED: 0x03,
  START_REDEMPTION: 0x04,
  SWAP_IN_REDEMPTION: 0x05,
  SWAP_OUT_REDEMPTION: 0x06,
  PAY_INTEREST: 0x07,
  CHANGE_INTEREST: 0x08,
} as const;

export const PoolFunction = {
  ADD_LIQUIDITY: 0x01,
  LIQUIDATE_LOAN: 0x02,
  NEW_PERIOD: 0x03,
  WITHDRAW_LIQUIDITY: 0x04,
} as const;

export const INTERNAL_CATEGORIES = [CAT.PARYON, CAT.POOL, CAT.REDEEMER, CAT.LOANKEY_FACTORY];

/**
 * Every category id the consensus tally is enforced over: the four internal authorities plus two
 * user-facing categories, so the model also carries categories the attacker may move freely. Z3 cannot
 * range over the unbounded category domain, so the tally is instantiated at these concrete ids; an
 * output may still take any id in range, and one outside this set is simply untallied (which only
 * admits more).
 */
export const TALLIED_CATEGORIES = [
  CAT.PARYON, CAT.POOL, CAT.REDEEMER, CAT.LOANKEY_FACTORY, CAT.USER_1, CAT.USER_2,
];

/** Reusable ownership rules (who rightfully holds each privileged capability). */
const own = (category: number, capability: number, scripts: number[]): OwnershipRule =>
  ({ category, capability, scripts });
export const OWN = {
  paryonMutableLoanPrice: own(CAT.PARYON, Capability.MUTABLE, [SCRIPT.LOAN, SCRIPT.PRICE]),
  poolMintingFull: own(CAT.POOL, Capability.MINTING, [SCRIPT.STABILITY_POOL, SCRIPT.PAYOUT]), // pool + each Payout
  poolMutableCollector: own(CAT.POOL, Capability.MUTABLE, [SCRIPT.COLLECTOR]),
  redeemerMutable: own(CAT.REDEEMER, Capability.MUTABLE, [SCRIPT.REDEMPTION]),
  redeemerMinting: own(CAT.REDEEMER, Capability.MINTING, [SCRIPT.REDEEMER]),
  paryonMintingBorrowing: own(CAT.PARYON, Capability.MINTING, [SCRIPT.BORROWING]),
  loanKeyFactoryMinting: own(CAT.LOANKEY_FACTORY, Capability.MINTING, [SCRIPT.LOANKEY_FACTORY]),
} satisfies Record<string, OwnershipRule>;

/**
 * The function NFTs: immutable NFTs with a single-byte commitment that `Loan.interact` (paryon) and
 * `StabilityPool.interact` (pool) accept as their delegated function *by shape alone* — category plus
 * `commitment.length == 1`, never the script. So (authenticity) no NFT of that shape may ever exist off
 * these function scripts, or its holder could spend any loan / the pool with no covenant logic; and
 * (preservation) a spent one must be recreated in place, or that operation is bricked.
 */
const LOAN_FUNCTION_SITES: Record<number, number> = {
  [SCRIPT.FN_LIQUIDATE]: LoanFunction.LIQUIDATED,
  [SCRIPT.FN_MANAGE]: LoanFunction.MANAGE_LOAN,
  [SCRIPT.FN_REDEEM]: LoanFunction.REDEEMED,
  [SCRIPT.FN_START_REDEMPTION]: LoanFunction.START_REDEMPTION,
  [SCRIPT.FN_SWAP_IN]: LoanFunction.SWAP_IN_REDEMPTION,
  [SCRIPT.FN_SWAP_OUT]: LoanFunction.SWAP_OUT_REDEMPTION,
  [SCRIPT.FN_PAY_INTEREST]: LoanFunction.PAY_INTEREST,
  [SCRIPT.FN_CHANGE_INTEREST]: LoanFunction.CHANGE_INTEREST,
};
const POOL_FUNCTION_SITES: Record<number, number> = {
  [SCRIPT.FN_ADD_LIQUIDITY]: PoolFunction.ADD_LIQUIDITY,
  [SCRIPT.FN_LIQUIDATELOAN]: PoolFunction.LIQUIDATE_LOAN,
  [SCRIPT.FN_NEW_PERIOD]: PoolFunction.NEW_PERIOD,
  [SCRIPT.FN_WITHDRAW]: PoolFunction.WITHDRAW_LIQUIDITY,
};

export const FUNCTION_NFTS: FunctionNftRule[] = [
  {
    category: CAT.PARYON, commitmentLength: 1,
    scripts: Object.keys(LOAN_FUNCTION_SITES).map(Number), commitments: LOAN_FUNCTION_SITES,
    // The eight loan functions are the only paryon immutable NFTs with a non-empty commitment: the
    // pool and redemption sidecars hold paryon *fungible* tokens with no NFT, and every other paryon
    // NFT is the mutable loan or price state. `Redeemer.createRedemption` relies on it, authenticating
    // the startRedemption NFT by leading byte without checking the commitment length.
    exhaustiveNonEmpty: true,
  },
  {
    category: CAT.POOL, commitmentLength: 1,
    scripts: Object.keys(POOL_FUNCTION_SITES).map(Number), commitments: POOL_FUNCTION_SITES,
  },
];

/**
 * The sidecar pairs. `Loan.interact`, `StabilityPool.interact` and `RedemptionSidecar.attach`
 * authenticate their companion UTXO by outpoint adjacency alone — same source transaction, next
 * output index — and never by locking script. So "the UTXO one index after a loan / pool / redemption
 * is its sidecar" is part of the system invariant, and it is the assumption every template made when
 * it pinned input 1 to the sidecar script. Assumed on inputs, discharged on outputs by
 * `adjacencyWitness`.
 */
export const SIDECAR_PAIRS: AdjacencyRule[] = [
  { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.LOAN, companionScript: SCRIPT.LOAN_SIDECAR },
  {
    category: CAT.POOL, capability: Capability.MINTING, script: SCRIPT.STABILITY_POOL,
    companionScript: SCRIPT.POOL_SIDECAR,
  },
  {
    category: CAT.REDEEMER, capability: Capability.MUTABLE, script: SCRIPT.REDEMPTION,
    companionScript: SCRIPT.REDEMPTION_SIDECAR,
  },
];

/**
 * The state NFTs' leading identifier bytes. A loan's mutable NFT always starts 0x01 and the price
 * contract's always starts 0x00 — the byte the covenants authenticate each other by, never the locking
 * script — so without the binding a price contract can stand in for a loan anywhere in the system.
 * The other state NFTs (Borrowing, Collector, StabilityPool, Redemption, Payout) begin with a period
 * counter, a token id or a public-key hash and have no fixed identifier to bind.
 * Assumed on inputs, discharged on outputs by `stateShapeWitness`.
 */
export const STATE_SHAPES: StateShapeRule[] = [
  { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.LOAN, head: 0x01 },
  { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE, head: 0x00 },
];

/**
 * The system invariant, in one place: everything the proof assumes about a transaction's inputs, and
 * therefore everything it must re-establish on that transaction's outputs.
 *
 *   ownership          where each privileged (category, capability) may sit   -> leakWitness
 *   functionNfts       which script each function NFT sits on, with which id  -> forgedFunctionNftWitness
 *                      and that a spent one is recreated                      -> preservationWitness
 *   adjacency          the sidecar one outpoint index after a state NFT       -> adjacencyWitness
 *   stateShapes        the loan/price state's leading identifier byte         -> stateShapeWitness
 *
 * It is stated for the whole system at once, with no transaction shape attached, which is what lets a
 * single build cover every operation — batched operations included.
 *
 * The base case is the genesis state, and `verify_contract_deployment` is what **must** establish the
 * same facts of it, and does: the capability and commitment of every privileged NFT on its owning
 * contract (ownership), one function NFT per function contract with its own one-byte identifier and
 * no paryon token output anywhere but the borrowing, price and function contracts (functionNfts,
 * including exhaustiveNonEmpty), the adjacency of each state NFT and its sidecar in the genesis
 * outputs (adjacency), and the price contract's leading 0x00 state byte (stateShapes).
 */
export const SYSTEM_POLICY: LeakPolicy = {
  internalAuthorityCategories: INTERNAL_CATEGORIES,
  ownership: [
    OWN.paryonMutableLoanPrice,
    OWN.paryonMintingBorrowing,
    OWN.poolMintingFull,
    OWN.poolMutableCollector,
    OWN.redeemerMinting,
    OWN.redeemerMutable,
    OWN.loanKeyFactoryMinting,
  ],
  functionNfts: FUNCTION_NFTS,
  adjacency: SIDECAR_PAIRS,
  stateShapes: STATE_SHAPES,
};

/**
 * The loanKey origin proofs. `LoanKeyFactory.create` mints a fresh loanKey category onto the
 * `LoanKeyOriginEnforcer` and, one output later, an immutable factory NFT onto `LoanKeyOriginProof`.
 * The enforcer accepts that NFT as proof of the category's origin by category and outpoint adjacency
 * alone, and `borrow` turns the category into the loan's id, which redemptions find the loan by. So
 * each proof must be used once: a proof that survives its borrow vouches for any enforcer UTXO parked
 * in front of it, including a copy of a live loanKey, and a second loan with an existing loan's id
 * follows. Discharged on outputs by `singleUseWitness`.
 */
export const ORIGIN_PROOFS: SingleUseRule[] = [
  { category: CAT.LOANKEY_FACTORY, script: SCRIPT.ORIGIN_PROOF, pairedScript: SCRIPT.ORIGIN_ENFORCER },
];

/**
 * `SYSTEM_POLICY` with the `singleUse` clause: each loanKey origin proof is used once, then burned.
 *
 * It is kept apart from `SYSTEM_POLICY` because the published contracts do not preserve it: `borrow`
 * leaves the proof free to go to any of its free outputs 7 to 9 (`tests/whole-system-origin-proof.test.ts`).
 * An invariant the contracts do not preserve cannot be assumed by the other witnesses, so they keep
 * proving against `SYSTEM_POLICY`, which never relies on it.
 *
 * The clause can only be closed through the price contract, the one covenant in every borrow whose
 * code can change, and then only as far as the price contract's code goes: `migrateContract` is
 * excluded from the registry, so a proof that relies on the price code holds as long as the oracle
 * migration key does not move the price threads to code without the check.
 *
 * Base case: genesis mints only the factory's minting NFT, so no immutable loanKey factory NFT exists
 * at genesis. But the published contracts break the clause from genesis on, so for a fix that arrives
 * through the price contract the base case is the chain state when the last price thread moves: every
 * origin proof still unspent on `LoanKeyOriginProof`, one outpoint after its enforcer. Neither is
 * asserted by the deployment checker yet.
 */
export const SINGLE_USE_POLICY: LeakPolicy = { ...SYSTEM_POLICY, singleUse: ORIGIN_PROOFS };
