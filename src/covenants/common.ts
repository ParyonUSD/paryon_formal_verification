import { Capability, type Utxo } from '../model.js';
import { type LeakPolicy, type OwnershipRule, type PreservationRule } from '../policy.js';
import type { Num, Z3Solver } from '../z3.js';
import { CAT, SCRIPT } from './ids.js';

// Abstract category/script identity ids live in ./ids.js (arbitrary, equality-only).
export { CAT, SCRIPT } from './ids.js';

/**
 * Shared scaffolding for the loan subsystem: small constraint helpers, the
 * function-NFT identifier enums, and the loan leak policy + ownership building
 * blocks. Used by every loan-function model.
 */

/**
 * Function-NFT commitment identifiers (the single-byte ids the contracts authenticate by) and the
 * loan status byte — mirrors the canonical enums in @paryonusd/contracts. Used to pin commitments
 * where a contract branches on them (e.g. StabilityPool.interact'solver `commitment == 0x02`) instead of
 * hardcoding magic numbers. Modelled as numbers since commitments are integers in our model.
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

/** Every category id the consensus tally is enforced over. */
export const LOAN_CATEGORIES = [CAT.PARYON, CAT.POOL, CAT.REDEEMER, CAT.LOANKEY_FACTORY, CAT.LOANKEY, CAT.LOANKEY_2];

/** Reusable ownership rules (who rightfully holds each privileged capability). */
const own = (category: number, capability: number, scripts: number[]): OwnershipRule =>
  ({ category, capability, scripts });
export const OWN = {
  paryonMutableLoanPrice: own(CAT.PARYON, Capability.MUTABLE, [SCRIPT.LOAN, SCRIPT.PRICE]),
  paryonMutableLoan: own(CAT.PARYON, Capability.MUTABLE, [SCRIPT.LOAN]), // templates with no price input
  poolMinting: own(CAT.POOL, Capability.MINTING, [SCRIPT.STABILITY_POOL]),
  poolMintingFull: own(CAT.POOL, Capability.MINTING, [SCRIPT.STABILITY_POOL, SCRIPT.PAYOUT]), // pool + each Payout
  poolMutableCollector: own(CAT.POOL, Capability.MUTABLE, [SCRIPT.COLLECTOR]),
  redeemerMutable: own(CAT.REDEEMER, Capability.MUTABLE, [SCRIPT.REDEMPTION]),
  redeemerMinting: own(CAT.REDEEMER, Capability.MINTING, [SCRIPT.REDEEMER]),
  paryonMintingBorrowing: own(CAT.PARYON, Capability.MINTING, [SCRIPT.BORROWING]),
  loanKeyFactoryMinting: own(CAT.LOANKEY_FACTORY, Capability.MINTING, [SCRIPT.LOANKEY_FACTORY]),
} satisfies Record<string, OwnershipRule>;

/**
 * The function NFTs: immutable NFTs whose presence on their function script is what makes each
 * covenant operation possible. Every transaction spending one must recreate it in place (checked by
 * `preservationWitness`); losing one would brick that operation for the whole system.
 */
export const FUNCTION_NFTS: PreservationRule[] = [
  { category: CAT.PARYON, scripts: [
    SCRIPT.FN_LIQUIDATE, SCRIPT.FN_MANAGE, SCRIPT.FN_REDEEM, SCRIPT.FN_START_REDEMPTION,
    SCRIPT.FN_SWAP_IN, SCRIPT.FN_SWAP_OUT, SCRIPT.FN_PAY_INTEREST, SCRIPT.FN_CHANGE_INTEREST,
  ] },
  { category: CAT.POOL, scripts: [
    SCRIPT.FN_LIQUIDATELOAN, SCRIPT.FN_ADD_LIQUIDITY, SCRIPT.FN_WITHDRAW, SCRIPT.FN_NEW_PERIOD,
  ] },
];

/**
 * A loan leak policy over the three internal authorities. `ownership` lists the
 * privileged-capability owners actually present in this template — omitting a
 * (category, capability) means it cannot legitimately appear on any input, which
 * is exactly how we say "no paryon-minting input exists in a loan transaction".
 */
export function loanPolicy(ownership: OwnershipRule[]): LeakPolicy {
  return { internalAuthorityCategories: INTERNAL_CATEGORIES, ownership, preserve: FUNCTION_NFTS };
}

/**
 * Per-function leak policies (the security *spec*: which categories are internal
 * authorities, and which covenant rightfully holds each privileged capability).
 * These are NOT transcribed contract logic — they parameterise the leak property
 * for each loan-function transaction, whose output pins are derived from the
 * compiled artifact bytecode (see src/script + tests/artifact-loan.test.ts).
 */
export const POLICY = {
  changeInterest: loanPolicy([OWN.paryonMutableLoan]),
  manage: loanPolicy([OWN.paryonMutableLoanPrice]),
  payInterest: loanPolicy([OWN.paryonMutableLoanPrice, OWN.poolMutableCollector]),
  redeem: loanPolicy([OWN.paryonMutableLoan, OWN.redeemerMutable]),
  swap: loanPolicy([OWN.paryonMutableLoan, OWN.redeemerMutable]),
  // creates a Redemption (redeemer-mutable), so that owner is listed too
  startRedemption: loanPolicy([OWN.paryonMutableLoanPrice, OWN.redeemerMinting, OWN.redeemerMutable]),
  liquidate: loanPolicy([OWN.paryonMutableLoanPrice, OWN.poolMinting]),
  // stability-pool functions
  addLiquidity: loanPolicy([OWN.poolMinting]),
  withdraw: loanPolicy([OWN.poolMinting]),
  newPeriod: loanPolicy([OWN.poolMintingFull, OWN.poolMutableCollector]), // creates a Payout
  payout: loanPolicy([OWN.poolMintingFull]),
  // borrowing + loanKey factory
  borrow: loanPolicy([OWN.paryonMintingBorrowing, OWN.paryonMutableLoanPrice]),
  loanKeyFactory: loanPolicy([OWN.loanKeyFactoryMinting]),
} satisfies Record<string, LeakPolicy>;

export interface UtxoSpec {
  script?: number;
  category?: number;
  capability?: number;
  fts?: number | Num;
  value?: number | Num;
  /** NFT commitment as an integer (used to pin function-NFT identifiers). */
  commitment?: number;
}

/** Mark a slot present and constrain the provided fields. */
export function pin(solver: Z3Solver, utxo: Utxo, spec: UtxoSpec): void {
  solver.add(utxo.present);
  if (spec.script !== undefined) solver.add(utxo.script.eq(spec.script));
  if (spec.category !== undefined) solver.add(utxo.category.eq(spec.category));
  if (spec.capability !== undefined) solver.add(utxo.capability.eq(spec.capability));
  if (spec.fts !== undefined) solver.add(utxo.fts.eq(spec.fts));
  if (spec.value !== undefined) solver.add(utxo.value.eq(spec.value));
  if (spec.commitment !== undefined) solver.add(utxo.commitment.eq(spec.commitment));
}

/** A loan input: paryon mutable NFT (no fungible) on the loan script. */
export function loanInput(solver: Z3Solver, utxo: Utxo): void {
  pin(solver, utxo, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.LOAN, fts: 0 });
}

/** A loan function NFT input: paryon immutable on the function'solver script, carrying its commitment id. */
export function functionNftInput(solver: Z3Solver, utxo: Utxo, scriptId: number, commitment?: number): void {
  pin(solver, utxo, { category: CAT.PARYON, capability: Capability.IMMUTABLE, script: scriptId, fts: 0, commitment });
}

/** A loan token sidecar input: a (user-facing) loanKey immutable NFT on the sidecar script. */
export function loanSidecarInput(solver: Z3Solver, utxo: Utxo, categoryId: number = CAT.LOANKEY): void {
  pin(solver, utxo, { category: categoryId, capability: Capability.IMMUTABLE, script: SCRIPT.LOAN_SIDECAR, fts: 0 });
}
