/**
 * Abstract identity ids for token categories and locking scripts.
 *
 * These integers are NOT contract data: a real tokenId is 32 random bytes and a
 * real locking script is ~35-byte P2SH32, but the leak property only ever needs
 * *identity* (which category/script equals which). Distinct small ints capture
 * that exactly and keep the solver in a tiny finite domain. The actual bytes are
 * checked separately, on chain, by `verify_contract_deployment`.
 *
 * Values are arbitrary; only their distinctness matters. The bounds in model.ts
 * (`MAX_CATEGORY` / `MAX_SCRIPT`) must stay above the largest id used here.
 */

/** Token-category ids. The internal-authority categories are paryon/pool/redeemer/loanKeyFactory. */
export const CAT = {
  PARYON: 1, // internal authority
  POOL: 2, // internal authority (stabilityPool minting, collector mutable, receipts immutable)
  REDEEMER: 3, // internal authority (redeemer minting, redemption mutable) == redemptionTokenId
  LOANKEY_FACTORY: 4, // internal authority (the loanKey factory minting NFT)
  // per-loan loanKey categories — user-facing (the minting loanKey is held by the user)
  LOANKEY: 10,
  LOANKEY_2: 11, // a second loan's key (swap templates involve two loans)
} as const;

/** Locking-script ids (>= Script.FIRST_COVENANT are system covenants). */
export const SCRIPT = {
  LOAN: 2,
  PRICE: 3,
  LOAN_SIDECAR: 4,
  // loan function NFTs (paryon immutable, single-byte commitment) — distinct covenant scripts
  FN_LIQUIDATE: 5,
  FN_MANAGE: 6,
  FN_REDEEM: 7,
  FN_START_REDEMPTION: 8,
  FN_SWAP_IN: 9,
  FN_SWAP_OUT: 10,
  FN_PAY_INTEREST: 11,
  FN_CHANGE_INTEREST: 12,
  // stability pool subsystem
  STABILITY_POOL: 13,
  POOL_SIDECAR: 14,
  COLLECTOR: 15,
  FN_LIQUIDATELOAN: 16, // stability pool function NFTs
  // redeemer subsystem
  REDEEMER: 17,
  REDEMPTION: 18,
  REDEMPTION_SIDECAR: 19,
  // more stability pool subsystem
  PAYOUT: 20,
  PROTOCOL_FEE: 21, // external protocol-fee address (BCH only)
  FN_ADD_LIQUIDITY: 22,
  FN_WITHDRAW: 23,
  FN_NEW_PERIOD: 24,
  // borrowing + loanKey factory subsystem
  BORROWING: 25,
  FEE: 26, // external borrowing-fee address (BCH only)
  ORIGIN_ENFORCER: 27,
  ORIGIN_PROOF: 28,
  LOANKEY_FACTORY: 29,
} as const;
