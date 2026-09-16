import type { Bool, Num, Z3 } from './z3.js';

/**
 * NFT capability, encoded as an integer so the consensus tally can do
 * arithmetic over it. `NONE` (-1) means "no NFT on this UTXO".
 *
 * The on-chain introspection encoding concatenates the 1-byte capability onto
 * the 32-byte category; we model the (category, capability) pair instead of the
 * raw 32/33-byte string, which is the faithful and far cheaper representation.
 */
export const Capability = {
  NONE: -1,
  IMMUTABLE: 0,
  MUTABLE: 1,
  MINTING: 2,
} as const;

/** Category id 0 is reserved for "no token category" (pure BCH UTXO). */
export const NO_CATEGORY = 0;

/**
 * Category and script ids are enums modelled as integers. Bounding them to a
 * finite range is essential for performance: it turns the solver's search over
 * free outputs from an unbounded-integer problem into a finite one. The bounds
 * only need to cover every id the registry assigns; the attacker can still pick
 * any value in range (including internal categories and the ATTACKER script), so
 * bounding never hides a leak.
 */
export const MAX_CATEGORY = 31;
export const MAX_SCRIPT = 63;

/**
 * Reserved locking-script ids. Real system covenant scripts get ids >= 2,
 * assigned by the caller (e.g. one per ParyonUSD contract instance).
 *
 *  - ATTACKER: any script the attacker controls, i.e. NOT a system covenant
 *    and NOT a burn. A privileged mutable/minting NFT reaching this script is
 *    exactly the leak we are hunting.
 *  - BURN: a provably-unspendable OP_RETURN nulldata output. Safe destination,
 *    but it still consumes an NFT slot in the consensus tally.
 */
export const Script = {
  ATTACKER: 0,
  BURN: 1,
  FIRST_COVENANT: 2,
} as const;

/** A single symbolic UTXO (transaction input or output). */
export interface Utxo {
  /** BCH amount in satoshis. */
  value: Num;
  /** Token category id (NO_CATEGORY when no token is present). */
  category: Num;
  /** Fungible token amount. */
  fts: Num;
  /** NFT capability (see {@link Capability}). */
  capability: Num;
  /** Locking-script id (see {@link Script}). */
  script: Num;
  /**
   * NFT commitment, modelled as an integer. We only resolve it where a contract
   * branches on a small constant (function-NFT identifiers like `commitment == 0x02`);
   * everything else treats it opaquely (split/reconstruct contribute no constraint).
   */
  commitment: Num;
  /**
   * NFT commitment byte length (0 when there is no NFT). Together with the int reading it makes
   * commitment identity nearly injective (only negative-zero encodings collide), and it is what
   * `commitment.length == 1` — the function-NFT shape the covenants authenticate by — talks about.
   */
  commitmentLength: Num;
  /**
   * Identity of the transaction this UTXO was created by (its outpoint's txid), as a small int.
   * **Inputs only** — an output has no outpoint yet, so the field is declared but never constrained
   * or read for output slots.
   *
   * Like category/script ids this is an equality-only identity: the covenants compare two inputs'
   * `outpointTransactionHash` and nothing else, and any equality pattern over n inputs is realisable
   * with n distinct values, so the bounded domain (see `addOutpointRules`) loses nothing.
   */
  outpointTx: Num;
  /** The outpoint's output index (>= 0). Inputs only, like {@link Utxo.outpointTx}. */
  outpointIndex: Num;
  /** Whether this slot is actually used by the transaction. */
  present: Bool;
}

/** A symbolic transaction: fixed-capacity input and output vectors. */
export interface SymbolicTx {
  inputs: Utxo[];
  outputs: Utxo[];
  /** This transaction's symbol namespace (see declareTx); auxiliary variables use it too. */
  prefix: string;
}

// Every declared transaction gets its own symbol namespace. Z3 identifies constants by name, so two
// builds in one context sharing `in0.category` share the constant and everything the context caches
// about it; with unique names each build is a fresh problem to the solver.
let txCounter = 0;

function declareUtxo(z3: Z3, prefix: string, kind: 'in' | 'out', i: number): Utxo {
  const name = (field: string) => `${prefix}${kind}${i}.${field}`;
  return {
    value: z3.Int.const(name('value')),
    category: z3.Int.const(name('category')),
    fts: z3.Int.const(name('fts')),
    capability: z3.Int.const(name('capability')),
    script: z3.Int.const(name('script')),
    commitment: z3.Int.const(name('commitment')),
    commitmentLength: z3.Int.const(name('commitmentLength')),
    outpointTx: z3.Int.const(name('outpointTx')),
    outpointIndex: z3.Int.const(name('outpointIndex')),
    present: z3.Bool.const(name('present')),
  };
}

/**
 * Declare a fresh symbolic transaction with `nIn` input slots and `nOut` output
 * slots. No constraints are added here; call {@link addConsensusRules} next.
 */
export function declareTx(z3: Z3, nIn: number, nOut: number): SymbolicTx {
  const prefix = `t${txCounter++}.`;
  return {
    inputs: Array.from({ length: nIn }, (_, i) => declareUtxo(z3, prefix, 'in', i)),
    outputs: Array.from({ length: nOut }, (_, i) => declareUtxo(z3, prefix, 'out', i)),
    prefix,
  };
}
