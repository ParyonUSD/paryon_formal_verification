import { Capability, MAX_CATEGORY, MAX_SCRIPT, NO_CATEGORY, Script, type SymbolicTx, type Utxo } from './model.js';
import { any, countIf, type Bool, type Z3, type Z3Solver } from './z3.js';

// This models only the part of CashTokens validation that governs NFT-capability movement (the
// per-category token tally + structural rules). It deliberately omits BCH value/fee conservation,
// fungible amounts, standardness/dust, commitment contents, timelocks and signatures, none of which
// can move a capability. See docs/scope.md for the full "what is / isn't checked" and why that is
// sound for a leak-freedom proof.

/**
 * Structural well-formedness + presence/contiguity. "Absent" slots are pinned to
 * no-token so they cannot masquerade as carrying a capability; present slots must
 * respect category <-> token consistency.
 */
function addStructure(z3: Z3, s: Z3Solver, slots: Utxo[]): void {
  slots.forEach((u, i) => {
    s.add(u.capability.ge(Capability.NONE), u.capability.le(Capability.MINTING));
    // Finite enum domains for category/script (essential for solver performance).
    s.add(u.category.ge(0), u.category.le(MAX_CATEGORY));
    s.add(u.script.ge(0), u.script.le(MAX_SCRIPT));

    const hasNft = u.capability.ge(Capability.IMMUTABLE);
    const hasToken = z3.Or(hasNft, u.fts.gt(0));

    s.add(
      z3.If(
        u.present,
        z3.And(u.fts.ge(0), z3.Eq(u.category.neq(NO_CATEGORY), hasToken)),
        z3.And(
          u.category.eq(NO_CATEGORY),
          u.fts.eq(0),
          u.capability.eq(Capability.NONE),
          u.script.eq(Script.ATTACKER),
          u.commitment.eq(0),
        ),
      ),
    );

    // Contiguity: a present slot implies the previous slot is present, so the
    // input/output count is a well-defined prefix.
    const prev = slots[i - 1];
    if (prev) s.add(z3.Implies(u.present, prev.present));
  });
}

function isCat(u: Utxo, cat: number): Bool {
  return u.category.eq(cat);
}
function nftOfCat(z3: Z3, u: Utxo, cat: number): Bool {
  return z3.And(u.present, isCat(u, cat), u.capability.ge(Capability.IMMUTABLE));
}
function capOfCat(z3: Z3, u: Utxo, cat: number, capability: number): Bool {
  return z3.And(u.present, isCat(u, cat), u.capability.eq(capability));
}

/**
 * The CashTokens NFT token-validation tally, per category — the trusted base.
 *
 * For a category with NO minting input (genesis excluded; see note):
 *   1. minting_out == 0                  (cannot create minting capability)
 *   2. mutable_out <= mutable_in         (cannot create/duplicate mutable NFTs)
 *   3. nft_out     <= nft_in             (cannot create NFTs of a category with no NFT inputs)
 *
 * A minting input lifts all three for that category (unlimited NFTs of any
 * capability), so such contracts must instead bound their outputs explicitly.
 *
 * Genesis note: a brand-new category can be minted by an input whose outpoint
 * index is 0. We do not model outpoints; we assume no analysed transaction
 * genesis-creates a privileged category (their ids are historical/unforgeable).
 *
 * Fungible-token conservation is intentionally omitted: fungible tokens carry no
 * capability, so they are irrelevant to leak-freedom (a separate property).
 */
function addTokenTally(z3: Z3, s: Z3Solver, tx: SymbolicTx, categories: number[]): void {
  for (const cat of categories) {
    const hasMintingIn = any(z3, tx.inputs.map((u) => capOfCat(z3, u, cat, Capability.MINTING)));

    const mintingOut = countIf(z3, tx.outputs.map((u) => capOfCat(z3, u, cat, Capability.MINTING)));
    const mutableIn = countIf(z3, tx.inputs.map((u) => capOfCat(z3, u, cat, Capability.MUTABLE)));
    const mutableOut = countIf(z3, tx.outputs.map((u) => capOfCat(z3, u, cat, Capability.MUTABLE)));
    const nftIn = countIf(z3, tx.inputs.map((u) => nftOfCat(z3, u, cat)));
    const nftOut = countIf(z3, tx.outputs.map((u) => nftOfCat(z3, u, cat)));

    s.add(z3.Implies(z3.Not(hasMintingIn), mintingOut.eq(0)));
    s.add(z3.Implies(z3.Not(hasMintingIn), mutableOut.le(mutableIn)));
    s.add(z3.Implies(z3.Not(hasMintingIn), nftOut.le(nftIn)));
  }
}

/**
 * Add the consensus capability model for a transaction. `categories` is the
 * finite set of concrete category ids the tally is enforced over (Z3 cannot
 * range over the unbounded category domain symbolically).
 */
export function addConsensusRules(z3: Z3, s: Z3Solver, tx: SymbolicTx, categories: number[]): void {
  addStructure(z3, s, tx.inputs);
  addStructure(z3, s, tx.outputs);
  addTokenTally(z3, s, tx, categories);
}
