import { Capability, MAX_CATEGORY, MAX_SCRIPT, NO_CATEGORY, Script, type SymbolicTx, type Utxo } from './model.js';
import { any, countIf, type Bool, type Num, type Z3, type Z3Solver } from './z3.js';

/** Consensus maximum NFT commitment length (BCH 2026 rules). */
const MAX_COMMITMENT_LENGTH = 128;

// This models only the part of CashTokens validation that governs NFT movement (the per-category
// token tally incl. immutable-commitment matching + structural rules). It deliberately omits BCH
// value/fee conservation, fungible amounts, standardness/dust, timelocks and signatures, none of which
// can move a capability. See docs/scope.md for the full "what is / isn't checked" and why that is
// sound for a leak-freedom proof.

/**
 * Structural well-formedness + presence/contiguity. "Absent" slots are pinned to
 * no-token so they cannot masquerade as carrying a capability; present slots must
 * respect category <-> token consistency.
 */
function addStructure(z3: Z3, out: Bool[], slots: Utxo[]): void {
  slots.forEach((utxo, i) => {
    out.push(utxo.capability.ge(Capability.NONE), utxo.capability.le(Capability.MINTING));
    // Finite enum domains for category/script (essential for solver performance).
    out.push(utxo.category.ge(0), utxo.category.le(MAX_CATEGORY));
    out.push(utxo.script.ge(0), utxo.script.le(MAX_SCRIPT));
    out.push(utxo.commitmentLength.ge(0), utxo.commitmentLength.le(MAX_COMMITMENT_LENGTH));
    out.push(utxo.commitmentHead.ge(0), utxo.commitmentHead.le(0xff));
    // An empty commitment has no first byte and reads as the integer 0; a one-byte commitment's int
    // reading IS its byte, sign-magnitude (0x81 reads as -1, 0x80 as 0).
    out.push(z3.Implies(utxo.commitmentLength.eq(0), z3.And(utxo.commitment.eq(0), utxo.commitmentHead.eq(0))));
    out.push(z3.Implies(
      utxo.commitmentLength.eq(1),
      utxo.commitment.eq(z3.If(utxo.commitmentHead.ge(0x80), utxo.commitmentHead.neg().add(0x80), utxo.commitmentHead)),
    ));

    const hasNft = utxo.capability.ge(Capability.IMMUTABLE);
    const hasToken = z3.Or(hasNft, utxo.fts.gt(0));

    out.push(
      z3.If(
        utxo.present,
        z3.And(
          utxo.fts.ge(0),
          z3.Eq(utxo.category.neq(NO_CATEGORY), hasToken),
          // A UTXO without an NFT has no commitment: introspection pushes the empty string (int 0, length 0).
          z3.Implies(z3.Not(hasNft), z3.And(utxo.commitment.eq(0), utxo.commitmentLength.eq(0))),
        ),
        z3.And(
          utxo.category.eq(NO_CATEGORY),
          utxo.fts.eq(0),
          utxo.capability.eq(Capability.NONE),
          utxo.script.eq(Script.ATTACKER),
          utxo.commitment.eq(0),
        ),
      ),
    );

    // Contiguity: a present slot implies the previous slot is present, so the
    // input/output count is a well-defined prefix.
    const prev = slots[i - 1];
    if (prev) out.push(z3.Implies(utxo.present, prev.present));
  });
}

/**
 * Outpoint structure for the inputs (outputs have no outpoint).
 *
 * Two facts, both faithful:
 *  - an outpoint index is a non-negative output index;
 *  - no transaction spends the same outpoint twice, so the (txid, index) pairs of the present inputs
 *    are pairwise distinct.
 *
 * The txid is modelled as an equality-only identity bounded to `0 .. nIn-1`. The covenants only ever
 * compare two inputs' `outpointTransactionHash` to each other, so all that is observable is the
 * partition of the inputs into "came from the same transaction" classes, and every partition of n
 * inputs is realisable with n values: the bound excludes no transaction the model can distinguish.
 * The index is left unbounded above so a contract comparing it against any value stays modelled.
 */
function addOutpointRules(z3: Z3, out: Bool[], tx: SymbolicTx): void {
  const inputs = tx.inputs;
  inputs.forEach((utxo, i) => {
    out.push(utxo.outpointIndex.ge(0));
    out.push(utxo.outpointTx.ge(0), utxo.outpointTx.le(Math.max(inputs.length - 1, 0)));
    for (let j = 0; j < i; j++) {
      const other = inputs[j]!;
      out.push(z3.Implies(
        z3.And(utxo.present, other.present),
        z3.Or(utxo.outpointTx.neq(other.outpointTx), utxo.outpointIndex.neq(other.outpointIndex)),
      ));
    }
  });
}

function isCat(utxo: Utxo, cat: number): Bool {
  return utxo.category.eq(cat);
}
function nftOfCat(z3: Z3, utxo: Utxo, cat: number): Bool {
  return z3.And(utxo.present, isCat(utxo, cat), utxo.capability.ge(Capability.IMMUTABLE));
}
function capOfCat(z3: Z3, utxo: Utxo, cat: number, capability: number): Bool {
  return z3.And(utxo.present, isCat(utxo, cat), utxo.capability.eq(capability));
}

/**
 * The CashTokens NFT token-validation tally, per category — the trusted base.
 *
 * For a category with NO minting input (genesis excluded; see note):
 *   1. minting_out == 0                  (cannot create minting capability)
 *   2. mutable_out <= mutable_in         (cannot create/duplicate mutable NFTs)
 *   3. nft_out     <= nft_in             (cannot create NFTs of a category with no NFT inputs)
 *
 *   4. every immutable output NFT is either matched to a distinct immutable input NFT of the
 *      same category with an identical commitment, or consumes one mutable input:
 *      mutable_out + unmatched_immutable_out <= mutable_in   (see addImmutableMatching)
 *
 * A minting input lifts all four for that category (unlimited NFTs of any
 * capability), so such contracts must instead bound their outputs explicitly.
 *
 * Genesis note: a brand-new category can be minted by an input whose outpoint
 * index is 0. We do not model outpoints; we assume no analysed transaction
 * genesis-creates a privileged category (their ids are historical/unforgeable).
 *
 * Fungible-token conservation is intentionally omitted: fungible tokens carry no
 * capability, so they are irrelevant to leak-freedom (a separate property).
 */
function addTokenTally(z3: Z3, out: Bool[], tx: SymbolicTx, categories: number[]): void {
  for (const cat of categories) {
    const hasMintingIn = any(z3, tx.inputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MINTING)));

    const mintingOut = countIf(z3, tx.outputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MINTING)));
    const mutableIn = countIf(z3, tx.inputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MUTABLE)));
    const mutableOut = countIf(z3, tx.outputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MUTABLE)));
    const nftIn = countIf(z3, tx.inputs.map((utxo) => nftOfCat(z3, utxo, cat)));
    const nftOut = countIf(z3, tx.outputs.map((utxo) => nftOfCat(z3, utxo, cat)));

    out.push(z3.Implies(z3.Not(hasMintingIn), mintingOut.eq(0)));
    out.push(z3.Implies(z3.Not(hasMintingIn), mutableOut.le(mutableIn)));
    out.push(z3.Implies(z3.Not(hasMintingIn), nftOut.le(nftIn)));
  }
}

/**
 * Rule 4, the immutable-commitment matching of CashTokens validation, encoded exactly (up to the
 * model's commitment identity, which is the int reading plus the byte length — a coarsening of real
 * byte identity, so the model matches at least everything the chain matches: a sound superset).
 *
 * A boolean match matrix `m[j][i]` ("output j is matched to input i"): a match requires a present
 * immutable input of the same category with the same commitment; every input is matched by at most
 * one output and every output by at most one input; an output the rule does not govern (not
 * immutable, not a tallied category, or its category has a minting input) matches nothing. Per
 * category without a minting input, the unmatched immutable outputs plus the mutable outputs may not
 * exceed the mutable inputs. (Booleans + cardinality sums keep this cheap for Z3; an earlier encoding
 * with integer source variables and pairwise inequalities sent the manage build over its memory.)
 *
 * This is the rule that makes a *forged* immutable NFT impossible: without a minting input, an
 * immutable NFT with a fresh commitment can only come from spending a mutable one of that category.
 */
function addImmutableMatching(z3: Z3, rules: Bool[], tx: SymbolicTx, categories: number[]): void {
  const hasMintingIn = (cat: Num): Bool =>
    any(z3, tx.inputs.map((utxo) =>
      z3.And(utxo.present, utxo.category.eq(cat), utxo.capability.eq(Capability.MINTING))));
  const isImmutable = (utxo: Utxo): Bool => z3.And(utxo.present, utxo.capability.eq(Capability.IMMUTABLE));
  const tallied = (utxo: Utxo): Bool => any(z3, categories.map((cat) => utxo.category.eq(cat)));

  const m = tx.outputs.map((_, j) => tx.inputs.map((__, i) => z3.Bool.const(`${tx.prefix}out${j}.matches.in${i}`)));
  tx.outputs.forEach((out, j) => {
    const governed = z3.And(isImmutable(out), tallied(out), z3.Not(hasMintingIn(out.category)));
    tx.inputs.forEach((input, i) => {
      rules.push(z3.Implies(m[j]![i]!, z3.And(
        governed, isImmutable(input), input.category.eq(out.category),
        input.commitment.eq(out.commitment), input.commitmentLength.eq(out.commitmentLength),
      )));
    });
    rules.push(countIf(z3, m[j]!).le(1));
  });
  tx.inputs.forEach((_, i) => rules.push(countIf(z3, m.map((row) => row[i]!)).le(1)));
  for (const cat of categories) {
    const unmatchedOut = countIf(z3, tx.outputs.map((out, j) =>
      z3.And(isImmutable(out), out.category.eq(cat), z3.Not(any(z3, m[j]!)))));
    const mutableIn = countIf(z3, tx.inputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MUTABLE)));
    const mutableOut = countIf(z3, tx.outputs.map((utxo) => capOfCat(z3, utxo, cat, Capability.MUTABLE)));
    rules.push(z3.Implies(z3.Not(hasMintingIn(z3.Int.val(cat))), mutableOut.add(unmatchedOut).le(mutableIn)));
  }
}

/**
 * Add the consensus capability model for a transaction. `categories` is the
 * finite set of concrete category ids the tally is enforced over (Z3 cannot
 * range over the unbounded category domain symbolically).
 */
export function addConsensusRules(z3: Z3, solver: Z3Solver, tx: SymbolicTx, categories: number[]): void {
  solver.add(...consensusRules(z3, tx, categories));
}

/**
 * The consensus rules as a list of constraints, built once per transaction. A build with several
 * path solvers adds the same expressions to each of them: z3-solver's wasm bindings are fragile under
 * heavy expression allocation (crashes in the AST manager were observed when every solver rebuilt
 * these), so sharing the objects is a robustness measure, not just an optimisation.
 */
export function consensusRules(z3: Z3, tx: SymbolicTx, categories: number[]): Bool[] {
  const out: Bool[] = [];
  addStructure(z3, out, tx.inputs);
  addStructure(z3, out, tx.outputs);
  addOutpointRules(z3, out, tx);
  addTokenTally(z3, out, tx, categories);
  addImmutableMatching(z3, out, tx, categories);
  return out;
}
