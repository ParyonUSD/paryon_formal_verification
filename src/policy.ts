import { Capability, Script, type SymbolicTx, type Utxo } from './model.js';
import { any, type Bool, type Z3 } from './z3.js';

/**
 * Ownership of a privileged (category, capability) pair: the set of covenant
 * script ids that may legitimately hold it. This encodes the *real* deployment
 * fact behind the inductive hypothesis — e.g. paryon-minting lives only on the
 * Borrowing contract, paryon-mutable only on price contracts and loans.
 *
 * Leaving a privileged pair out of the ownership list means "no covenant owns
 * it", i.e. it may not appear on any input at all.
 */
export interface OwnershipRule {
  category: number;
  /** MUTABLE or MINTING. */
  capability: number;
  scripts: number[];
}

/**
 * The capability-leak policy.
 *
 * `internalAuthorityCategories` are the categories whose *mutable or minting*
 * capability must never escape the system — in ParyonUSD these are four of the five
 * deploy categories (paryon, pool, redeemer, loanKeyFactory); the fifth, the oracle
 * migration key, is an admin trust assumption outside the proof (see README).
 *
 * The policy is per-(category, capability), NOT a blanket "no NFT escapes":
 *  - mutable/minting of an internal category  -> only covenant or BURN scripts
 *  - immutable of an internal category        -> may be user-held (receipts, sidecars)
 *  - any capability of a non-internal category (e.g. a per-loan loanKey, which
 *    is a deliberately user-held *minting* NFT) -> unconstrained here
 *
 * `ownership` pins, per template, which covenant owns each privileged pair (used
 * by the inductive hypothesis on inputs).
 */
export interface LeakPolicy {
  internalAuthorityCategories: number[];
  ownership: OwnershipRule[];
  /**
   * The function NFTs: immutable NFTs of an internal category with a commitment of a fixed short
   * length, which the loan / pool covenants accept as their delegated function by *shape alone*
   * (category + commitment length, never the script). Two obligations follow:
   *  - authenticity (part of the invariant): every NFT of that shape sits on one of the function
   *    scripts — a forged one on any other script would let its holder spend any loan/pool with no
   *    covenant logic. Assumed on inputs, checked on outputs by {@link forgedFunctionNftWitness}.
   *  - preservation (liveness): a function NFT that is spent is recreated in place, see
   *    {@link preservationWitness}. Losing one bricks that operation.
   * Optional; templates without it check the capability leak only.
   */
  functionNfts?: FunctionNftRule[];
}

/** A class of function NFTs: this category, immutable, this commitment length, only on these scripts. */
export interface FunctionNftRule {
  category: number;
  scripts: number[];
  commitmentLength: number;
}

/** True when a UTXO has the shape of a function NFT under `rule` (whatever script it sits on). */
function hasFunctionNftShape(z3: Z3, utxo: Utxo, rule: FunctionNftRule): Bool {
  return z3.And(
    utxo.present, utxo.category.eq(rule.category), utxo.capability.eq(Capability.IMMUTABLE),
    utxo.commitmentLength.eq(rule.commitmentLength),
  );
}
const onScripts = (z3: Z3, utxo: Utxo, scripts: number[]): Bool => any(z3, scripts.map((sc) => utxo.script.eq(sc)));

/** True when a UTXO carries an internal-authority category with mutable/minting capability. */
export function isInternalPrivileged(z3: Z3, utxo: Utxo, policy: LeakPolicy): Bool {
  const isInternal = any(z3, policy.internalAuthorityCategories.map((c) => utxo.category.eq(c)));
  const isPrivilegedCap = z3.Or(
    utxo.capability.eq(Capability.MUTABLE),
    utxo.capability.eq(Capability.MINTING),
  );
  return z3.And(utxo.present, isInternal, isPrivilegedCap);
}

/** True when this UTXO'solver (category, capability) is held by one of its rightful owner covenants. */
function ownedByCovenant(z3: Z3, utxo: Utxo, policy: LeakPolicy): Bool {
  return any(z3, policy.ownership.map((rule) =>
    z3.And(
      utxo.category.eq(rule.category),
      utxo.capability.eq(rule.capability),
      any(z3, rule.scripts.map((sc) => utxo.script.eq(sc))),
    ),
  ));
}

/**
 * The inductive hypothesis, asserted on inputs.
 *
 * The global invariant is "every UTXO carrying an internal-authority category
 * with mutable/minting capability sits on the covenant that owns it". The inputs
 * to this transaction existed *before* it, so under the induction they already
 * satisfy the invariant. Without this, the solver could hand the attacker (or a
 * wrong covenant) a privileged NFT and "leak" it trivially — a counterexample
 * that does not correspond to any reachable state.
 */
export function inputsRespectInvariant(z3: Z3, tx: SymbolicTx, policy: LeakPolicy): Bool {
  return z3.And(
    ...tx.inputs.map((utxo) => z3.Implies(isInternalPrivileged(z3, utxo, policy), ownedByCovenant(z3, utxo, policy))),
    // Function-NFT authenticity: anything of that shape sits on a function script.
    ...tx.inputs.flatMap((utxo) => (policy.functionNfts ?? []).map((rule) =>
      z3.Implies(hasFunctionNftShape(z3, utxo, rule), onScripts(z3, utxo, rule.scripts)))),
  );
}

/**
 * The forged-function-NFT witness: satisfiable exactly when some output has the shape of a function
 * NFT but sits on neither a function script nor a burn. Such an output is the second half of the
 * invariant the induction needs (the first being {@link leakWitness}): the loan and pool covenants
 * authenticate their delegate by shape alone, so a forged one anywhere else is full authority over
 * every loan / the pool. Query it with {@link preservedInputsOnlyAt}, like the preservation witness:
 * an ungoverned input of that shape is impossible on chain (it can only be spent by its covenant).
 */
export function forgedFunctionNftWitness(z3: Z3, tx: SymbolicTx, policy: LeakPolicy): Bool {
  return any(z3, tx.outputs.flatMap((out) => (policy.functionNfts ?? []).map((rule) => z3.And(
    hasFunctionNftShape(z3, out, rule),
    z3.Not(out.script.eq(Script.BURN)),
    z3.Not(onScripts(z3, out, rule.scripts)),
  ))));
}

/**
 * Restrict the privileged-input set to the designated covenant participants.
 *
 * On-chain, a UTXO carrying an internal mutable/minting capability can only be
 * spent by running the covenant that governs it (a loan needs its loan-function
 * machinery, the collector needs Collector.collect, etc.), which in turn pins
 * that UTXO'solver output. A model that lets the solver add an extra "ghost"
 * privileged input — owned by the right script but governed by nothing — would
 * inflate the tally and report spurious leaks on templates without an output
 * cap. This pins which input indices may carry a privileged capability; every
 * other input is non-privileged.
 *
 * Soundness note: this scopes each loan-function check to its canonical single-
 * operation transaction shape. Batching several governed loans into one tx is a
 * distinct (larger) template in which each loan is still individually pinned.
 */
export function privilegedInputsOnlyAt(z3: Z3, tx: SymbolicTx, policy: LeakPolicy, allowed: number[]): Bool {
  return z3.And(
    ...tx.inputs.map((utxo, i) =>
      allowed.includes(i) ? z3.Bool.val(true) : z3.Not(isInternalPrivileged(z3, utxo, policy)),
    ),
  );
}

/**
 * The preservation counterpart of {@link privilegedInputsOnlyAt}: an immutable NFT of a preserved class
 * sits on a covenant script, so spending it means running that covenant, which recreates it (that is
 * what its own template proves). In a template that does not run it, such an input cannot occur; without
 * this restriction the solver adds an ungoverned function NFT as an extra input and reports it lost.
 * `governed` is every input index whose covenant this template interprets or designates.
 */
export function preservedInputsOnlyAt(z3: Z3, tx: SymbolicTx, policy: LeakPolicy, governed: number[]): Bool {
  const rules = policy.functionNfts ?? [];
  return z3.And(
    ...tx.inputs.map((utxo, i) =>
      governed.includes(i) ? z3.Bool.val(true) : z3.Not(any(z3, rules.map((rule) => z3.And(
        utxo.present, utxo.category.eq(rule.category), utxo.capability.eq(Capability.IMMUTABLE),
        z3.Or(onScripts(z3, utxo, rule.scripts), utxo.commitmentLength.eq(rule.commitmentLength)),
      ))))),
  );
}

/**
 * The preservation witness: satisfiable exactly when some input matches a preservation rule (an
 * immutable NFT of that category on one of its scripts) and no output recreates it — same category,
 * still immutable, same script, same commitment. Assert alongside consensus + covenants, expect UNSAT.
 */
export function preservationWitness(z3: Z3, tx: SymbolicTx, policy: LeakPolicy): Bool {
  const rules = policy.functionNfts ?? [];
  return any(z3, tx.inputs.flatMap((input) => rules.map((rule) => {
    const matches = z3.And(
      input.present, input.category.eq(rule.category), input.capability.eq(Capability.IMMUTABLE),
      onScripts(z3, input, rule.scripts),
    );
    const recreated = any(z3, tx.outputs.map((out) => z3.And(
      out.present, out.category.eq(rule.category), out.capability.eq(Capability.IMMUTABLE),
      out.script.eq(input.script), out.commitment.eq(input.commitment),
      out.commitmentLength.eq(input.commitmentLength),
    )));
    return z3.And(matches, z3.Not(recreated));
  })));
}

/**
 * The leak witness: satisfiable exactly when some output carries a privileged capability that is
 * neither burned (an OP_RETURN output is never spent again) nor held by a covenant that rightfully
 * owns it. Assert it alongside the consensus + covenant constraints and expect UNSAT; a SAT result is
 * a concrete counterexample transaction.
 *
 * This is *invariant preservation*, not merely "no attacker output": the induction assumes
 * `inputsRespectInvariant` on the inputs, so the outputs must be shown to satisfy the same
 * ownership invariant. A privileged NFT parked on the wrong covenant is not spendable by the attacker
 * today, but the wrong covenant's code does not protect it, and no template analyses that spend —
 * which is why it counts as a leak here. The per-template `ownership` list is therefore the reviewed
 * specification of where each capability may legitimately end up.
 */
export function leakWitness(z3: Z3, tx: SymbolicTx, policy: LeakPolicy): Bool {
  return any(z3, tx.outputs.map((utxo) =>
    z3.And(
      isInternalPrivileged(z3, utxo, policy),
      z3.Not(utxo.script.eq(Script.BURN)),
      z3.Not(ownedByCovenant(z3, utxo, policy)),
    ),
  ));
}
