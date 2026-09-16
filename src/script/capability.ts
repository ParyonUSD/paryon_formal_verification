import { Capability, NO_CATEGORY, Script, type SymbolicTx } from '../model.js';
import type { Bool, Num, Z3 } from '../z3.js';
import { Op } from './script.js';
import { bytesToNum, leadingByte, type SVal } from './value.js';

/**
 * The capability-abstraction layer: it interprets the interpreter'solver symbolic stack
 * values (see value.ts) as capability constraints, and decides what is even relevant.
 *
 * Its obligation is *conservativeness*, not faithfulness: it emits a Z3 constraint
 * ONLY for the comparisons that can move an NFT capability — token-category equality
 * (-> category + capability class), locking-bytecode equality (-> script id),
 * output/input-count comparisons, and the small commitment branches that select a
 * function-NFT. Everything else (BCH values, token amounts, commitment contents,
 * arithmetic, hashes, signatures) yields `null` and contributes no constraint.
 * Dropping a constraint only ever *widens* the modelled transaction set, so UNSAT on
 * the model implies UNSAT on-chain — the leak-freedom proof stays sound. (The dual
 * obligation, that the stack routing feeding these decisions is *faithful*, belongs to
 * the interpreter/value layers; this layer trusts the SVal it is handed.)
 *
 * This is the ParyonUSD-leaning half of the interpreter: what counts as a category
 * vs a script vs a genesis mint, and how capability classes are encoded.
 */

// Category id base for genesis-minted categories (per genesis input index). Distinct from the
// registry'solver category ids and outside the tallied/internal sets — a fresh, user-facing category.
// (LoanKeyFactory mints one as reservedTokenId + 0x02.)
const GENESIS_BASE = 20;
// Suffix classes of a category-like byte string, i.e. what `tokenCategory` (+ an appended capability
// byte) can serialise to. 0..3 are the introspection results; 4..9 arise only from appending a byte
// to a non-bare base and equal no introspection result, but two such strings can equal each other.
//   0: empty          1: bare 32 bytes     2: cat+01          3: cat+02
//   4: "01" alone     5: "02" alone        6: cat+01+01       7: cat+01+02
//   8: cat+02+01      9: cat+02+02
// The class of `base + suffix`, by base class (0..3) and suffix byte (01 / 02):
const APPEND_CLASS: Record<number, Record<number, number>> = {
  0: { [Capability.MUTABLE]: 4, [Capability.MINTING]: 5 },
  1: { [Capability.MUTABLE]: 2, [Capability.MINTING]: 3 },
  2: { [Capability.MUTABLE]: 6, [Capability.MINTING]: 7 },
  3: { [Capability.MUTABLE]: 8, [Capability.MINTING]: 9 },
};
// Commitment constants longer than this are not read as an integer (the model's commitment abstraction
// only ever needs the single-byte function identifiers; longer constants fall outside exact-int range).
const MAX_COMMITMENT_CONST_BYTES = 6;
/** `constSuffixClass`: the constant is the capability suffix of no tokenCategory at all. */
const NO_SUFFIX = -1;

/**
 * The result of a modelled equality. `e` is null when the compare cannot move a capability. `lossy`
 * marks `e` as a *necessary* condition only: a script id stands for a class of scripts (every P2PKH is
 * ATTACKER, every nulldata is BURN, every instance of a covenant shares its id) and a commitment int
 * identifies several byte strings (`0x` and `0x00` both read as 0), so `e` is implied by the real byte
 * equality but does not imply it. The interpreter asserts a lossy `e` only where the script requires
 * the comparison true; asserting `¬e` (under OP_NOT, or on the untaken side of a branch) would exclude
 * real transactions — an unsoundness the superset argument does not protect against. Category
 * equality is exact (category ids and suffix classes are exact identities) and so never lossy.
 */
export interface EqualityResult { e: Bool | null; lossy: boolean }

/** Interprets stack values as capability-relevant constraints for a given transaction. */
export interface CapabilityModel {
  /** A capability-relevant equality (`OP_EQUAL`/`OP_EQUALVERIFY`); see {@link EqualityResult}. */
  equalConstraint(a: SVal, b: SVal): EqualityResult;
  /** The result of `OP_NUMEQUAL`(`VERIFY`): a count/value/amount/selector comparison as a bool SVal. */
  numEqResult(a: SVal, b: SVal): SVal;
  /** The result of a numeric ordering compare (`OP_LESSTHAN` etc.) as a bool SVal. */
  compare(op: number, top: SVal, second: SVal): SVal;
  /** The byte length of a stack value as a model Int (`OP_SIZE`), or null when unknown. */
  lengthOf(v: SVal): Num | null;
  /**
   * The numeric value of a stack item as a model Int, or null when it is not a resolvable number.
   * Used by the interpreter's linear arithmetic (`OP_ADD`/`OP_1ADD`/... against a constant).
   */
  numValue(v: SVal): Num | null;
}

export function makeCapabilityModel(z3: Z3, tx: SymbolicTx, activeIndex: number): CapabilityModel {
  const outCount = countPresent(z3, tx, 'out');
  const inCount = countPresent(z3, tx, 'in');

  const exact = (e: Bool): EqualityResult => ({ e, lossy: false });
  const lossy = (e: Bool): EqualityResult => ({ e, lossy: true });
  const NONE: EqualityResult = { e: null, lossy: false };

  const eqInt = (a: Num | number, b: Num | number): Bool => {
    if (typeof a === 'number' && typeof b === 'number') return z3.Bool.val(a === b);
    return (typeof a === 'number' ? (b as Num).eq(a) : (a as Num).eq(b));
  };

  // ---- token-category interpretation ----
  // We compare the *byte serialisation* of tokenCategory, captured as (catId, suffix class):
  //   0 = empty (no token), 1 = bare 32-byte (immutable NFT *or* fungible-only — indistinguishable),
  //   2 = +0x01 (mutable), 3 = +0x02 (minting).
  /** Suffix class of a model slot'solver tokenCategory as a Z3 Int. */
  const catClass = (i: number, side: 'in' | 'out'): Num => {
    const utxo = side === 'in' ? tx.inputs[i]! : tx.outputs[i]!;
    return z3.If(utxo.category.eq(NO_CATEGORY), z3.Int.val(0),
      z3.If(utxo.capability.le(Capability.IMMUTABLE), z3.Int.val(1),
        z3.If(utxo.capability.eq(Capability.MUTABLE), z3.Int.val(2), z3.Int.val(3))));
  };

  type CatView = { catId: Num | number; cls: Num | number };
  function catView(v: SVal): CatView | null {
    if (v.k === 'field' && v.f === 'utxoCat') return { catId: tx.inputs[v.i]!.category, cls: catClass(v.i, 'in') };
    if (v.k === 'field' && v.f === 'outCat') return { catId: tx.outputs[v.i]!.category, cls: catClass(v.i, 'out') };
    if (v.k === 'split' && v.at === 32 && v.side === 'L') {
      const inner = catView(v.v);
      if (inner) return { catId: inner.catId, cls: 1 }; // split(32)[0] is always 32 bytes (bare)
    }
    if (v.k === 'cat' && v.parts.length === 2) {
      const [a, b] = v.parts;
      // Base category: another category view, or a bare outpoint txhash used to mint a brand-new
      // genesis category (LoanKeyFactory: reservedTokenId + 0x02). Appending a capability byte yields
      // a real category string only when the base is *bare* (class 1: a split(32)[0], a tokenId seed,
      // or a raw field of a UTXO carrying an immutable NFT / fungible-only token); any other base
      // class maps to one of the non-category classes 4..9 (see APPEND_CLASS), which keeps equality
      // exact: `0x + 02` equals `0x + 02` but never a category, and never `0x + 01`.
      const base = catView(a!);
      const baseCatId = base?.catId ?? (a!.k === 'outpoint' ? GENESIS_BASE + a!.i : null);
      const suffix = b!.k === 'bytes' && b!.v.length === 1 && (b!.v[0] === Capability.MUTABLE || b!.v[0] === Capability.MINTING)
        ? b!.v[0] : null;
      if (baseCatId !== null && suffix !== null) {
        const baseCls: Num | number = base ? base.cls : 1; // an outpoint txhash is always bare
        if (typeof baseCls === 'number') {
          const cls = APPEND_CLASS[baseCls]?.[suffix];
          return cls === undefined ? null : { catId: baseCatId, cls }; // a doubly-suffixed base: not modelled
        }
        // A field's class is always 0..3, so the chain below is total.
        const cls = [3, 2, 1].reduce<Num>(
          (acc, c) => z3.If(baseCls.eq(c), z3.Int.val(APPEND_CLASS[c]![suffix]!), acc),
          z3.Int.val(APPEND_CLASS[0]![suffix]!),
        );
        return { catId: baseCatId, cls };
      }
    }
    if (v.k === 'bytes' && v.v.length === 0) return { catId: NO_CATEGORY, cls: 0 };
    if (v.k === 'seed' && v.seed.kind === 'category') return { catId: v.seed.id!, cls: 1 };
    return null;
  }

  const eqCategory = (x: CatView, y: CatView): Bool => z3.And(eqInt(x.catId, y.catId), eqInt(x.cls, y.cls));

  // ---- capability suffix ----
  // `tokenCategory.split(32)[1]` is the other half of the introspection string: the empty string for a
  // bare category (an immutable NFT or a fungible-only UTXO), 0x01 for mutable, 0x02 for minting —
  // exactly the suffix classes 1, 2 and 3. `Borrowing.borrow` authenticates its prepared loanKey this
  // way (`require(loanKeyCapability == 0x02)`), so dropping it let a *non-minting* NFT pass as the
  // loanKey and the borrow outputs then carried the wrong category. Only a raw introspection field is
  // handled, whose class is 1..3 whenever the split succeeds at all, which makes this exact rather
  // than lossy: a category-less field (class 0) is a split past the end, which the VM rejects and this
  // equality reports false.
  const capSuffixClass = (v: SVal): Num | null => {
    if (v.k !== 'split' || v.at !== 32 || v.side !== 'R' || v.v.k !== 'field') return null;
    if (v.v.f === 'utxoCat') return catClass(v.v.i, 'in');
    if (v.v.f === 'outCat') return catClass(v.v.i, 'out');
    return null;
  };
  /** The suffix class a constant is the suffix of: `0x` -> bare, `0x01` -> mutable, `0x02` -> minting. */
  const constSuffixClass = (v: SVal): number | null => {
    if (v.k !== 'bytes') return null;
    if (v.v.length === 0) return 1;
    if (v.v.length === 1 && v.v[0] === Capability.MUTABLE) return 2;
    if (v.v.length === 1 && v.v[0] === Capability.MINTING) return 3;
    return NO_SUFFIX; // any other string is the suffix of no tokenCategory
  };

  // ---- locking-bytecode interpretation ----
  type ScriptView = { kind: 'in' | 'out'; i: number } | { kind: 'const'; id: number };
  function scriptView(v: SVal): ScriptView | null {
    if (v.k === 'field' && v.f === 'utxoBytecode') return { kind: 'in', i: v.i };
    if (v.k === 'field' && v.f === 'outBytecode') return { kind: 'out', i: v.i };
    if (v.k === 'activeBytecode') return { kind: 'in', i: activeIndex };
    if (v.k === 'seed' && v.seed.kind === 'script') return { kind: 'const', id: v.seed.id! };
    // A constant / runtime-built locking script: classify by its first byte.
    const lead = leadingByte(v);
    if (lead === 0x6a) return { kind: 'const', id: Script.BURN }; // OP_RETURN nulldata (provably unspendable)
    if (lead === 0x76) return { kind: 'const', id: Script.ATTACKER }; // P2PKH (user-controlled)
    return null;
  }
  const scriptExpr = (sv: ScriptView): Num | number =>
    sv.kind === 'const' ? sv.id : sv.kind === 'in' ? tx.inputs[sv.i]!.script : tx.outputs[sv.i]!.script;

  function eqScript(a: SVal, b: SVal): Bool | null {
    const viewA = scriptView(a), viewB = scriptView(b);
    if (!viewA || !viewB) return null;
    return eqInt(scriptExpr(viewA), scriptExpr(viewB));
  }

  // ---- count / value / amount / commitment interpretation ----
  // Input/output counts, satoshi values and fungible amounts are model Ints; a comparison of one against
  // a constant or another such field is exact (the VM compares the same numbers). Arithmetic on them
  // (`OP_ADD` etc.) still yields an opaque number, so derived quantities contribute nothing.
  const intField = (v: SVal): Num | null => {
    if (v.k === 'count') return v.of === 'out' ? outCount : inCount;
    if (v.k === 'num') return v.e;
    if (v.k !== 'field') return null;
    switch (v.f) {
      case 'utxoValue': return tx.inputs[v.i]!.value;
      case 'outValue': return tx.outputs[v.i]!.value;
      case 'utxoAmount': return tx.inputs[v.i]!.fts;
      case 'outAmount': return tx.outputs[v.i]!.fts;
      default: return null;
    }
  };
  const countExpr = intField;

  // NFT commitment as a model Int, for function-NFT identifier branches (e.g. commitment == 0x02).
  const commitSlot = (v: SVal) =>
    v.k === 'field' && v.f === 'utxoCommit' ? tx.inputs[v.i]! : v.k === 'field' && v.f === 'outCommit' ? tx.outputs[v.i]! : null;
  const commitExpr = (v: SVal): Num | null => commitSlot(v)?.commitment ?? null;

  // ---- the leading identifier byte ----
  // Every covenant tells one kind of state NFT from another by its first byte:
  // `nftCommitment.split(1)[0] == 0x00` is the price contract, `0x01` a loan, `0x04` the
  // startRedemption function NFT. The int reading cannot supply it (it reads the whole string), so the
  // model carries the byte itself and this view finds it in a stack value. `guard` is what the VM
  // requires for the split that took the byte to succeed at all — splitting an empty commitment at 1
  // is an error, so the equality must be false there. `fromSlot` marks a value that came from a
  // commitment field, which is what makes the comparison worth a constraint at all.
  type HeadView = { head: Num | number; guard: Bool | null; fromSlot: boolean };
  const bothGuards = (x: Bool | null, y: Bool | null): Bool | null =>
    x === null ? y : y === null ? x : z3.And(x, y);
  function headView(v: SVal): HeadView | null {
    const slot = commitSlot(v);
    if (slot) return { head: slot.commitmentHead, guard: null, fromSlot: true };
    if (v.k === 'bytes') return v.v.length > 0 ? { head: v.v[0]!, guard: null, fromSlot: false } : null;
    // A left split keeps the front of the string, so it keeps its first byte — provided the string was
    // long enough for the split in the first place.
    if (v.k === 'split' && v.side === 'L' && v.at >= 1) {
      const inner = headView(v.v);
      if (!inner) return null;
      const len = lengthOf(v.v);
      // A statically known length is a fact about the value, not a constraint to emit; a symbolic one
      // (a commitment field) becomes the guard. Over-splitting a too-short constant stays admitted.
      const guard = len !== null && typeof len !== 'number' ? len.ge(v.at) : null;
      return { head: inner.head, guard: bothGuards(inner.guard, guard), fromSlot: inner.fromSlot };
    }
    if (v.k === 'cat') {
      for (const part of v.parts) {
        if (lengthOf(part) === 0) continue; // a statically empty part contributes nothing
        return headView(part); // the first possibly-non-empty part carries the first byte
      }
    }
    return null;
  }
  const headEquality = (x: HeadView, y: HeadView): Bool => {
    const guard = bothGuards(x.guard, y.guard);
    const eq = eqInt(x.head, y.head);
    return guard === null ? eq : z3.And(guard, eq);
  };

  // ---- byte lengths ----
  // Exact where the structure is known: constants, sized opaques (NUM2BIN, hashes), commitment fields,
  // tokenCategory fields (0 / 32 / 33 by class), seeds, outpoint hashes, and CAT/SPLIT of those.
  // (A split whose position exceeds the length fails on chain; the model just admits it: superset.)
  function lengthOf(v: SVal): Num | number | null {
    switch (v.k) {
      case 'bytes': return v.v.length;
      case 'sized': return v.len;
      case 'outpoint': return 32;
      case 'seed': return v.seed.kind === 'category' ? 32 : null;
      case 'field': {
        const slot = commitSlot(v);
        if (slot) return slot.commitmentLength;
        if (v.f === 'utxoCat' || v.f === 'outCat') {
          const cls = catClass(v.i, v.f === 'utxoCat' ? 'in' : 'out');
          return z3.If(cls.eq(0), z3.Int.val(0), z3.If(cls.eq(1), z3.Int.val(32), z3.Int.val(33)));
        }
        return null;
      }
      case 'split': {
        if (v.side === 'L') return v.at;
        const inner = lengthOf(v.v);
        return inner === null ? null : (typeof inner === 'number' ? inner - v.at : inner.sub(v.at));
      }
      case 'cat': {
        let total: Num | number = 0;
        for (const part of v.parts) {
          const len = lengthOf(part);
          if (len === null) return null;
          total = typeof total === 'number' && typeof len === 'number' ? total + len
            : (typeof total === 'number' ? (len as Num).add(total) : total.add(len));
        }
        return total;
      }
      default: return null;
    }
  }
  const lengthNum = (v: SVal): Num | null => {
    const len = lengthOf(v);
    return len === null ? null : typeof len === 'number' ? z3.Int.val(len) : len;
  };
  /**
   * A lower bound on the byte length when the exact length is unknown: the known parts of a
   * concatenation (`toPaddedBytes(x, 4) + bytes(y)` is at least 4 bytes). Exact when known.
   */
  function minLengthOf(v: SVal): Num | number {
    const exact = lengthOf(v);
    if (exact !== null) return exact;
    if (v.k === 'cat') {
      return v.parts.reduce<Num | number>((acc, part) => {
        const m = minLengthOf(part);
        return typeof acc === 'number' && typeof m === 'number' ? acc + m : (typeof acc === 'number' ? (m as Num).add(acc) : acc.add(m));
      }, 0);
    }
    if (v.k === 'split' && v.side === 'L') return v.at;
    return 0;
  }

  function equalConstraint(a: SVal, b: SVal): EqualityResult {
    const suffixA = capSuffixClass(a), suffixB = capSuffixClass(b);
    if (suffixA !== null || suffixB !== null) {
      if (suffixA !== null && suffixB !== null) return exact(suffixA.eq(suffixB));
      const known = (suffixA ?? suffixB)!;
      const constant = constSuffixClass(suffixA !== null ? b : a);
      if (constant === null) return NONE;
      return exact(constant === NO_SUFFIX ? z3.Bool.val(false) : known.eq(constant));
    }
    // Outpoint txid identity: `tx.inputs[i].outpointTransactionHash == tx.inputs[j].outpointTransactionHash`,
    // the adjacency check `Loan.interact` / `LoanTokenSidecar.attach` authenticate their partner with.
    // Exact, not lossy: `outpointTx` is a per-input identity variable, so two inputs' hashes are equal
    // exactly when the variables are (unlike script ids, which stand for a *class* of scripts).
    if (a.k === 'outpoint' && b.k === 'outpoint') {
      return exact(tx.inputs[a.i]!.outpointTx.eq(tx.inputs[b.i]!.outpointTx));
    }
    const ca = catView(a), cb = catView(b);
    if (ca && cb) return exact(eqCategory(ca, cb));
    const sc = eqScript(a, b);
    if (sc) return lossy(sc); // script ids are class identities
    // Commitment equalities: `commitment == constByte`, `out.commit == in.commit`, and
    // `commit == toPaddedBytes(..) + ..` resolve to the conjunction of whatever is known about both
    // sides: the int reading (fields, short constants) and the byte length (fields, constants, NUM2BIN
    // and CAT/SPLIT of those). Both are necessary conditions for byte equality, not sufficient (the
    // int reading identifies 0x00 and 0x80), hence lossy. Nothing known on one side -> no constraint.
    if (commitSlot(a) || commitSlot(b)) {
      const parts: Bool[] = [];
      const ia = commitIntOf(a), ib = commitIntOf(b);
      if (ia !== null && ib !== null) parts.push(eqInt(ia, ib));
      const heads = [headView(a), headView(b)];
      if (heads[0] && heads[1]) parts.push(headEquality(heads[0], heads[1]));
      const la = lengthOf(a), lb = lengthOf(b);
      if (la !== null && lb !== null) parts.push(eqInt(la, lb));
      else if (la !== null || lb !== null) {
        // One side's length is only bounded below (a concatenation with an opaque part): equality still
        // implies the known side is at least that long — enough to tell a 10-byte receipt from a
        // 1-byte function identifier.
        const known = (la ?? lb) as Num | number, bound = la !== null ? minLengthOf(b) : minLengthOf(a);
        const knownE = typeof known === 'number' ? z3.Int.val(known) : known;
        parts.push(typeof bound === 'number' ? knownE.ge(bound) : knownE.ge(bound));
      }
      return parts.length > 0 ? lossy(z3.And(...parts)) : NONE;
    }
    // `commitment.split(1)[0] == 0x01`: neither side is a whole commitment field, but both have a
    // known first byte. Necessary for byte equality, never asserted under negation (lossy).
    const headA = headView(a), headB = headView(b);
    if (headA && headB && (headA.fromSlot || headB.fromSlot)) return lossy(headEquality(headA, headB));
    return NONE; // value / amount / opaque -> no capability content
  }

  // The int reading of a commitment-like value: a commitment field, or a constant in exact-int range.
  const commitIntOf = (v: SVal): Num | number | null =>
    commitExpr(v) ?? (v.k === 'bytes' && v.v.length <= MAX_COMMITMENT_CONST_BYTES ? bytesToNum(v.v) : null);

  function numEqResult(a: SVal, b: SVal): SVal {
    const ea = countExpr(a), eb = countExpr(b);
    if (ea !== null || eb !== null) {
      let e: Bool | null = null;
      if (ea !== null && eb !== null) e = ea.eq(eb);
      else if (ea !== null && b.k === 'bytes' && b.v.length <= 6) e = ea.eq(bytesToNum(b.v));
      else if (eb !== null && a.k === 'bytes' && a.v.length <= 6) e = eb.eq(bytesToNum(a.v));
      return { k: 'bool', e };
    }
    // Two concrete numbers (e.g. selector vs function index) -> a concrete boolean.
    if (a.k === 'bytes' && b.k === 'bytes') {
      return { k: 'bytes', v: bytesToNum(a.v) === bytesToNum(b.v) ? Uint8Array.of(1) : new Uint8Array() };
    }
    return { k: 'bool', e: null };
  }

  // Numeric value of an SVal, or null if it isn't a resolvable number.
  function numVal(v: SVal): Num | null {
    if (v.k === 'bytes') return v.v.length <= 6 ? z3.Int.val(bytesToNum(v.v)) : null;
    return intField(v);
  }

  function compare(op: number, top: SVal, second: SVal): SVal {
    // operands popped in reverse: `second OP top` in stack order is (a=second, b=top)
    const av = numVal(second), bv = numVal(top);
    if (av === null || bv === null) return { k: 'bool', e: null }; // unresolved operand -> opaque
    switch (op) {
      case Op.OP_LESSTHANOREQUAL: return { k: 'bool', e: av.le(bv) };
      case Op.OP_GREATERTHANOREQUAL: return { k: 'bool', e: av.ge(bv) };
      case Op.OP_LESSTHAN: return { k: 'bool', e: av.lt(bv) };
      case Op.OP_GREATERTHAN: return { k: 'bool', e: av.gt(bv) };
      default: return { k: 'bool', e: null };
    }
  }

  return { equalConstraint, numEqResult, compare, lengthOf: lengthNum, numValue: numVal };
}

function countPresent(z3: Z3, tx: SymbolicTx, of: 'in' | 'out'): Num {
  const slots = of === 'out' ? tx.outputs : tx.inputs;
  return slots.reduce<Num>((acc, utxo) => acc.add(z3.If(utxo.present, z3.Int.val(1), z3.Int.val(0))), z3.Int.val(0));
}
