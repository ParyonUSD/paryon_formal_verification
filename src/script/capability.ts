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

/** Interprets stack values as capability-relevant constraints for a given transaction. */
export interface CapabilityModel {
  /** A capability-relevant equality (`OP_EQUAL`/`OP_EQUALVERIFY`), or null when the compare can't move a capability. */
  equalConstraint(a: SVal, b: SVal): Bool | null;
  /** The result of `OP_NUMEQUAL`(`VERIFY`): a count/selector comparison as a bool SVal. */
  numEqResult(a: SVal, b: SVal): SVal;
  /** The result of a numeric ordering compare (`OP_LESSTHAN` etc.) as a bool SVal. */
  compare(op: number, top: SVal, second: SVal): SVal;
}

export function makeCapabilityModel(z3: Z3, tx: SymbolicTx, activeIndex: number): CapabilityModel {
  const outCount = countPresent(z3, tx, 'out');
  const inCount = countPresent(z3, tx, 'in');

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
      // Base category: either another category view, or a bare outpoint txhash used to
      // mint a brand-new genesis category (LoanKeyFactory: reservedTokenId + 0x02).
      const baseCatId = catView(a!)?.catId ?? (a!.k === 'outpoint' ? GENESIS_BASE + a!.i : null);
      if (baseCatId !== null && b!.k === 'bytes' && b!.v.length === 1) {
        if (b!.v[0] === Capability.MUTABLE) return { catId: baseCatId, cls: 2 };
        if (b!.v[0] === Capability.MINTING) return { catId: baseCatId, cls: 3 };
      }
    }
    if (v.k === 'bytes' && v.v.length === 0) return { catId: NO_CATEGORY, cls: 0 };
    if (v.k === 'seed' && v.seed.kind === 'category') return { catId: v.seed.id!, cls: 1 };
    return null;
  }

  const eqCategory = (x: CatView, y: CatView): Bool => z3.And(eqInt(x.catId, y.catId), eqInt(x.cls, y.cls));

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

  // ---- count / commitment interpretation ----
  const countExpr = (v: SVal): Num | null => (v.k === 'count' ? (v.of === 'out' ? outCount : inCount) : v.k === 'num' ? v.e : null);

  // NFT commitment as a model Int, for function-NFT identifier branches (e.g. commitment == 0x02).
  const commitExpr = (v: SVal): Num | null =>
    v.k === 'field' && v.f === 'utxoCommit' ? tx.inputs[v.i]!.commitment
      : v.k === 'field' && v.f === 'outCommit' ? tx.outputs[v.i]!.commitment
        : null;

  function equalConstraint(a: SVal, b: SVal): Bool | null {
    const ca = catView(a), cb = catView(b);
    if (ca && cb) return eqCategory(ca, cb);
    const sc = eqScript(a, b);
    if (sc) return sc;
    // Commitment equalities: resolve `commitment == constByte` / `out.commit == in.commit`
    // so function-NFT identifier branches (and recreations) decide correctly.
    const ka = commitExpr(a), kb = commitExpr(b);
    if (ka !== null && kb !== null) return eqInt(ka, kb);
    if (ka !== null && b.k === 'bytes') return eqInt(ka, bytesToNum(b.v));
    if (kb !== null && a.k === 'bytes') return eqInt(kb, bytesToNum(a.v));
    return null; // value / amount / opaque -> no capability content
  }

  function numEqResult(a: SVal, b: SVal): SVal {
    const ea = countExpr(a), eb = countExpr(b);
    if (ea !== null || eb !== null) {
      let e: Bool | null = null;
      if (ea !== null && eb !== null) e = ea.eq(eb);
      else if (ea !== null && b.k === 'bytes') e = ea.eq(bytesToNum(b.v));
      else if (eb !== null && a.k === 'bytes') e = eb.eq(bytesToNum(a.v));
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
    if (v.k === 'count') return v.of === 'out' ? outCount : inCount;
    if (v.k === 'num') return v.e;
    if (v.k === 'bytes') return z3.Int.val(bytesToNum(v.v));
    return null;
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

  return { equalConstraint, numEqResult, compare };
}

function countPresent(z3: Z3, tx: SymbolicTx, of: 'in' | 'out'): Num {
  const slots = of === 'out' ? tx.outputs : tx.inputs;
  return slots.reduce<Num>((acc, utxo) => acc.add(z3.If(utxo.present, z3.Int.val(1), z3.Int.val(0))), z3.Int.val(0));
}
