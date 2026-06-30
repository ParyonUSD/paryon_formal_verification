import { Capability, NO_CATEGORY, Script, type SymbolicTx } from '../model.js';
import type { Bool, Num, Z3 } from '../z3.js';
import { Op, opName, bytesToNum, smallIntPush, type Script as ScriptOps } from './script.js';

/**
 * A symbolic Bitcoin Script interpreter that extracts the capability-relevant
 * constraints from a compiled CashScript artifact.
 *
 * It tracks an abstract stack and, at every *VERIFY, emits a Z3 constraint ONLY
 * for the comparisons that can move an NFT capability: token-category equality
 * (-> category + capability), locking-bytecode equality (-> script id) and
 * output-count comparisons (-> the cap). Everything else — commitment bytes,
 * BCH values, token amounts, arithmetic — is treated as opaque and contributes
 * no constraint. Dropping those is sound for a *leak-freedom* proof: it yields a
 * superset of transactions, so UNSAT on the model implies UNSAT on-chain.
 *
 * OP_IF/OP_NOTIF on a non-constant condition fork execution; the interpreter
 * returns one Path per reachable branch, each with its own constraint set.
 */

type SeedKind = 'script' | 'category' | 'opaque';
/** A constructor-argument seed (e.g. a locking-script param or a tokenId param). */
export interface Seed {
  kind: SeedKind;
  /** script id (kind 'script') or category id (kind 'category'). */
  id?: number;
}

type Field =
  | 'utxoCat' | 'outCat'
  | 'utxoCommit' | 'outCommit'
  | 'utxoBytecode' | 'outBytecode'
  | 'utxoValue' | 'outValue'
  | 'utxoAmount' | 'outAmount';

export type SVal =
  | { k: 'bytes'; v: Uint8Array }
  | { k: 'field'; f: Field; i: number }
  | { k: 'activeBytecode' }
  | { k: 'count'; of: 'in' | 'out' }
  | { k: 'cat'; parts: SVal[] }
  | { k: 'split'; v: SVal; at: number; side: 'L' | 'R' }
  | { k: 'outpoint'; i: number } // an input's outpoint txhash: opaque alone, a genesis category base when concatenated with a capability byte
  | { k: 'seed'; seed: Seed }
  | { k: 'num'; e: Num | null }
  | { k: 'bool'; e: Bool | null }
  | { k: 'opaque' };

const OPAQUE: SVal = { k: 'opaque' };
// Category id base for genesis-minted categories (per genesis input index). Distinct from the
// registry's category ids and outside the tallied/internal sets — a fresh, user-facing category.
const GENESIS_BASE = 20;

export interface Path {
  constraints: Bool[];
}

export interface InterpretOptions {
  activeIndex: number;
  /** Initial stack, bottom-first: constructor-arg seeds followed by function-arg placeholders. */
  initialStack: SVal[];
  /** Safety valve against pathological branch counts. */
  maxPaths?: number;
}

/** Build an opaque function-argument placeholder for the initial stack. */
export const ARG: SVal = OPAQUE;
/** Build a constructor-arg seed for the initial stack. */
export function seedScript(id: number): SVal { return { k: 'seed', seed: { kind: 'script', id } }; }
export function seedCategory(id: number): SVal { return { k: 'seed', seed: { kind: 'category', id } }; }
export const seedOpaque: SVal = { k: 'seed', seed: { kind: 'opaque' } };
/** A concrete function-selector value (its numeric index), used to pick a branch of a multi-function contract. */
export function seedSelector(index: number): SVal { return { k: 'bytes', v: numToBytes(index) }; }

export function interpret(z3: Z3, tx: SymbolicTx, script: ScriptOps, opts: InterpretOptions): Path[] {
  const maxPaths = opts.maxPaths ?? 64;
  const outCount = countPresent(z3, tx, 'out');
  const inCount = countPresent(z3, tx, 'in');

  // ---- helpers over our model ----
  const num = (e: Num | null): SVal => ({ k: 'num', e });
  const constBytes = (v: Uint8Array): SVal => ({ k: 'bytes', v });

  function toIndex(v: SVal): number {
    if (v.k === 'bytes') return bytesToNum(v.v);
    if (v.k === 'num' && v.e === null) throw new Error('symbolic index unsupported');
    throw new Error(`cannot resolve index from ${v.k}`);
  }

  // ---- token-category interpretation ----
  // We compare the *byte serialisation* of tokenCategory, captured as (catId, suffix class):
  //   0 = empty (no token), 1 = bare 32-byte (immutable NFT *or* fungible-only — indistinguishable),
  //   2 = +0x01 (mutable), 3 = +0x02 (minting).
  const eqInt = (a: Num | number, b: Num | number): Bool => {
    if (typeof a === 'number' && typeof b === 'number') return z3.Bool.val(a === b);
    return (typeof a === 'number' ? (b as Num).eq(a) : (a as Num).eq(b));
  };
  /** Suffix class of a model slot's tokenCategory as a Z3 Int. */
  const catClass = (i: number, side: 'in' | 'out'): Num => {
    const u = side === 'in' ? tx.inputs[i]! : tx.outputs[i]!;
    return z3.If(u.category.eq(NO_CATEGORY), z3.Int.val(0),
      z3.If(u.capability.le(Capability.IMMUTABLE), z3.Int.val(1),
        z3.If(u.capability.eq(Capability.MUTABLE), z3.Int.val(2), z3.Int.val(3))));
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
    if (v.k === 'activeBytecode') return { kind: 'in', i: opts.activeIndex };
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
    const x = scriptView(a), y = scriptView(b);
    if (!x || !y) return null;
    return eqInt(scriptExpr(x), scriptExpr(y));
  }

  // ---- count interpretation ----
  const countExpr = (v: SVal): Num | null => (v.k === 'count' ? (v.of === 'out' ? outCount : inCount) : v.k === 'num' ? v.e : null);

  // NFT commitment as a model Int, for function-NFT identifier branches (e.g. commitment == 0x02).
  const commitExpr = (v: SVal): Num | null =>
    v.k === 'field' && v.f === 'utxoCommit' ? tx.inputs[v.i]!.commitment
      : v.k === 'field' && v.f === 'outCommit' ? tx.outputs[v.i]!.commitment
        : null;

  /** Capability-relevant equality, or null when the comparison can't move a capability. */
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

  // ---- per-path execution ----
  const paths: Path[] = [];

  function run(ip: number, stack: SVal[], cons: Bool[], decided: Map<SVal, boolean>): void {
    if (paths.length > maxPaths) throw new Error('path explosion');
    const push = (v: SVal) => stack.push(v);
    const pop = (): SVal => { const v = stack.pop(); if (!v) throw new Error('stack underflow'); return v; };
    let feasible = true;
    // A concrete-false require (e.g. a seeded function selector that doesn't match
    // this branch) means the path can't occur on-chain; prune it.
    const verify = (v: SVal) => {
      if (v.k === 'bytes') { if (bytesToNum(v.v) === 0) feasible = false; }
      else if (v.k === 'bool' && v.e) cons.push(v.e);
    };

    for (let i = ip; i < script.length && feasible; i++) {
      const instr = script[i]!;
      if (instr instanceof Uint8Array) { push(constBytes(instr)); continue; }
      const op = instr;

      const small = smallIntPush(op);
      if (small !== undefined) { push(constBytes(numToBytes(small))); continue; }

      switch (op) {
        // pushes / no-ops
        case Op.OP_0: push(constBytes(new Uint8Array())); break;

        // introspection (index on stack)
        case Op.OP_UTXOTOKENCATEGORY: push({ k: 'field', f: 'utxoCat', i: toIndex(pop()) }); break;
        case Op.OP_OUTPUTTOKENCATEGORY: push({ k: 'field', f: 'outCat', i: toIndex(pop()) }); break;
        case Op.OP_UTXOTOKENCOMMITMENT: push({ k: 'field', f: 'utxoCommit', i: toIndex(pop()) }); break;
        case Op.OP_OUTPUTTOKENCOMMITMENT: push({ k: 'field', f: 'outCommit', i: toIndex(pop()) }); break;
        case Op.OP_UTXOBYTECODE: push({ k: 'field', f: 'utxoBytecode', i: toIndex(pop()) }); break;
        case Op.OP_OUTPUTBYTECODE: push({ k: 'field', f: 'outBytecode', i: toIndex(pop()) }); break;
        case Op.OP_UTXOVALUE: push({ k: 'field', f: 'utxoValue', i: toIndex(pop()) }); break;
        case Op.OP_OUTPUTVALUE: push({ k: 'field', f: 'outValue', i: toIndex(pop()) }); break;
        case Op.OP_UTXOTOKENAMOUNT: push({ k: 'field', f: 'utxoAmount', i: toIndex(pop()) }); break;
        case Op.OP_OUTPUTTOKENAMOUNT: push({ k: 'field', f: 'outAmount', i: toIndex(pop()) }); break;
        case Op.OP_ACTIVEBYTECODE: push({ k: 'activeBytecode' }); break;
        case Op.OP_INPUTINDEX: push(constBytes(numToBytes(opts.activeIndex))); break;
        case Op.OP_TXINPUTCOUNT: push({ k: 'count', of: 'in' }); break;
        case Op.OP_TXOUTPUTCOUNT: push({ k: 'count', of: 'out' }); break;
        case Op.OP_OUTPOINTTXHASH: push({ k: 'outpoint', i: toIndex(pop()) }); break;
        case Op.OP_OUTPOINTINDEX: case Op.OP_INPUTSEQUENCENUMBER: pop(); push(OPAQUE); break;
        case Op.OP_TXLOCKTIME: case Op.OP_TXVERSION: push(num(null)); break;

        // byte ops
        case Op.OP_CAT: { const b = pop(), a = pop(); push({ k: 'cat', parts: [a, b] }); break; }
        case Op.OP_SPLIT: { const at = toIndex(pop()); const v = pop(); push({ k: 'split', v, at, side: 'L' }); push({ k: 'split', v, at, side: 'R' }); break; }
        case Op.OP_SIZE: { const v = stack[stack.length - 1]!; void v; push(num(null)); break; }
        case Op.OP_BIN2NUM: { pop(); push(num(null)); break; }
        case Op.OP_NUM2BIN: { pop(); pop(); push(OPAQUE); break; }

        // comparisons
        case Op.OP_EQUAL: { const b = pop(), a = pop(); push({ k: 'bool', e: equalConstraint(a, b) }); break; }
        case Op.OP_EQUALVERIFY: {
          const b = pop(), a = pop(); const c = equalConstraint(a, b); if (c) cons.push(c); break;
        }
        case Op.OP_NUMEQUAL: { const b = pop(), a = pop(); push(numEqResult(a, b)); break; }
        case Op.OP_NUMEQUALVERIFY: { const b = pop(), a = pop(); verify(numEqResult(a, b)); break; }
        case Op.OP_LESSTHANOREQUAL: case Op.OP_GREATERTHANOREQUAL:
        case Op.OP_LESSTHAN: case Op.OP_GREATERTHAN: { push(boolFromCompare(op, pop(), pop())); break; }
        case Op.OP_NOT: { const v = pop(); push({ k: 'bool', e: v.k === 'bool' && v.e ? z3.Not(v.e) : null }); break; }
        case Op.OP_0NOTEQUAL: { pop(); push({ k: 'bool', e: null }); break; }
        case Op.OP_BOOLAND: {
          const b = pop(), a = pop();
          const both = a.k === 'bool' && a.e && b.k === 'bool' && b.e;
          push({ k: 'bool', e: both ? z3.And(a.e as Bool, b.e as Bool) : null });
          break;
        }
        case Op.OP_BOOLOR: {
          // Disjunction of capability comparisons (e.g. `out.cat == 0x || out.cat == paryon`).
          const b = pop(), a = pop();
          const both = a.k === 'bool' && a.e && b.k === 'bool' && b.e;
          push({ k: 'bool', e: both ? z3.Or(a.e as Bool, b.e as Bool) : null });
          break;
        }

        // verifies
        case Op.OP_VERIFY: verify(pop()); break;

        // stack manipulation
        case Op.OP_DUP: { const v = stack[stack.length - 1]!; push(v); break; }
        case Op.OP_DROP: pop(); break;
        case Op.OP_2DROP: pop(); pop(); break;
        case Op.OP_NIP: { const b = pop(); pop(); push(b); break; }
        case Op.OP_OVER: { const v = stack[stack.length - 2]!; push(v); break; }
        case Op.OP_TUCK: { const b = pop(), a = pop(); push(b); push(a); push(b); break; }
        case Op.OP_SWAP: { const b = pop(), a = pop(); push(b); push(a); break; }
        case Op.OP_ROT: { const c = pop(), b = pop(), a = pop(); push(b); push(c); push(a); break; }
        case Op.OP_2DUP: { const b = stack[stack.length - 1]!, a = stack[stack.length - 2]!; push(a); push(b); break; }
        case Op.OP_3DUP: {
          const c = stack[stack.length - 1]!, b = stack[stack.length - 2]!, a = stack[stack.length - 3]!;
          push(a); push(b); push(c); break;
        }
        case Op.OP_2SWAP: {
          const d = pop(), c = pop(), b = pop(), a = pop(); push(c); push(d); push(a); push(b); break;
        }
        case Op.OP_2OVER: { const a = stack[stack.length - 4]!, b = stack[stack.length - 3]!; push(a); push(b); break; }
        case Op.OP_2ROT: {
          const f = pop(), e = pop(), d = pop(), c = pop(), b = pop(), a = pop();
          push(c); push(d); push(e); push(f); push(a); push(b); break;
        }
        case Op.OP_PICK: { const n = toIndex(pop()); push(stack[stack.length - 1 - n]!); break; }
        case Op.OP_ROLL: {
          const n = toIndex(pop()); const v = stack.splice(stack.length - 1 - n, 1)[0]!; push(v); break;
        }
        case Op.OP_DEPTH: push(num(null)); break;

        // add/sub stay concrete on concrete bytes (used to compute output/input indices)
        case Op.OP_ADD: { const b = pop(), a = pop(); push(a.k === 'bytes' && b.k === 'bytes' ? constBytes(numToBytes(bytesToNum(a.v) + bytesToNum(b.v))) : num(null)); break; }
        case Op.OP_SUB: { const b = pop(), a = pop(); push(a.k === 'bytes' && b.k === 'bytes' ? constBytes(numToBytes(bytesToNum(a.v) - bytesToNum(b.v))) : num(null)); break; }
        // other arithmetic we don't model -> opaque number
        case Op.OP_MUL: case Op.OP_DIV: case Op.OP_MOD: case Op.OP_MIN: case Op.OP_MAX: case Op.OP_AND: case Op.OP_OR:
          pop(); pop(); push(num(null)); break;
        case Op.OP_ABS: pop(); push(num(null)); break; // unary
        case Op.OP_1ADD: { const v = pop(); push(v.k === 'bytes' ? constBytes(numToBytes(bytesToNum(v.v) + 1)) : num(null)); break; }
        case Op.OP_1SUB: { const v = pop(); push(v.k === 'bytes' ? constBytes(numToBytes(bytesToNum(v.v) - 1)) : num(null)); break; }
        case Op.OP_NEGATE: { pop(); push(num(null)); break; }
        case Op.OP_HASH160: case Op.OP_HASH256: case Op.OP_SHA256: case Op.OP_RIPEMD160:
          pop(); push(OPAQUE); break;
        case Op.OP_CHECKSIG: case Op.OP_CHECKDATASIG: pop(); pop(); push({ k: 'bool', e: null }); break;
        case Op.OP_CHECKSIGVERIFY: case Op.OP_CHECKDATASIGVERIFY: pop(); pop(); break;
        // timelock checks read (don't pop) the top item; no capability effect.
        case Op.OP_CHECKLOCKTIMEVERIFY: case Op.OP_CHECKSEQUENCEVERIFY: case Op.OP_NOP: break;

        // control flow — fork on non-constant condition, but keep correlated
        // branches (same condition SVal, shared via OP_DUP) consistent.
        case Op.OP_IF: case Op.OP_NOTIF: {
          const cond = pop();
          const isIf = op === Op.OP_IF;
          const { elseStart, endIp } = scanBranch(script, i);
          const condE = cond.k === 'bool' ? cond.e : null;
          const go = (condValue: boolean): void => {
            const d = new Map(decided);
            d.set(cond, condValue);
            const c2 = cons.slice();
            // When the condition is a real predicate (e.g. an output-count compare),
            // assert it on the taken path so the path is consistent with the branch.
            if (condE) c2.push(condValue ? condE : z3.Not(condE));
            const execThen = isIf ? condValue : !condValue;
            run(execThen ? i + 1 : (elseStart ?? endIp), stack.slice(), c2, d);
          };
          if (cond.k === 'bytes') go(bytesToNum(cond.v) !== 0); // concrete (e.g. seeded selector) — one branch
          else {
            const known = decided.get(cond);
            if (known !== undefined) go(known); // already decided upstream — stay consistent
            else { go(true); go(false); }
          }
          return; // branches handled recursively
        }
        case Op.OP_ELSE: { // reached only while executing a then-branch: skip to ENDIF
          const endIp = matchEndif(script, i);
          i = endIp; break;
        }
        case Op.OP_ENDIF: break;

        default:
          throw new Error(`unhandled opcode ${opName(op)} at ip ${i}`);
      }
    }
    // Implicit final verify: a covenant must end truthy.
    if (feasible && stack.length > 0) verify(stack[stack.length - 1]!);
    if (feasible) paths.push({ constraints: cons });
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
  function boolFromCompare(op: number, top: SVal, second: SVal): SVal {
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

  run(0, opts.initialStack.slice(), [], new Map());
  return paths;
}

// ---- pure helpers ----
/** First concrete byte of a (possibly concatenated) constant byte expression, if known. */
function leadingByte(v: SVal): number | null {
  if (v.k === 'bytes') return v.v.length > 0 ? v.v[0]! : null;
  if (v.k === 'cat' && v.parts.length > 0) return leadingByte(v.parts[0]!);
  return null;
}

function numToBytes(n: number): Uint8Array {
  if (n === 0) return new Uint8Array();
  const out: number[] = [];
  let x = Math.abs(n);
  while (x > 0) { out.push(x & 0xff); x = Math.floor(x / 256); }
  if (n < 0) out[out.length - 1]! |= 0x80;
  return new Uint8Array(out);
}

function countPresent(z3: Z3, tx: SymbolicTx, of: 'in' | 'out'): Num {
  const slots = of === 'out' ? tx.outputs : tx.inputs;
  return slots.reduce<Num>((acc, u) => acc.add(z3.If(u.present, z3.Int.val(1), z3.Int.val(0))), z3.Int.val(0));
}

/** Find the matching OP_ELSE / OP_ENDIF for an OP_IF/OP_NOTIF at `ifIp`. */
function scanBranch(script: ScriptOps, ifIp: number): { elseStart: number | null; endIp: number } {
  let depth = 0, elseStart: number | null = null;
  for (let i = ifIp + 1; i < script.length; i++) {
    const op = script[i];
    if (op === Op.OP_IF || op === Op.OP_NOTIF) depth++;
    else if (op === Op.OP_ENDIF) {
      if (depth > 0) { depth--; continue; }
      return { elseStart: elseStart === null ? null : elseStart + 1, endIp: i + 1 };
    } else if (op === Op.OP_ELSE && depth === 0) elseStart = i;
  }
  throw new Error('unmatched OP_IF');
}
function matchEndif(script: ScriptOps, fromIp: number): number {
  let depth = 0;
  for (let i = fromIp + 1; i < script.length; i++) {
    const op = script[i];
    if (op === Op.OP_IF || op === Op.OP_NOTIF) depth++;
    else if (op === Op.OP_ENDIF) { if (depth === 0) return i; depth--; }
  }
  throw new Error('unmatched OP_ELSE');
}
