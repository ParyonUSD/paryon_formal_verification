import type { SymbolicTx } from '../model.js';
import type { Bool, Z3 } from '../z3.js';
import { Op, opName, bytesToNum, smallIntPush, type Script as ScriptOps } from './script.js';
import { makeCapabilityModel } from './capability.js';
import { OPAQUE, constBytes, num, numToBytes, type SVal } from './value.js';

/**
 * A symbolic Bitcoin Script interpreter that executes a compiled CashScript artifact
 * over an abstract stack of {@link SVal}s. This file is the BCH/CashTokens-general
 * stack machine: opcode dispatch, stack routing, byte structure (CAT/SPLIT), concrete
 * index arithmetic, and OP_IF/OP_NOTIF branch forking.
 *
 * Its obligation is *faithfulness* — every stack effect must match the VM exactly,
 * because a mis-routed value or a mis-matched ELSE silently emits a constraint about
 * the wrong UTXO, or prunes a path that is reachable on-chain. (This is the half of
 * the soundness story the superset argument does NOT protect.) Deciding which
 * comparisons carry a capability, and turning them into Z3 constraints, is delegated
 * to the capability-abstraction layer (capability.ts), which is allowed to be lossy.
 *
 * OP_IF/OP_NOTIF on a non-constant condition fork execution; the interpreter returns
 * one Path per reachable branch, each with its own constraint set.
 */

// Re-export the value language so callers drive the interpreter through one import surface.
export { ARG, seedCategory, seedOpaque, seedScript, seedSelector } from './value.js';
export type { SVal, Seed } from './value.js';

export interface Path {
  constraints: Bool[];
}

export interface InterpretOptions {
  activeIndex: number;
  /** Initial stack, bottom-first: constructor-arg seeds followed by function-arg placeholders. */
  initialStack: SVal[];
  /** Safety valve against pathological branch counts. */
  maxPaths?: number;
  /** Filled in with what the script touched (see {@link InterpretStats}). */
  stats?: InterpretStats;
}

/** What a script referenced, for template-capacity checks in fromArtifact. */
export interface InterpretStats {
  /** Highest output index any introspection opcode read on any path, or -1. */
  maxOutputIndex: number;
  /**
   * Every read of an input/output index at or beyond the model's capacity, which dropped the path
   * that made it.
   *
   * Within the bounded model — transactions with at most `nInputs` inputs and `nOutputs` outputs — no
   * such field exists, so dropping the path is faithful *for that bound*. But a dropped path turns
   * `script == S => OR(paths)` into `script == S => false` at that index, which is a hole in the proof
   * by construction, so this is not a diagnostic: a builder must surface every entry and a test must
   * enumerate the ones it accepts, with the argument for why that shape is outside the bound.
   */
  beyondCapacity?: { side: 'in' | 'out'; index: number }[];
}

export function interpret(z3: Z3, tx: SymbolicTx, script: ScriptOps, opts: InterpretOptions): Path[] {
  const maxPaths = opts.maxPaths ?? 64;
  const cap = makeCapabilityModel(z3, tx, opts.activeIndex);

  function toIndex(v: SVal): number {
    if (v.k === 'bytes') return bytesToNum(v.v);
    if (v.k === 'num' && v.e === null) throw new Error('symbolic index unsupported');
    throw new Error(`cannot resolve index from ${v.k}`);
  }
  function outIndex(v: SVal): number {
    const i = toIndex(v);
    if (opts.stats && i > opts.stats.maxOutputIndex) opts.stats.maxOutputIndex = i;
    return i;
  }

  /**
   * The VM's truth value of a stack item: a resolved predicate as-is (keeping its lossy mark), a
   * concrete byte string by its CScriptNum reading (any non-zero number, so negative zero is false),
   * anything else unknown (null). Byte strings beyond the exact integer range are treated as unknown.
   */
  type Truth = { e: Bool | null; lossy: boolean };
  const truth = (v: SVal): Truth => {
    if (v.k === 'bool') return { e: v.e, lossy: v.lossy === true };
    if (v.k === 'bytes') return { e: v.v.length <= 6 ? z3.Bool.val(bytesToNum(v.v) !== 0) : null, lossy: false };
    return { e: null, lossy: false };
  };
  const boolVal = (t: Truth): SVal => ({ k: 'bool', e: t.e, ...(t.lossy ? { lossy: true } : {}) });

  /**
   * `a + sign*b` as a stack value. Both concrete -> a concrete byte string (index arithmetic must stay
   * concrete: `toIndex` reads it). Exactly one concrete, the other a number the model resolves ->
   * the linear Z3 expression, which the VM computes the same way. Otherwise opaque.
   */
  const addSub = (a: SVal, b: SVal, sign: 1 | -1): SVal => {
    if (a.k === 'bytes' && b.k === 'bytes') return constBytes(numToBytes(bytesToNum(a.v) + sign * bytesToNum(b.v)));
    const constSide = a.k === 'bytes' ? 'a' : b.k === 'bytes' ? 'b' : null;
    if (constSide === null) return num(null); // two symbolic operands: out of scope, stays opaque
    const ea = cap.numValue(a), eb = cap.numValue(b);
    if (ea === null || eb === null) return num(null);
    return num(sign === 1 ? ea.add(eb) : ea.sub(eb));
  };

  // ---- per-path execution ----
  const paths: Path[] = [];

  function run(ip: number, stack: SVal[], cons: Bool[], decided: Map<SVal, boolean>): void {
    if (paths.length > maxPaths) throw new Error('path explosion');
    const push = (v: SVal) => stack.push(v);
    const pop = (): SVal => { const v = stack.pop(); if (!v) throw new Error('stack underflow'); return v; };
    let feasible = true;
    // Introspection index resolution, bounded by the model's capacity. A negative index names a
    // UTXO that never exists (`this.activeInputIndex - 1` at input 0), and an index at or beyond the
    // capacity names one this bounded model does not carry: either way the path cannot occur here,
    // so it is pruned. Prunings of the second kind are counted so a builder can report that its
    // capacity — not the contract — cut a path.
    const beyond = (side: 'in' | 'out', index: number): void => {
      if (!opts.stats) return;
      const seen = (opts.stats.beyondCapacity ??= []);
      if (!seen.some((r) => r.side === side && r.index === index)) seen.push({ side, index });
    };
    const inSlot = (v: SVal): number => {
      const i = toIndex(v);
      if (i >= 0 && i < tx.inputs.length) return i;
      if (i >= tx.inputs.length) beyond('in', i);
      feasible = false;
      return 0; // a safe placeholder: the path is discarded, its constraints never reach a solver
    };
    const outSlot = (v: SVal): number => {
      const i = outIndex(v);
      if (i >= 0 && i < tx.outputs.length) return i;
      if (i >= tx.outputs.length) beyond('out', i);
      feasible = false;
      return 0;
    };
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
        case Op.OP_UTXOTOKENCATEGORY: push({ k: 'field', f: 'utxoCat', i: inSlot(pop()) }); break;
        case Op.OP_OUTPUTTOKENCATEGORY: push({ k: 'field', f: 'outCat', i: outSlot(pop()) }); break;
        case Op.OP_UTXOTOKENCOMMITMENT: push({ k: 'field', f: 'utxoCommit', i: inSlot(pop()) }); break;
        case Op.OP_OUTPUTTOKENCOMMITMENT: push({ k: 'field', f: 'outCommit', i: outSlot(pop()) }); break;
        case Op.OP_UTXOBYTECODE: push({ k: 'field', f: 'utxoBytecode', i: inSlot(pop()) }); break;
        case Op.OP_OUTPUTBYTECODE: push({ k: 'field', f: 'outBytecode', i: outSlot(pop()) }); break;
        case Op.OP_UTXOVALUE: push({ k: 'field', f: 'utxoValue', i: inSlot(pop()) }); break;
        case Op.OP_OUTPUTVALUE: push({ k: 'field', f: 'outValue', i: outSlot(pop()) }); break;
        case Op.OP_UTXOTOKENAMOUNT: push({ k: 'field', f: 'utxoAmount', i: inSlot(pop()) }); break;
        case Op.OP_OUTPUTTOKENAMOUNT: push({ k: 'field', f: 'outAmount', i: outSlot(pop()) }); break;
        case Op.OP_ACTIVEBYTECODE: push({ k: 'activeBytecode' }); break;
        case Op.OP_INPUTINDEX: push(constBytes(numToBytes(opts.activeIndex))); break;
        case Op.OP_TXINPUTCOUNT: push({ k: 'count', of: 'in' }); break;
        case Op.OP_TXOUTPUTCOUNT: push({ k: 'count', of: 'out' }); break;
        case Op.OP_OUTPOINTTXHASH: push({ k: 'outpoint', i: inSlot(pop()) }); break;
        // The outpoint index is a model Int, so the adjacency checks the loan/pool contracts
        // authenticate their sidecar with (`inputs[i+1].outpointIndex == inputs[i].outpointIndex + 1`)
        // decide exactly instead of going opaque.
        case Op.OP_OUTPOINTINDEX: push(num(tx.inputs[inSlot(pop())]!.outpointIndex)); break;
        case Op.OP_INPUTSEQUENCENUMBER: pop(); push(OPAQUE); break;
        case Op.OP_TXLOCKTIME: case Op.OP_TXVERSION: push(num(null)); break;

        // byte ops
        case Op.OP_CAT: { const b = pop(), a = pop(); push({ k: 'cat', parts: [a, b] }); break; }
        case Op.OP_SPLIT: { const at = toIndex(pop()); const v = pop(); push({ k: 'split', v, at, side: 'L' }); push({ k: 'split', v, at, side: 'R' }); break; }
        case Op.OP_SIZE: { push(num(cap.lengthOf(stack[stack.length - 1]!))); break; }
        case Op.OP_BIN2NUM: { pop(); push(num(null)); break; }
        case Op.OP_NUM2BIN: {
          // Content stays opaque; the length is the (concrete) size argument.
          const size = pop(); pop();
          push(size.k === 'bytes' ? { k: 'sized', len: bytesToNum(size.v) } : OPAQUE);
          break;
        }

        // comparisons — capability content is decided by the abstraction layer
        case Op.OP_EQUAL: { const b = pop(), a = pop(); push(boolVal(cap.equalConstraint(a, b))); break; }
        case Op.OP_EQUALVERIFY: {
          const b = pop(), a = pop(); const c = cap.equalConstraint(a, b).e; if (c) cons.push(c); break;
        }
        case Op.OP_NUMEQUAL: { const b = pop(), a = pop(); push(cap.numEqResult(a, b)); break; }
        case Op.OP_NUMEQUALVERIFY: { const b = pop(), a = pop(); verify(cap.numEqResult(a, b)); break; }
        case Op.OP_LESSTHANOREQUAL: case Op.OP_GREATERTHANOREQUAL:
        case Op.OP_LESSTHAN: case Op.OP_GREATERTHAN: { const b = pop(), a = pop(); push(cap.compare(op, b, a)); break; }
        // The negation of a lossy (necessary-only) predicate is unknown; conjunction and disjunction of
        // necessary conditions are necessary conditions, so they stay resolved and inherit the mark.
        case Op.OP_NOT: {
          const t = truth(pop());
          push(boolVal({ e: t.e && !t.lossy ? z3.Not(t.e) : null, lossy: false }));
          break;
        }
        case Op.OP_0NOTEQUAL: { push(boolVal(truth(pop()))); break; }
        case Op.OP_BOOLAND: {
          const b = truth(pop()), a = truth(pop());
          push(boolVal({ e: a.e && b.e ? z3.And(a.e, b.e) : null, lossy: a.lossy || b.lossy }));
          break;
        }
        case Op.OP_BOOLOR: {
          // Disjunction of capability comparisons (e.g. `out.cat == 0x || out.cat == paryon`).
          const b = truth(pop()), a = truth(pop());
          push(boolVal({ e: a.e && b.e ? z3.Or(a.e, b.e) : null, lossy: a.lossy || b.lossy }));
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

        // add/sub stay concrete on concrete bytes (used to compute output/input indices); on a
        // resolved model number against a *constant* they yield the linear expression, which is what
        // makes `tx.inputs[k].outpointIndex == tx.inputs[i].outpointIndex + 1` an exact constraint.
        // Two unresolved/symbolic operands still go opaque (sums of values/amounts stay out of scope).
        case Op.OP_ADD: { const b = pop(), a = pop(); push(addSub(a, b, 1)); break; }
        case Op.OP_SUB: { const b = pop(), a = pop(); push(addSub(a, b, -1)); break; }
        // other arithmetic we don't model -> opaque number
        case Op.OP_MUL: case Op.OP_DIV: case Op.OP_MOD: case Op.OP_MIN: case Op.OP_MAX: case Op.OP_AND: case Op.OP_OR:
          pop(); pop(); push(num(null)); break;
        case Op.OP_ABS: pop(); push(num(null)); break; // unary
        case Op.OP_1ADD: { const v = pop(); push(addSub(v, constBytes(numToBytes(1)), 1)); break; }
        case Op.OP_1SUB: { const v = pop(); push(addSub(v, constBytes(numToBytes(1)), -1)); break; }
        case Op.OP_NEGATE: { pop(); push(num(null)); break; }
        case Op.OP_HASH160: case Op.OP_RIPEMD160: pop(); push({ k: 'sized', len: 20 }); break;
        case Op.OP_HASH256: case Op.OP_SHA256: pop(); push({ k: 'sized', len: 32 }); break;
        // CHECKSIG takes (sig, pubkey); CHECKDATASIG takes (sig, message, pubkey).
        case Op.OP_CHECKSIG: pop(); pop(); push({ k: 'bool', e: null }); break;
        case Op.OP_CHECKSIGVERIFY: pop(); pop(); break;
        case Op.OP_CHECKDATASIG: pop(); pop(); pop(); push({ k: 'bool', e: null }); break;
        case Op.OP_CHECKDATASIGVERIFY: pop(); pop(); pop(); break;
        // timelock checks read (don't pop) the top item; no capability effect.
        case Op.OP_CHECKLOCKTIMEVERIFY: case Op.OP_CHECKSEQUENCEVERIFY: case Op.OP_NOP: break;

        // control flow — fork on non-constant condition, but keep correlated
        // branches (same condition SVal, shared via OP_DUP) consistent.
        case Op.OP_IF: case Op.OP_NOTIF: {
          const cond = pop();
          const isIf = op === Op.OP_IF;
          const { elseStart, endIp } = scanBranch(script, i);
          const condT = cond.k === 'bool' ? truth(cond) : { e: null, lossy: false };
          // Only predicate SVals have a meaningful identity: `ARG`/`OPAQUE` are shared singletons, so two
          // unrelated branches on opaque values must not be correlated (that would prune reachable paths).
          const correlatable = cond.k === 'bool';
          const go = (condValue: boolean): void => {
            const branchDecided = new Map(decided);
            if (correlatable) branchDecided.set(cond, condValue);
            const c2 = cons.slice();
            // When the condition is a real predicate (e.g. an output-count compare), assert it on the
            // taken path so the path is consistent with the branch. A lossy predicate is asserted only
            // on the path where the script requires it true; its negation is never asserted.
            if (condT.e && condValue) c2.push(condT.e);
            else if (condT.e && !condT.lossy) c2.push(z3.Not(condT.e));
            const execThen = isIf ? condValue : !condValue;
            run(execThen ? i + 1 : (elseStart ?? endIp), stack.slice(), c2, branchDecided);
          };
          if (cond.k === 'bytes') go(bytesToNum(cond.v) !== 0); // concrete (e.g. seeded selector) — one branch
          else {
            const known = correlatable ? decided.get(cond) : undefined;
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

  run(0, opts.initialStack.slice(), [], new Map());
  return paths;
}

// ---- pure helpers ----
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
