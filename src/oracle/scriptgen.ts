import { Capability, NO_CATEGORY, Script } from '../model.js';
import { Op, type Script as ScriptOps } from '../script/script.js';
import { ARG, numToBytes, seedCategory, seedScript, type SVal } from '../script/value.js';
import { minimalCommitment, p2pkh, p2sh32, nulldata, type ConcreteTx, type Rng, type Universe } from './concrete.js';

/**
 * Random covenant-shaped scripts for the differential oracle (tests/oracle-interpreter.test.ts).
 *
 * The generator tracks the simulated stack height so every program is well-formed for the real
 * VM (no underflow, valid PICK/ROLL depths, balanced IF/ELSE/ENDIF, clean single-item exit),
 * and routes comparison operands through a menu of stack-shuffle patterns so the interpreter's
 * stack routing (its faithfulness obligation) is exercised, not just its opcode table.
 *
 * Two modes:
 *  - `exact`: only constructs the capability model claims to capture *exactly* — token-category
 *    identity, locking-bytecode identity against canonical constants/fields/seeds, minimally-encoded
 *    commitments, input/output counts, satoshi values and token amounts in comparisons, boolean
 *    combinators and branches on those. Here the model must agree with libauth in both directions.
 *  - wide (`exact: false`): additionally everything the model abstracts (values, amounts, arithmetic,
 *    hashes, sigs, non-minimal encodings, out-of-range indices, mismatched-kind compares, ...).
 *    Here only soundness is asserted: whatever libauth accepts, the model must admit.
 */
export interface GenConfig {
  rng: Rng;
  universe: Universe;
  /** The concrete transaction the script will be evaluated against (exact mode picks present indices). */
  ctx: ConcreteTx;
  capacity: { nIn: number; nOut: number };
  activeIndex: number;
  exact: boolean;
  categoryIds: number[];
  covenantIds: number[];
}

export interface Generated {
  /** The body (what the interpreter executes). */
  body: ScriptOps;
  /** Constructor seeds in declaration order (real script: pushed in reverse before the body). */
  seeds: { sval: SVal; bytes: Uint8Array }[];
  /** Function arguments (real: pushed by the unlocking script, bottom of stack). */
  args: Uint8Array[];
  /** The interpreter's initial stack, bottom-first (mirrors fromArtifact). */
  initialStack: SVal[];
  /** The full locking bytecode as a decoded script: seed pushes then body. */
  lockingScript: ScriptOps;
}

type Kind = 'cat' | 'bc' | 'commit' | 'num';

// Stack effect of the plain stack opcodes we emit.
const DELTA: Partial<Record<number, number>> = {
  [Op.OP_DROP]: -1, [Op.OP_2DROP]: -2, [Op.OP_NIP]: -1, [Op.OP_SWAP]: 0, [Op.OP_ROT]: 0, [Op.OP_OVER]: 1,
  [Op.OP_TUCK]: 1, [Op.OP_2DUP]: 2, [Op.OP_3DUP]: 3, [Op.OP_2SWAP]: 0, [Op.OP_2OVER]: 2, [Op.OP_2ROT]: 0,
  [Op.OP_DUP]: 1,
};

export function generateScript(cfg: GenConfig): Generated {
  const { rng, universe, ctx, exact } = cfg;
  const ops: ScriptOps = [];
  // ---- seeds and args (the initial stack) ----
  const nArgs = rng.int(3);
  const args = Array.from({ length: nArgs }, () => rng.bytes(1 + rng.int(3)));
  const seeds: Generated['seeds'] = [];
  const nSeeds = rng.int(3);
  for (let s = 0; s < nSeeds; s++) {
    if (rng.bool()) {
      const id = rng.pick(cfg.categoryIds);
      seeds.push({ sval: seedCategory(id), bytes: universe.categoryBytes(id) });
    } else {
      const id = rng.pick(cfg.covenantIds);
      seeds.push({ sval: seedScript(id), bytes: universe.scriptBytes(id) });
    }
  }
  let height = nArgs + nSeeds;

  // ---- emit primitives ----
  const emit = (op: number, delta?: number): void => {
    ops.push(op);
    const d = delta ?? DELTA[op];
    if (d === undefined) throw new Error(`no stack delta for op ${op}`);
    height += d;
  };
  const pushData = (bytes: Uint8Array): void => { ops.push(bytes); height += 1; };
  const pushNum = (n: number): void => {
    if (n === 0) emit(Op.OP_0, 1);
    else if (n >= 1 && n <= 16) emit(Op.OP_1 + n - 1, 1);
    else pushData(numToBytes(n));
  };
  /** Copy the stack item at absolute index `idx` (0 = bottom) to the top. */
  // `n OP_PICK` pops n and pushes a copy (net +1 with the push of n); `n OP_ROLL` moves instead (net 0).
  const pickAbs = (idx: number): void => { pushNum(height - 1 - idx); emit(Op.OP_PICK, 0); };

  /** Declaration indices of the seeds of one kind. */
  const seedsOfKind = (kind: 'category' | 'script'): number[] =>
    seeds.flatMap((s, i) => (s.sval.k === 'seed' && s.sval.seed.kind === kind ? [i] : []));
  const capSuffix = (): void => {
    pushData(Uint8Array.of(rng.pick([Capability.MUTABLE, Capability.MINTING])));
    emit(Op.OP_CAT, -1);
  };

  const inIdx = (): number => (exact ? rng.int(ctx.inputs.length) : rng.int(cfg.capacity.nIn));
  const outIdx = (): number => (exact ? rng.int(ctx.outputs.length) : rng.int(cfg.capacity.nOut));
  const wide = (p = 0.3): boolean => !exact && rng.bool(p);

  // ---- operands: each pushes exactly one item ----
  const junk = (): void => {
    if (nArgs > 0 && rng.bool(0.4)) pickAbs(rng.int(nArgs));
    else if (rng.bool()) pushNum(rng.int(17));
    else pushData(rng.bytes(1 + rng.int(4)));
  };

  const catOperand = (): void => {
    const r = rng.next();
    if (r < 0.1) { emit(Op.OP_0, 1); return; } // empty: "no token"
    if (r < 0.25 && seedsOfKind('category').length > 0) {
      pickAbs(nArgs + (nSeeds - 1 - rng.pick(seedsOfKind('category'))));
      if (rng.bool(0.4)) capSuffix();
      return;
    }
    const side = rng.bool() ? 'in' : 'out';
    const i = side === 'in' ? inIdx() : outIdx();
    if (side === 'in' && i === cfg.activeIndex && rng.bool(0.3)) emit(Op.OP_INPUTINDEX, 1); else pushNum(i);
    emit(side === 'in' ? Op.OP_UTXOTOKENCATEGORY : Op.OP_OUTPUTTOKENCATEGORY, 0);
    const slot = side === 'in' ? ctx.inputs[i] : ctx.outputs[i];
    const hasToken = slot !== undefined && slot.category !== NO_CATEGORY;
    if ((hasToken || wide(0.5)) && rng.bool(0.4)) {
      pushNum(32); emit(Op.OP_SPLIT, 0); emit(Op.OP_DROP); // bare 32-byte category
      if (rng.bool(0.6)) capSuffix();
    } else if (rng.bool(0.25)) {
      capSuffix(); // suffix on a raw field: a category string only if the field was bare (exact either way)
    }
  };

  const bcOperand = (): void => {
    const r = rng.next();
    if (r < 0.15) { pushData(universe.scriptBytes(Script.ATTACKER)); return; }
    if (r < 0.3) { pushData(universe.scriptBytes(Script.BURN)); return; }
    if (r < 0.4 && seedsOfKind('script').length > 0) {
      pickAbs(nArgs + (nSeeds - 1 - rng.pick(seedsOfKind('script'))));
      return;
    }
    if (r < 0.5) { emit(Op.OP_ACTIVEBYTECODE, 1); return; }
    if (wide(0.2)) { // a P2PKH / nulldata / P2SH32 the model only knows by class (or not at all)
      pushData(rng.pick([p2pkh(rng.bytes(20)), nulldata(rng.bytes(2)), p2sh32(rng.bytes(32))]));
      return;
    }
    const side = rng.bool() ? 'in' : 'out';
    const i = side === 'in' ? inIdx() : outIdx();
    if (side === 'in' && i === cfg.activeIndex && rng.bool(0.3)) emit(Op.OP_INPUTINDEX, 1); else pushNum(i);
    emit(side === 'in' ? Op.OP_UTXOBYTECODE : Op.OP_OUTPUTBYTECODE, 0);
  };

  const commitOperand = (forceField = false): void => {
    if (!forceField && rng.bool(0.4)) {
      if (wide(0.4)) pushData(rng.pick([Uint8Array.of(0), Uint8Array.of(2, 0), Uint8Array.of(0x80), rng.bytes(3)]));
      else pushData(minimalCommitment(rng));
      return;
    }
    const side = rng.bool() ? 'in' : 'out';
    pushNum(side === 'in' ? inIdx() : outIdx());
    emit(side === 'in' ? Op.OP_UTXOTOKENCOMMITMENT : Op.OP_OUTPUTTOKENCOMMITMENT, 0);
    if (wide(0.3)) { pushNum(1); emit(Op.OP_SPLIT, 0); emit(Op.OP_DROP); } // first byte (opaque to the model)
  };

  /** Pushes a number; returns whether it is symbolic to the model (a count) or a plain constant. */
  const numOperand = (forceSymbolic: boolean): boolean => {
    if (!forceSymbolic && rng.bool(0.4)) {
      // Small constants, occasionally negative (OP_1NEGATE / sign-magnitude encodings).
      pushNum(rng.bool(0.2) ? -(1 + rng.int(3)) : rng.int(Math.max(cfg.capacity.nIn, cfg.capacity.nOut) + 2));
      return false;
    }
    if (wide(0.3)) { opaqueNum(); return false; }
    // Counts, satoshi values and fungible amounts are all model Ints (exact in comparisons).
    switch (rng.int(5)) {
      case 0: pushNum(inIdx()); emit(Op.OP_UTXOVALUE, 0); break;
      case 1: pushNum(outIdx()); emit(Op.OP_OUTPUTVALUE, 0); break;
      case 2: pushNum(inIdx()); emit(Op.OP_UTXOTOKENAMOUNT, 0); break;
      case 3: pushNum(outIdx()); emit(Op.OP_OUTPUTTOKENAMOUNT, 0); break;
      default: emit(rng.bool() ? Op.OP_TXOUTPUTCOUNT : Op.OP_TXINPUTCOUNT, 1); break;
    }
    return true;
  };

  /** Wide mode only: a number the model treats as opaque. */
  const opaqueNum = (): void => {
    const r = rng.int(8);
    switch (r) {
      case 0: pushNum(inIdx()); emit(Op.OP_UTXOVALUE, 0); pushNum(1 + rng.int(9)); emit(Op.OP_ADD, -1); break;
      case 1: pushNum(outIdx()); emit(Op.OP_OUTPUTVALUE, 0); emit(Op.OP_BIN2NUM, 0); break;
      case 2: pushNum(inIdx()); emit(Op.OP_UTXOTOKENAMOUNT, 0); pushNum(2); emit(Op.OP_MUL, -1); break;
      case 3: pushNum(outIdx()); emit(Op.OP_OUTPUTTOKENAMOUNT, 0); emit(Op.OP_SIZE, 1); emit(Op.OP_NIP); break;
      case 4: emit(rng.bool() ? Op.OP_TXLOCKTIME : Op.OP_TXVERSION, 1); break;
      case 5:
        pushNum(rng.int(50)); pushNum(1 + rng.int(9));
        emit(rng.pick([Op.OP_ADD, Op.OP_SUB, Op.OP_MUL, Op.OP_DIV, Op.OP_MOD, Op.OP_MIN, Op.OP_MAX]), -1);
        break;
      case 6: pushNum(rng.int(50)); emit(rng.pick([Op.OP_1ADD, Op.OP_1SUB, Op.OP_NEGATE, Op.OP_ABS]), 0); break;
      default: junk(); emit(Op.OP_SIZE, 1); emit(Op.OP_NIP); break;
    }
  };

  // ---- shuffle patterns ----
  // Each leaves [.., a, b] on top; `cleanup` removes the leftover junk once the compare result is on top.
  type Pattern = { arrange: (a: () => void, b: () => void) => void; cleanup: number[] };
  const J = junk;
  const op = (...ops: number[]): void => { for (const o of ops) emit(o); };
  const NIP = Op.OP_NIP;
  const patterns: Pattern[] = [
    { arrange: (a, b) => { a(); b(); }, cleanup: [] },
    { arrange: (a, b) => { b(); a(); emit(Op.OP_SWAP); }, cleanup: [] },
    { arrange: (a, b) => { a(); J(); b(); emit(Op.OP_ROT); emit(Op.OP_SWAP); }, cleanup: [Op.OP_NIP] },
    { arrange: (a, b) => { a(); b(); J(); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); b(); emit(Op.OP_2DUP); emit(Op.OP_2DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); b(); emit(Op.OP_OVER); emit(Op.OP_OVER); }, cleanup: [Op.OP_NIP, Op.OP_NIP] },
    { arrange: (a, b) => { J(); a(); b(); emit(Op.OP_ROT); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); b(); J(); J(); emit(Op.OP_2DROP); }, cleanup: [] },
    { arrange: (a, b) => { b(); J(); a(); pushNum(2); emit(Op.OP_ROLL, -1); op(Op.OP_ROT, Op.OP_DROP); }, cleanup: [] },
    {
      arrange: (a, b) => { J(); a(); b(); pushNum(2); emit(Op.OP_PICK, 0); op(Op.OP_DROP, Op.OP_ROT, Op.OP_DROP); },
      cleanup: [],
    },
    { arrange: (a, b) => { a(); b(); emit(Op.OP_TUCK); emit(Op.OP_ROT); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { J(); J(); a(); b(); emit(Op.OP_2SWAP); emit(Op.OP_2DROP); }, cleanup: [] },
    {
      arrange: (a, b) => {
        a(); b(); J(); J(); J(); J();
        op(Op.OP_2ROT, Op.OP_2SWAP, Op.OP_2DROP, Op.OP_2SWAP, Op.OP_2DROP);
      },
      cleanup: [],
    },
    { arrange: (a, b) => { a(); b(); J(); op(Op.OP_3DUP, Op.OP_DROP); }, cleanup: [NIP, NIP, NIP] },
    { arrange: (a, b) => { a(); J(); b(); emit(Op.OP_SWAP); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); J(); b(); emit(Op.OP_NIP); }, cleanup: [] },
    { arrange: (a, b) => { b(); a(); b(); emit(Op.OP_ROT); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); emit(Op.OP_DUP); b(); emit(Op.OP_ROT); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); b(); emit(Op.OP_DUP); emit(Op.OP_DROP); }, cleanup: [] },
    { arrange: (a, b) => { a(); b(); J(); J(); emit(Op.OP_2OVER); }, cleanup: [NIP, NIP, NIP, NIP] },
    {
      arrange: (a, b) => { a(); J(); J(); b(); pushNum(3); emit(Op.OP_PICK, 0); emit(Op.OP_SWAP); },
      cleanup: [NIP, NIP, NIP],
    },
    {
      arrange: (a, b) => { a(); J(); J(); b(); pushNum(3); emit(Op.OP_ROLL, -1); emit(Op.OP_SWAP); },
      cleanup: [NIP, NIP],
    },
  ];

  /**
   * Emit a comparison of two operands of `kind`, leaving one bool on the stack (or, with `verify`,
   * nothing). Returns whether the model sees the result as a symbolic bool (exact mode guarantees it).
   */
  const compare = (kind: Kind, verify: boolean): boolean => {
    const pattern = rng.bool(0.5) ? patterns[0]! : rng.pick(patterns);
    let symbolic = true;
    if (kind === 'num') {
      // Exact mode: at least one side is a count so the model's result is a Z3 predicate, not a constant.
      let aSym = false, bSym = false;
      pattern.arrange(() => { aSym = numOperand(false); }, () => { bSym = numOperand(!aSym && exact); });
      symbolic = aSym || bSym;
      const cmp = rng.pick([
        Op.OP_NUMEQUAL, Op.OP_LESSTHAN, Op.OP_GREATERTHAN, Op.OP_LESSTHANOREQUAL, Op.OP_GREATERTHANOREQUAL,
      ]);
      if (verify && cmp === Op.OP_NUMEQUAL && rng.bool()) emit(Op.OP_NUMEQUALVERIFY, -2);
      else { emit(cmp, -1); if (verify) emit(Op.OP_VERIFY, -1); }
    } else {
      // Two constant commitments compare to nothing in the model (only fields carry a commitment), so exact
      // mode keeps a field on one side; categories and bytecode constants are modelled, so they need no such care.
      const operand = kind === 'cat' ? catOperand : kind === 'bc' ? bcOperand : () => commitOperand(exact);
      const other = wide(0.15)
        ? rng.pick([catOperand, bcOperand, () => commitOperand(), junk]) // mismatched kinds: opaque to the model
        : (kind === 'commit' ? () => commitOperand() : operand);
      const [a, b] = rng.bool() ? [operand, other] : [other, operand];
      pattern.arrange(a, b);
      if (verify && rng.bool()) emit(Op.OP_EQUALVERIFY, -2);
      else { emit(Op.OP_EQUAL, -1); if (verify) emit(Op.OP_VERIFY, -1); }
    }
    // Leftover junk: below the result (NIP it away), or on top once a VERIFY form consumed both operands (DROP).
    for (const op of pattern.cleanup) emit(verify && op === Op.OP_NIP ? Op.OP_DROP : op);
    return symbolic;
  };

  /**
   * A boolean expression left on the stack; returns whether the model sees it symbolically.
   *
   * `positive` is the polarity the expression is consumed in. Script-identity and commitment equalities
   * are *lossy* in the model (exact only as a requirement, see capability.ts), so exact mode places them
   * only in positive position: not under OP_NOT, and not as a branch condition (the model explores the
   * negated branch too). Category and count comparisons are exact in every position.
   */
  const boolExpr = (depth: number, positive = true): boolean => {
    const r = rng.next();
    if (depth > 0 && r < 0.2) { const sym = boolExpr(depth - 1, false); emit(Op.OP_NOT, 0); return sym; } // NOT
    if (depth > 0 && r < 0.4) { // AND / OR
      const s1 = boolExpr(depth - 1, positive); const s2 = boolExpr(depth - 1, positive);
      emit(rng.bool() ? Op.OP_BOOLAND : Op.OP_BOOLOR, -1);
      return s1 && s2;
    }
    if (wide(0.08)) { // opaque predicates
      const w = rng.int(4);
      if (w === 0) { // empty signature against a well-formed pubkey: a clean `false`, no NULLFAIL error
        emit(Op.OP_0, 1); pushData(Uint8Array.from([0x02, ...rng.bytes(32)])); emit(Op.OP_CHECKSIG, -1);
        return false;
      }
      if (w === 3) { // CHECKDATASIG takes three operands (sig, message, pubkey); an empty sig yields `false`
        emit(Op.OP_0, 1); junk(); pushData(Uint8Array.from([0x02, ...rng.bytes(32)])); emit(Op.OP_CHECKDATASIG, -2);
        return false;
      }
      if (w === 1) { opaqueNum(); emit(Op.OP_0NOTEQUAL, 0); return false; }
      junk(); emit(rng.pick([Op.OP_SHA256, Op.OP_HASH256, Op.OP_HASH160, Op.OP_RIPEMD160]), 0);
      junk(); emit(Op.OP_EQUAL, -1);
      return false;
    }
    const kinds: Kind[] = exact && !positive ? ['cat', 'cat', 'num'] : ['cat', 'cat', 'bc', 'bc', 'commit', 'num'];
    return compare(rng.pick(kinds), false);
  };

  // ---- statements: stack-neutral ----
  const statement = (depth: number): void => {
    const r = rng.next();
    if (depth > 0 && r < 0.25) { // if / if-else / notif
      boolExpr(1, false);
      emit(rng.bool(0.8) ? Op.OP_IF : Op.OP_NOTIF, -1);
      block(depth - 1);
      if (rng.bool(0.6)) { emit(Op.OP_ELSE, 0); block(depth - 1); }
      emit(Op.OP_ENDIF, 0);
      return;
    }
    if (depth > 0 && r < 0.35) { // correlated branches on one condition (shared via OP_DUP)
      boolExpr(1, false);
      emit(Op.OP_DUP);
      emit(Op.OP_IF, -1); block(depth - 1); emit(Op.OP_ENDIF, 0);
      emit(Op.OP_NOTIF, -1); block(depth - 1); emit(Op.OP_ENDIF, 0);
      return;
    }
    if (!exact && r < 0.42) { // wide: OP_VERIFY on a raw field / constant (model: no constraint)
      if (rng.bool()) { pushNum(inIdx()); emit(Op.OP_UTXOTOKENCATEGORY, 0); } else pushNum(1 + rng.int(3));
      emit(Op.OP_VERIFY, -1);
      return;
    }
    if (r < 0.7) { compare(rng.pick<Kind>(['cat', 'cat', 'bc', 'bc', 'commit', 'num']), true); return; }
    boolExpr(2); emit(Op.OP_VERIFY, -1);
  };
  const block = (depth: number): void => { const n = 1 + rng.int(2); for (let k = 0; k < n; k++) statement(depth); };

  const n = 1 + rng.int(4);
  for (let k = 0; k < n; k++) statement(2);

  // ---- exit: exactly one truthy-or-not item ----
  if (rng.bool(0.4)) boolExpr(1); else emit(Op.OP_1, 1);
  while (height > 1) { if (height >= 3 && rng.bool(0.3)) { emit(Op.OP_ROT); emit(Op.OP_DROP); } else emit(Op.OP_NIP); }

  const seedPushes: ScriptOps = seeds.map((s) => s.bytes).reverse();
  return {
    body: ops,
    seeds,
    args,
    initialStack: [...args.map(() => ARG), ...seeds.map((s) => s.sval).reverse()],
    lockingScript: [...seedPushes, ...ops],
  };
}
