import {
  createVirtualMachineBch2026, encodeDataPush, verifyTransactionTokens,
  type Output, type Transaction,
} from '@bitauth/libauth';
import { Capability, NO_CATEGORY, Script, type SymbolicTx } from '../model.js';
import { bytesToNum, type Script as ScriptOps } from '../script/script.js';
import type { Z3, Z3Solver } from '../z3.js';

/**
 * The concrete side of the differential oracle: a *concrete* transaction (real 32-byte
 * categories, real locking bytecode, real commitments) that can be handed to libauth's
 * BCH VM / token validation as-is, together with its abstraction into the symbolic
 * model (`fixTx`). libauth is the oracle here because it is cross-validated with BCHN
 * on the shared VMB test vectors; nothing in this file depends on CashScript.
 *
 * The abstraction `α: ConcreteTx -> model assignment` is what the soundness argument
 * is about: for every concrete transaction the chain accepts, the model must admit
 * α(tx) on at least one path (see tests/oracle-*.test.ts).
 */

// ---- deterministic PRNG (mulberry32) so every fuzz failure is reproducible from its seed ----
export interface Rng {
  /** Uniform in [0, 1). */
  next(): number;
  /** Uniform integer in [0, n). */
  int(n: number): number;
  pick<T>(xs: readonly T[]): T;
  bool(p?: number): boolean;
  bytes(n: number): Uint8Array;
}

export function makeRng(seed: number): Rng {
  let a = seed >>> 0;
  const next = (): number => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n: number): number => Math.floor(next() * n);
  return {
    next, int,
    pick: (xs) => { if (xs.length === 0) throw new Error('pick from empty'); return xs[int(xs.length)]!; },
    bool: (p = 0.5) => next() < p,
    bytes: (n) => Uint8Array.from({ length: n }, () => int(256)),
  };
}

// ---- concrete transaction ----
export interface ConcreteUtxo {
  /** Model category id (NO_CATEGORY = no token). */
  category: number;
  /** Model capability (Capability.NONE = no NFT). */
  capability: number;
  /** Model script id. */
  script: number;
  commitment: Uint8Array;
  fts: bigint;
  value: bigint;
  /**
   * The outpoint this input spends, as (transaction identity, output index). Inputs only; the
   * identity is mapped to real 32 bytes by {@link Universe.outpointHash}. Defaults to
   * `{ tx: <input index>, index: 1 }`: all-distinct transactions and a non-genesis index.
   */
  outpoint?: { tx: number; index: number };
}
export interface ConcreteTx {
  inputs: ConcreteUtxo[];
  outputs: ConcreteUtxo[];
}

/**
 * Maps the model's small-int identities to real bytes. Category ids map to distinct
 * 32-byte strings; script ids to distinct locking bytecode (ATTACKER = a P2PKH, BURN = an
 * OP_RETURN nulldata, covenants = P2SH32 unless overridden with `setScript`).
 */
export class Universe {
  private readonly categories = new Map<number, Uint8Array>();
  private readonly scripts = new Map<number, Uint8Array>();
  private readonly outpoints = new Map<number, Uint8Array>();
  private readonly rng: Rng;

  constructor(seed: number) {
    this.rng = makeRng(seed ^ 0x5eed);
    this.scripts.set(Script.ATTACKER, p2pkh(this.rng.bytes(20)));
    this.scripts.set(Script.BURN, nulldata(this.rng.bytes(4)));
  }

  /** The 32-byte category exactly as OP_UTXOTOKENCATEGORY pushes it (before any capability suffix). */
  categoryBytes(id: number): Uint8Array {
    if (id === NO_CATEGORY) throw new Error('NO_CATEGORY has no bytes');
    let bytes = this.categories.get(id);
    if (!bytes) { bytes = this.rng.bytes(32); this.categories.set(id, bytes); }
    return bytes;
  }

  scriptBytes(id: number): Uint8Array {
    let bytes = this.scripts.get(id);
    if (!bytes) { bytes = p2sh32(this.rng.bytes(32)); this.scripts.set(id, bytes); }
    return bytes;
  }

  /** Bind a script id to explicit locking bytecode (e.g. the bare script under test). */
  setScript(id: number, bytes: Uint8Array): void { this.scripts.set(id, bytes); }

  /** Distinct 32-byte transaction hashes per outpoint-transaction identity (the model's `outpointTx`). */
  outpointHash(txId: number): Uint8Array {
    let bytes = this.outpoints.get(txId);
    if (!bytes) { bytes = this.rng.bytes(32); this.outpoints.set(txId, bytes); }
    return bytes;
  }
}

export function p2pkh(hash20: Uint8Array): Uint8Array {
  return Uint8Array.from([0x76, 0xa9, 0x14, ...hash20, 0x88, 0xac]);
}
export function p2sh32(hash32: Uint8Array): Uint8Array {
  return Uint8Array.from([0xaa, 0x20, ...hash32, 0x87]);
}
export function nulldata(payload: Uint8Array): Uint8Array {
  return Uint8Array.from([0x6a, ...encodeDataPush(payload)]);
}

const CAPABILITY_NAME: Record<number, 'none' | 'mutable' | 'minting'> = {
  [Capability.IMMUTABLE]: 'none',
  [Capability.MUTABLE]: 'mutable',
  [Capability.MINTING]: 'minting',
};

function toLibauthOutput(universe: Universe, utxo: ConcreteUtxo): Output {
  const out: Output = { lockingBytecode: universe.scriptBytes(utxo.script), valueSatoshis: utxo.value };
  if (utxo.category !== NO_CATEGORY) {
    out.token = {
      amount: utxo.fts,
      // libauth stores the category in serialisation order and reverses it on introspection push.
      category: universe.categoryBytes(utxo.category).slice().reverse(),
      ...(utxo.capability !== Capability.NONE
        ? { nft: { capability: CAPABILITY_NAME[utxo.capability]!, commitment: utxo.commitment } }
        : {}),
    };
  }
  return out;
}

/** The libauth `{ transaction, sourceOutputs }` pair for a concrete transaction (see ConcreteUtxo.outpoint). */
export function toLibauth(
  universe: Universe, ctx: ConcreteTx, unlocking: { inputIndex: number; args: Uint8Array[] } | null = null,
): { transaction: Transaction; sourceOutputs: Output[] } {
  return {
    sourceOutputs: ctx.inputs.map((utxo) => toLibauthOutput(universe, utxo)),
    transaction: {
      version: 2,
      locktime: 0,
      inputs: ctx.inputs.map((utxo, i) => ({
        outpointIndex: utxo.outpoint?.index ?? 1,
        outpointTransactionHash: universe.outpointHash(utxo.outpoint?.tx ?? i),
        sequenceNumber: 0xffffffff,
        // Function arguments are what the unlocking script pushes (push-only, bottom of the stack).
        unlockingBytecode: unlocking && unlocking.inputIndex === i
          ? concatBytes(unlocking.args.map(encodeDataPush))
          : new Uint8Array(),
      })),
      outputs: ctx.outputs.map((utxo) => toLibauthOutput(universe, utxo)),
    },
  };
}

/** Encode a decoded script back to bytecode (minimal data pushes, as libauth/BCHN would). */
export function scriptToBytecode(script: ScriptOps): Uint8Array {
  return concatBytes(
    script.map((instr) => (instr instanceof Uint8Array ? encodeDataPush(instr) : Uint8Array.of(instr))),
  );
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export interface OracleEvaluation {
  ok: boolean;
  error?: string;
  stack: Uint8Array[];
}

const vm = createVirtualMachineBch2026(false); // consensus (non-standard) rules: the widest set the chain accepts

/**
 * Evaluate input `activeIndex` of a concrete transaction with libauth's VM. The universe must already
 * bind that input's script id to the bytecode under test (`universe.setScript`).
 */
export function evaluateWithLibauth(
  universe: Universe, ctx: ConcreteTx, activeIndex: number, args: Uint8Array[] = [],
): OracleEvaluation {
  const { transaction, sourceOutputs } = toLibauth(universe, ctx, { inputIndex: activeIndex, args });
  const state = vm.evaluate({ inputIndex: activeIndex, sourceOutputs, transaction });
  const result = vm.stateSuccess(state);
  return { ok: result === true, ...(result === true ? {} : { error: result }), stack: state.stack };
}

/** libauth's CashTokens validation verdict for a concrete transaction. */
export function verifyTokensWithLibauth(universe: Universe, ctx: ConcreteTx): true | string {
  const { transaction, sourceOutputs } = toLibauth(universe, ctx);
  return verifyTransactionTokens(transaction, sourceOutputs, { maximumTokenCommitmentLength: 128 });
}

/**
 * The abstraction α: pin every model slot to the concrete transaction. Slots beyond the concrete
 * size are absent and take the same defaults `addStructure` assigns to absent slots, so `fixTx`
 * is usable with or without the consensus rules loaded.
 */
export function fixTx(z3: Z3, solver: Z3Solver, tx: SymbolicTx, ctx: ConcreteTx): void {
  if (ctx.inputs.length > tx.inputs.length || ctx.outputs.length > tx.outputs.length) {
    throw new Error('concrete transaction exceeds model capacity');
  }
  const fix = (slots: SymbolicTx['inputs'], concrete: ConcreteUtxo[]): void => {
    slots.forEach((slot, i) => {
      const utxo = concrete[i];
      if (!utxo) {
        solver.add(z3.Not(slot.present), slot.category.eq(NO_CATEGORY), slot.capability.eq(Capability.NONE),
          slot.script.eq(Script.ATTACKER), slot.commitment.eq(0), slot.commitmentLength.eq(0),
          slot.commitmentHead.eq(0),
          slot.fts.eq(0), slot.value.eq(0));
        return;
      }
      solver.add(slot.present, slot.category.eq(utxo.category), slot.capability.eq(utxo.capability),
        slot.script.eq(utxo.script), slot.commitment.eq(commitmentToInt(utxo.commitment)),
        slot.commitmentLength.eq(utxo.commitment.length),
        slot.commitmentHead.eq(utxo.commitment.length > 0 ? utxo.commitment[0]! : 0),
        slot.fts.eq(Number(utxo.fts)), slot.value.eq(Number(utxo.value)));
    });
  };
  fix(tx.inputs, ctx.inputs);
  fix(tx.outputs, ctx.outputs);
  // Outpoints are an input-only field; absent slots get the same neutral values `addOutpointRules`
  // leaves them free to take, so fixTx stays usable with or without the consensus rules loaded.
  tx.inputs.forEach((slot, i) => {
    const utxo = ctx.inputs[i];
    solver.add(
      slot.outpointTx.eq(utxo?.outpoint?.tx ?? (utxo ? i : 0)),
      slot.outpointIndex.eq(utxo?.outpoint?.index ?? (utxo ? 1 : 0)),
    );
  });
}

/** The model's commitment abstraction (a CScriptNum reading of the bytes; see model.ts). */
export function commitmentToInt(commitment: Uint8Array): number {
  if (commitment.length > 6) throw new Error('oracle commitments must fit a safe integer');
  return bytesToNum(commitment);
}

// ---- random concrete transactions ----
export interface ConcreteTxOptions {
  nInMax: number;
  nOutMax: number;
  /** Category ids (excluding NO_CATEGORY) the transaction may use. */
  categoryIds: number[];
  /** Script ids the transaction may use. */
  scriptIds: number[];
  /** Only minimally-encoded CScriptNum commitments (the model's commitment abstraction is exact on those). */
  minimalCommitments: boolean;
}

/** A minimally-encoded CScriptNum byte string for a small non-negative number. */
export function minimalCommitment(rng: Rng): Uint8Array {
  const r = rng.next();
  if (r < 0.25) return new Uint8Array();
  if (r < 0.85) return Uint8Array.of(1 + rng.int(0x7f));
  return Uint8Array.of(rng.int(256), 1 + rng.int(0x7f));
}

export function randomCommitment(rng: Rng, minimal: boolean): Uint8Array {
  if (minimal || rng.bool(0.7)) return minimalCommitment(rng);
  // Non-minimal / arbitrary bytes: 0x00, 0x0100, sign-bit set, ...
  return rng.pick([
    Uint8Array.of(0), Uint8Array.of(1, 0), Uint8Array.of(0x80), Uint8Array.of(0xff, 0xff), rng.bytes(1 + rng.int(4)),
  ]);
}

export function randomUtxo(rng: Rng, opts: ConcreteTxOptions): ConcreteUtxo {
  const script = rng.pick(opts.scriptIds);
  const value = BigInt(1000 + rng.int(10000));
  if (rng.bool(0.25)) {
    return { category: NO_CATEGORY, capability: Capability.NONE, script, commitment: new Uint8Array(), fts: 0n, value };
  }
  const category = rng.pick(opts.categoryIds);
  const capability = rng.pick([Capability.NONE, Capability.IMMUTABLE, Capability.MUTABLE, Capability.MINTING]);
  // A token prefix needs an NFT or a positive fungible amount (category <-> token consistency).
  const fts = capability === Capability.NONE ? BigInt(1 + rng.int(100)) : (rng.bool(0.3) ? BigInt(rng.int(100)) : 0n);
  const commitment = capability === Capability.NONE ? new Uint8Array() : randomCommitment(rng, opts.minimalCommitments);
  return { category, capability, script, commitment, fts, value };
}

/**
 * Distinct outpoints for `n` inputs, drawn so that several inputs often share a transaction (which is
 * what the loan/pool adjacency checks compare) at nearby indices (which is what `outpointIndex + 1`
 * compares). No transaction spends one outpoint twice, so the pairs are kept pairwise distinct — the
 * model asserts that too. Transaction identities stay within `nInMax`, the model's `outpointTx` bound.
 */
export function genOutpoints(rng: Rng, n: number, nTxIds: number): { tx: number; index: number }[] {
  const used = new Set<string>();
  const out: { tx: number; index: number }[] = [];
  for (let i = 0; i < n; i++) {
    let pick = { tx: rng.int(nTxIds), index: rng.int(4) };
    // Retry a few times, then fall back to a slot that is certainly free.
    for (let attempt = 0; used.has(`${pick.tx}:${pick.index}`) && attempt < 8; attempt++) {
      pick = { tx: rng.int(nTxIds), index: rng.int(4) };
    }
    while (used.has(`${pick.tx}:${pick.index}`)) pick = { tx: pick.tx, index: pick.index + 1 };
    used.add(`${pick.tx}:${pick.index}`);
    out.push(pick);
  }
  return out;
}

export function genConcreteTx(rng: Rng, opts: ConcreteTxOptions): ConcreteTx {
  const nIn = 1 + rng.int(opts.nInMax);
  const nOut = 1 + rng.int(opts.nOutMax);
  const inputs = Array.from({ length: nIn }, () => randomUtxo(rng, opts));
  // A small pool of transaction identities so inputs genuinely share one (the adjacency shape).
  const outpoints = genOutpoints(rng, nIn, Math.max(2, Math.ceil(opts.nInMax / 2)));
  outpoints.forEach((outpoint, i) => { inputs[i]!.outpoint = outpoint; });
  // Outputs are biased towards recreating inputs (the shape covenants actually produce), with mutations.
  const outputs = Array.from({ length: nOut }, (_, i) => {
    const source = inputs[i];
    if (source && rng.bool(0.5)) {
      const copy = { ...source, commitment: source.commitment.slice() };
      if (rng.bool(0.3)) copy.script = rng.pick(opts.scriptIds);
      if (copy.category !== NO_CATEGORY && rng.bool(0.15)) {
        copy.capability = rng.pick([Capability.IMMUTABLE, Capability.MUTABLE, Capability.MINTING]);
      }
      if (copy.category !== NO_CATEGORY && copy.capability === Capability.NONE && copy.fts === 0n) copy.fts = 1n;
      if (copy.capability === Capability.NONE) copy.commitment = new Uint8Array();
      return copy;
    }
    return randomUtxo(rng, opts);
  });
  return { inputs, outputs };
}
