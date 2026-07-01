import { bytesToNum } from './script.js';
import type { Bool, Num } from '../z3.js';

/**
 * The symbolic value language of the script interpreter: the abstract stack
 * values pushed and popped during execution. This layer is BCH/CashTokens-general
 * — it describes *where data came from* (an introspected field, a concatenation, a
 * constant) and carries no ParyonUSD policy. Turning these values into capability
 * constraints is the job of capability.ts.
 */

/** A transaction field an introspection opcode can read, by side and meaning. */
export type Field =
  | 'utxoCat' | 'outCat'
  | 'utxoCommit' | 'outCommit'
  | 'utxoBytecode' | 'outBytecode'
  | 'utxoValue' | 'outValue'
  | 'utxoAmount' | 'outAmount';

type SeedKind = 'script' | 'category' | 'opaque';
/** A constructor-argument seed (e.g. a locking-script param or a tokenId param). */
export interface Seed {
  kind: SeedKind;
  /** script id (kind 'script') or category id (kind 'category'). */
  id?: number;
}

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

export const OPAQUE: SVal = { k: 'opaque' };

/** Wrap a (possibly unresolved) Z3 Int as a stack value. */
export const num = (e: Num | null): SVal => ({ k: 'num', e });
/** Wrap a concrete byte string as a stack value. */
export const constBytes = (v: Uint8Array): SVal => ({ k: 'bytes', v });

/** A function-argument placeholder for the initial stack (its content is opaque). */
export const ARG: SVal = OPAQUE;
/** A constructor-arg seed binding a locking-script param to a script id. */
export function seedScript(id: number): SVal { return { k: 'seed', seed: { kind: 'script', id } }; }
/** A constructor-arg seed binding a tokenId param to a category id. */
export function seedCategory(id: number): SVal { return { k: 'seed', seed: { kind: 'category', id } }; }
/** A constructor-arg seed whose value never feeds a capability comparison. */
export const seedOpaque: SVal = { k: 'seed', seed: { kind: 'opaque' } };
/** A concrete function-selector value (its numeric index), to pick a branch of a multi-function contract. */
export function seedSelector(index: number): SVal { return { k: 'bytes', v: numToBytes(index) }; }

/** Encode a number as a little-endian CScriptNum byte string (script's number encoding). */
export function numToBytes(n: number): Uint8Array {
  if (n === 0) return new Uint8Array();
  const out: number[] = [];
  let magnitude = Math.abs(n);
  while (magnitude > 0) { out.push(magnitude & 0xff); magnitude = Math.floor(magnitude / 256); }
  if (n < 0) out[out.length - 1]! |= 0x80;
  return new Uint8Array(out);
}

/** First concrete byte of a (possibly concatenated) constant byte expression, if known. */
export function leadingByte(v: SVal): number | null {
  if (v.k === 'bytes') return v.v.length > 0 ? v.v[0]! : null;
  if (v.k === 'cat' && v.parts.length > 0) return leadingByte(v.parts[0]!);
  return null;
}

// bytesToNum is re-exported here so the value language has a single import surface for callers
// that decode concrete byte strings; the canonical definition lives in script.ts.
export { bytesToNum };
