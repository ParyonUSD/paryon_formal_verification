import { asmToScript, Op, type Script } from '@cashscript/utils';

export { asmToScript, Op };
export type { Script };

/** Reverse opcode lookup (number -> name) for diagnostics. */
const NAMES = new Map<number, string>(Object.entries(Op).map(([k, v]) => [v as number, k]));
export function opName(op: number): string {
  return NAMES.get(op) ?? `OP_UNKNOWN_${op}`;
}

/** Interpret a byte string as a little-endian CScriptNum (script's number encoding). */
export function bytesToNum(b: Uint8Array): number {
  if (b.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < b.length; i++) n += b[i]! * 2 ** (8 * i);
  const negBit = 0x80;
  if ((b[b.length - 1]! & negBit) !== 0) {
    // negative (sign bit set) — not expected for our indices/values, but handle correctly.
    n -= 2 ** (8 * b.length - 1);
  }
  return n;
}

/** The small-integer opcodes OP_1..OP_16 push the numbers 1..16; OP_1NEGATE pushes -1. */
export function smallIntPush(op: number): number | undefined {
  if (op === Op.OP_1NEGATE) return -1;
  if (op >= Op.OP_1 && op <= Op.OP_16) return op - Op.OP_1 + 1;
  return undefined;
}
