import { asmToScript, Op, type Script } from '@cashscript/utils';

export { asmToScript, Op };
export type { Script };

/** Reverse opcode lookup (number -> name) for diagnostics. */
const NAMES = new Map<number, string>(
  Object.entries(Op).map(([name, opcode]) => [opcode as number, name]),
);
export function opName(op: number): string {
  return NAMES.get(op) ?? `OP_UNKNOWN_${op}`;
}

/** Interpret a byte string as a little-endian CScriptNum (script's number encoding). */
export function bytesToNum(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  let value = 0;
  for (let i = 0; i < bytes.length; i++) value += bytes[i]! * 2 ** (8 * i);
  const signBit = 0x80;
  if ((bytes[bytes.length - 1]! & signBit) !== 0) {
    // CScriptNum is sign-magnitude: the top bit is the sign, the rest the magnitude (0x81 == -1).
    value = -(value - 2 ** (8 * bytes.length - 1));
  }
  return value === 0 ? 0 : value; // never -0 (negative zero encodes 0)
}

/** The small-integer opcodes OP_1..OP_16 push the numbers 1..16; OP_1NEGATE pushes -1. */
export function smallIntPush(op: number): number | undefined {
  if (op === Op.OP_1NEGATE) return -1;
  if (op >= Op.OP_1 && op <= Op.OP_16) return op - Op.OP_1 + 1;
  return undefined;
}
