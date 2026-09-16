import { beforeAll, describe, expect, it } from 'vitest';
import { declareTx } from '../src/model.js';
import { interpret } from '../src/script/interpreter.js';
import { Op, bytesToNum } from '../src/script/script.js';
import { numToBytes } from '../src/script/value.js';
import { getContext, type Z3 } from '../src/z3.js';

let z3: Z3;
beforeAll(async () => { z3 = await getContext(); });

/** Small faithfulness regressions for bugs the libauth oracle found in the interpreter's stack machine. */
describe('interpreter faithfulness regressions', () => {
  it('CScriptNum decoding is sign-magnitude and round-trips the encoder', () => {
    expect(bytesToNum(Uint8Array.of(0x81))).toBe(-1);
    expect(bytesToNum(Uint8Array.of(0x80))).toBe(0); // negative zero
    expect(bytesToNum(Uint8Array.of(0x00, 0xff))).toBe(-0x7f00);
    expect(bytesToNum(Uint8Array.of(0xff, 0x00))).toBe(0xff);
    for (const n of [0, 1, -1, 127, -127, 128, -128, 1000, -1000, 2 ** 31, -(2 ** 31)]) expect(bytesToNum(numToBytes(n))).toBe(n);
  });

  it('OP_CHECKDATASIG(VERIFY) consumes three operands (sig, message, pubkey), OP_CHECKSIG two', () => {
    const tx = declareTx(z3, 1, 1);
    const run = (script: (number | Uint8Array)[]) => interpret(z3, tx, script, { activeIndex: 0, initialStack: [] });
    const three = [Uint8Array.of(1), Uint8Array.of(2), Uint8Array.of(3)];
    // Three items in, none left: a following OP_1 makes the script end with a single truthy item.
    expect(run([...three, Op.OP_CHECKDATASIGVERIFY, Op.OP_1])).toHaveLength(1);
    expect(run([...three, Op.OP_CHECKDATASIG])).toHaveLength(1);
    expect(() => run([Uint8Array.of(1), Uint8Array.of(2), Op.OP_CHECKDATASIGVERIFY])).toThrow('stack underflow');
    expect(run([Uint8Array.of(1), Uint8Array.of(2), Op.OP_CHECKSIGVERIFY, Op.OP_1])).toHaveLength(1);
  });
});
