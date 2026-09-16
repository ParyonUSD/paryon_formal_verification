import { beforeAll, describe, expect, it } from 'vitest';
import { Capability, Script, declareTx, type SymbolicTx } from '../src/model.js';
import { Op, type Script as ScriptOps } from '../src/script/script.js';
import { interpret } from '../src/script/interpreter.js';
import {
  Universe, evaluateWithLibauth, fixTx, scriptToBytecode, type ConcreteTx, type ConcreteUtxo,
} from '../src/oracle/concrete.js';
import { getContext, newSolver, type Z3 } from '../src/z3.js';

/**
 * Targeted differential cases for the commitment abstraction, where random search does not reach.
 *
 * The model keeps three things about an NFT commitment — an integer reading, a byte length and the
 * leading byte — and the covenants build new commitments by concatenation. That combination has a
 * trap: the first byte of `nftCommitment + 0x05` is the field's first byte only when the field is
 * non-empty, and an *empty* commitment is a perfectly ordinary run-time value. Claiming the field's
 * head unconditionally made the model reject transactions libauth accepts, which no superset argument
 * protects against and which the fuzzer will not stumble on (it needs the output commitment to be
 * exactly the input's plus the appended bytes).
 *
 * Every case asserts the soundness direction: whatever libauth's VM accepts, the model must admit on
 * some path.
 */
const CAPACITY = { nIn: 2, nOut: 2 };
const ACTIVE = 0;
const COVENANT = Script.FIRST_COVENANT;

let z3: Z3;
let tx: SymbolicTx;
beforeAll(async () => {
  z3 = await getContext();
  tx = declareTx(z3, CAPACITY.nIn, CAPACITY.nOut);
});

const nft = (commitment: Uint8Array, script: number): ConcreteUtxo =>
  ({ category: 1, capability: Capability.IMMUTABLE, script, commitment, fts: 0n, value: 1000n });

/** Run one script against one concrete transaction, on both sides. */
async function differential(body: ScriptOps, ctx: ConcreteTx): Promise<{ real: boolean; admits: boolean }> {
  const universe = new Universe(11);
  universe.setScript(COVENANT, scriptToBytecode(body));
  const real = evaluateWithLibauth(universe, ctx, ACTIVE);
  const paths = interpret(z3, tx, body, { activeIndex: ACTIVE, initialStack: [] });
  const solver = newSolver(z3);
  fixTx(z3, solver, tx, ctx);
  let admits = false;
  for (const path of paths) {
    solver.push();
    for (const c of path.constraints) solver.add(c);
    if ((await solver.check()) === 'sat') admits = true;
    solver.pop();
    if (admits) break;
  }
  return { real: real.ok, admits };
}

/** `tx.outputs[0].nftCommitment == tx.inputs[0].nftCommitment + <suffix>` */
const recreateWithSuffix = (suffix: Uint8Array): ScriptOps =>
  [Op.OP_0, Op.OP_OUTPUTTOKENCOMMITMENT, Op.OP_0, Op.OP_UTXOTOKENCOMMITMENT, suffix, Op.OP_CAT, Op.OP_EQUAL];

/** `(tx.inputs[0].nftCommitment + <suffix>).split(1)[0] == <expected>` */
const headOfSuffixed = (suffix: Uint8Array, expected: Uint8Array): ScriptOps =>
  [Op.OP_0, Op.OP_UTXOTOKENCOMMITMENT, suffix, Op.OP_CAT, Op.OP_1, Op.OP_SPLIT, Op.OP_DROP, expected, Op.OP_EQUAL];

describe('a commitment field at the front of a concatenation', () => {
  const suffix = Uint8Array.of(0x05);

  it('an EMPTY commitment takes its head from what follows it', async () => {
    const ctx: ConcreteTx = {
      inputs: [nft(new Uint8Array(), COVENANT)],
      outputs: [nft(Uint8Array.of(0x05), Script.ATTACKER)],
    };
    const { real, admits } = await differential(recreateWithSuffix(suffix), ctx);
    expect(real, 'libauth should accept: 0x + 0x05 == 0x05').toBe(true);
    expect(admits, 'the model must admit what the VM accepts').toBe(true);
  });

  it('...also when the first byte is read back out', async () => {
    const ctx: ConcreteTx = { inputs: [nft(new Uint8Array(), COVENANT)], outputs: [nft(new Uint8Array(), Script.ATTACKER)] };
    const { real, admits } = await differential(headOfSuffixed(suffix, Uint8Array.of(0x05)), ctx);
    expect(real, 'libauth should accept: (0x + 0x05).split(1)[0] == 0x05').toBe(true);
    expect(admits).toBe(true);
  });

  it('a NON-empty commitment keeps its own head', async () => {
    const ctx: ConcreteTx = {
      inputs: [nft(Uint8Array.of(0x07), COVENANT)],
      outputs: [nft(Uint8Array.of(0x07, 0x05), Script.ATTACKER)],
    };
    const { real, admits } = await differential(recreateWithSuffix(suffix), ctx);
    expect(real).toBe(true);
    expect(admits).toBe(true);
    const head = await differential(headOfSuffixed(suffix, Uint8Array.of(0x07)), ctx);
    expect(head.real).toBe(true);
    expect(head.admits).toBe(true);
  });

  it('the leading-byte constraint is still there for a plain field', async () => {
    // The precision the head exists for: a bare `nftCommitment.split(1)[0] == 0x01` still decides, so
    // the fix above dropped only the concatenation case.
    const body: ScriptOps = [Op.OP_0, Op.OP_UTXOTOKENCOMMITMENT, Op.OP_1, Op.OP_SPLIT, Op.OP_DROP, Uint8Array.of(0x01), Op.OP_EQUAL];
    const match = await differential(body, { inputs: [nft(Uint8Array.of(0x01, 0x09), COVENANT)], outputs: [] });
    expect(match).toEqual({ real: true, admits: true });
    const mismatch = await differential(body, { inputs: [nft(Uint8Array.of(0x02, 0x09), COVENANT)], outputs: [] });
    expect(mismatch, 'the model must reject it too, or the head buys nothing').toEqual({ real: false, admits: false });
  });
});
