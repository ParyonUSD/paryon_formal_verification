import { disassembleBytecodeBch } from '@bitauth/libauth';
import { beforeAll, describe, expect, it } from 'vitest';
import { Script, declareTx, type SymbolicTx } from '../src/model.js';
import { interpret } from '../src/script/interpreter.js';
import {
  Universe, evaluateWithLibauth, fixTx, genConcreteTx, makeRng, scriptToBytecode, type ConcreteTx,
} from '../src/oracle/concrete.js';
import { generateScript } from '../src/oracle/scriptgen.js';
import { getContext, newSolver, type Z3 } from '../src/z3.js';

/**
 * Differential test of the symbolic interpreter against libauth's BCH VM (the oracle).
 *
 * For a random concrete transaction and a random covenant-shaped script, libauth decides whether the
 * script accepts the transaction. The model must then admit the transaction's abstraction on at least
 * one interpreter path whenever libauth accepts — that is the soundness direction the leak-freedom
 * proof rests on ("the chain never accepts what the model rejects"). In exact mode (only constructs
 * the capability model claims to capture precisely) the two must agree in both directions, which
 * guards against the trivial way to pass the soundness check: admitting everything.
 *
 * Every case is reproducible from its seed (`ORACLE_SEED`), and the case count scales with
 * `ORACLE_CASES` (default 150 per mode). Z3's wasm heap is never reclaimed within a process, so keep a
 * single run at or below ~1000 cases per mode (1500 exhausts the 2 GB heap with the commitment-length
 * model); for a larger sweep run several times with different `ORACLE_SEED`s.
 */
const CASES = Number(process.env['ORACLE_CASES'] ?? 150);
const BASE_SEED = Number(process.env['ORACLE_SEED'] ?? 1);
const CAPACITY = { nIn: 4, nOut: 5 };
const CATEGORIES = [1, 2, 3];
const COVENANTS = [Script.FIRST_COVENANT, Script.FIRST_COVENANT + 1, Script.FIRST_COVENANT + 2];
const SCRIPTS = [Script.ATTACKER, Script.BURN, ...COVENANTS];

let z3: Z3;
let tx: SymbolicTx; // one symbolic transaction for every case: fixTx pins all of it, so sharing is exact and cheap
beforeAll(async () => { z3 = await getContext(); tx = declareTx(z3, CAPACITY.nIn, CAPACITY.nOut); });

interface CaseResult {
  seed: number;
  real: { ok: boolean; error?: string };
  admits: boolean;
  paths: number;
  modelError?: string;
  asm: string;
  ctx: ConcreteTx;
}

async function runCase(seed: number, exact: boolean): Promise<CaseResult> {
  const rng = makeRng(seed);
  const universe = new Universe(seed);
  const ctx = genConcreteTx(rng, {
    nInMax: CAPACITY.nIn, nOutMax: CAPACITY.nOut, categoryIds: CATEGORIES, scriptIds: SCRIPTS, minimalCommitments: exact,
  });
  // The script under test is the locking bytecode of a covenant id at the active input; every slot with that
  // id carries the same bytecode (the recreation shape). Seeds never reference it (its bytes are only known
  // after generation).
  const activeIndex = rng.int(ctx.inputs.length);
  const activeId = rng.pick(COVENANTS);
  ctx.inputs[activeIndex]!.script = activeId;
  const gen = generateScript({
    rng, universe, ctx, capacity: CAPACITY, activeIndex, exact, categoryIds: CATEGORIES,
    covenantIds: COVENANTS.filter((id) => id !== activeId),
  });
  const bytecode = scriptToBytecode(gen.lockingScript);
  universe.setScript(activeId, bytecode);

  const real = evaluateWithLibauth(universe, ctx, activeIndex, gen.args);

  let paths;
  try {
    paths = interpret(z3, tx, gen.body, { activeIndex, initialStack: gen.initialStack, maxPaths: 512 });
  } catch (e) {
    // An interpreter crash on a program the VM runs is a faithfulness bug; on a malformed program it is
    // the generator's fault. Either way surface it with the libauth verdict.
    return { seed, real, admits: false, paths: 0, modelError: (e as Error).message, asm: disassembleBytecodeBch(bytecode), ctx };
  }
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
  return { seed, real, admits, paths: paths.length, asm: disassembleBytecodeBch(bytecode), ctx };
}

function describeCase(r: CaseResult): string {
  const slot = (u: ConcreteTx['inputs'][number]) =>
    `cat=${u.category} cap=${u.capability} script=${u.script} commit=${Buffer.from(u.commitment).toString('hex') || '-'}`;
  return [
    `seed=${r.seed} libauth=${r.real.ok ? 'accept' : `reject (${r.real.error})`} model=${r.modelError ? `CRASH (${r.modelError})` : r.admits ? 'admits' : 'rejects'} paths=${r.paths}`,
    `inputs:  ${r.ctx.inputs.map(slot).join(' | ')}`,
    `outputs: ${r.ctx.outputs.map(slot).join(' | ')}`,
    `script:  ${r.asm}`,
  ].join('\n');
}

// In exact mode the only legitimate libauth failures are the script's own checks failing; anything else
// (underflow, bad split, invalid index) means the generator emitted a malformed program.
const EXPECTED_FAILURE = /OP_VERIFY|non-truthy|OP_EQUALVERIFY|OP_NUMEQUALVERIFY/;

describe('interpreter vs libauth VM (differential oracle)', () => {
  it('exact subset: model and libauth agree in both directions', async () => {
    const stats = { accept: 0, reject: 0 };
    const disagreements: string[] = [];
    for (let k = 0; k < CASES; k++) {
      const r = await runCase(BASE_SEED * 1_000_000 + k, true);
      if (r.real.ok) stats.accept++; else stats.reject++;
      if (!r.real.ok && !EXPECTED_FAILURE.test(r.real.error ?? '')) disagreements.push(`MALFORMED\n${describeCase(r)}`);
      else if (r.modelError || r.real.ok !== r.admits) disagreements.push(describeCase(r));
    }
    // Both verdicts must occur, or the test proves nothing.
    expect(stats.accept).toBeGreaterThan(0);
    expect(stats.reject).toBeGreaterThan(0);
    expect(disagreements, disagreements.join('\n\n')).toEqual([]);
  });

  it('wide subset: whatever libauth accepts, the model admits (soundness)', async () => {
    const stats = { accept: 0, reject: 0, rejectAdmitted: 0 };
    const unsound: string[] = [];
    for (let k = 0; k < CASES; k++) {
      const r = await runCase(BASE_SEED * 1_000_000 + 500_000 + k, false);
      if (r.real.ok) stats.accept++; else { stats.reject++; if (r.admits) stats.rejectAdmitted++; }
      if (r.real.ok && !r.admits) unsound.push(describeCase(r));
      else if (r.modelError) unsound.push(describeCase(r)); // a crash is never acceptable, even when the VM rejects too
    }
    expect(stats.accept).toBeGreaterThan(0);
    expect(unsound, unsound.join('\n\n')).toEqual([]);
  });
});
