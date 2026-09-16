import { beforeAll, describe, expect, it } from 'vitest';
import { addConsensusRules } from '../src/consensus.js';
import { Capability, NO_CATEGORY, Script, declareTx } from '../src/model.js';
import {
  Universe, fixTx, genConcreteTx, makeRng, verifyTokensWithLibauth, type ConcreteTx, type ConcreteUtxo,
} from '../src/oracle/concrete.js';
import { getContext, type Z3, type Z3Solver } from '../src/z3.js';

/**
 * Differential test of the hand-written CashTokens tally (src/consensus.ts) against libauth's
 * `verifyTransactionTokens` (the oracle, cross-validated with BCHN).
 *
 * Soundness (asserted on every random case): whatever libauth accepts, the model's consensus rules
 * admit. The model is deliberately weaker than the real rules — it drops fungible conservation and the
 * immutable-NFT commitment matching, neither of which can move a capability — so libauth rejecting
 * while the model admits is expected and only reported. Precision is asserted on targeted violations
 * of the three rules the model does encode.
 */
const CASES = Number(process.env['ORACLE_CASES'] ?? 300);
const BASE_SEED = Number(process.env['ORACLE_SEED'] ?? 1);
const CAPACITY = { nIn: 4, nOut: 5 };
const CATEGORIES = [1, 2, 3];
const SCRIPTS = [Script.ATTACKER, Script.BURN, Script.FIRST_COVENANT, Script.FIRST_COVENANT + 1];

let z3: Z3;
beforeAll(async () => { z3 = await getContext(); });

function modelSolver(ctx: ConcreteTx): Z3Solver {
  const tx = declareTx(z3, CAPACITY.nIn, CAPACITY.nOut);
  const solver = new z3.Solver();
  addConsensusRules(z3, solver, tx, CATEGORIES);
  fixTx(z3, solver, tx, ctx);
  return solver;
}

const slot = (u: ConcreteUtxo) => `cat=${u.category} cap=${u.capability} fts=${u.fts} commit=${Buffer.from(u.commitment).toString('hex') || '-'}`;
const describeTx = (ctx: ConcreteTx) => `inputs:  ${ctx.inputs.map(slot).join(' | ')}\noutputs: ${ctx.outputs.map(slot).join(' | ')}`;

describe('consensus tally vs libauth token validation (differential oracle)', () => {
  it('whatever libauth accepts, the model admits (soundness)', async () => {
    const stats = { accept: 0, reject: 0, rejectAdmitted: 0 };
    const unsound: string[] = [];
    for (let k = 0; k < CASES; k++) {
      const seed = BASE_SEED * 1_000_000 + k;
      const rng = makeRng(seed);
      const universe = new Universe(seed);
      const ctx = genConcreteTx(rng, { nInMax: CAPACITY.nIn, nOutMax: CAPACITY.nOut, categoryIds: CATEGORIES, scriptIds: SCRIPTS, minimalCommitments: false });
      const real = verifyTokensWithLibauth(universe, ctx);
      const admits = (await modelSolver(ctx).check()) === 'sat';
      if (real === true) stats.accept++; else { stats.reject++; if (admits) stats.rejectAdmitted++; }
      if (real === true && !admits) unsound.push(`seed=${seed}\n${describeTx(ctx)}`);
    }
    expect(stats.accept).toBeGreaterThan(0);
    expect(stats.reject).toBeGreaterThan(0);
    expect(unsound, unsound.join('\n\n')).toEqual([]);
  });

  describe('targeted violations of the modelled rules are rejected by both', () => {
    const bch = (script = Script.ATTACKER): ConcreteUtxo => ({ category: NO_CATEGORY, capability: Capability.NONE, script, commitment: new Uint8Array(), fts: 0n, value: 1000n });
    const nft = (category: number, capability: number, commitment = new Uint8Array()): ConcreteUtxo =>
      ({ category, capability, script: Script.FIRST_COVENANT, commitment, fts: 0n, value: 1000n });
    const check = async (ctx: ConcreteTx) => ({ real: verifyTokensWithLibauth(new Universe(7), ctx), admits: (await modelSolver(ctx).check()) === 'sat' });

    it('baseline recreation is accepted by both', async () => {
      const r = await check({ inputs: [nft(1, Capability.MUTABLE), nft(2, Capability.IMMUTABLE, Uint8Array.of(3))], outputs: [nft(1, Capability.MUTABLE), nft(2, Capability.IMMUTABLE, Uint8Array.of(3)), bch()] });
      expect(r).toEqual({ real: true, admits: true });
    });
    it('minting output without a minting input', async () => {
      const r = await check({ inputs: [nft(1, Capability.MUTABLE)], outputs: [nft(1, Capability.MINTING)] });
      expect(r.real).not.toBe(true); expect(r.admits).toBe(false);
    });
    it('more mutable outputs than mutable inputs', async () => {
      const r = await check({ inputs: [nft(1, Capability.MUTABLE)], outputs: [nft(1, Capability.MUTABLE), nft(1, Capability.MUTABLE)] });
      expect(r.real).not.toBe(true); expect(r.admits).toBe(false);
    });
    it('an NFT of a category with no NFT input', async () => {
      const r = await check({ inputs: [bch(), nft(2, Capability.MUTABLE)], outputs: [nft(1, Capability.IMMUTABLE)] });
      expect(r.real).not.toBe(true); expect(r.admits).toBe(false);
    });
    it('a minting input lifts every restriction for its category (and only its category)', async () => {
      const ok = await check({ inputs: [nft(1, Capability.MINTING)], outputs: [nft(1, Capability.MINTING), nft(1, Capability.MUTABLE), nft(1, Capability.IMMUTABLE, Uint8Array.of(9))] });
      expect(ok).toEqual({ real: true, admits: true });
      const other = await check({ inputs: [nft(1, Capability.MINTING)], outputs: [nft(2, Capability.IMMUTABLE)] });
      expect(other.real).not.toBe(true); expect(other.admits).toBe(false);
    });
    it('known imprecision: unmatched immutable commitments are rejected on chain but admitted by the model', async () => {
      // Sound (the model is a superset) and irrelevant to capability movement; documented in docs/scope.md.
      const r = await check({ inputs: [nft(1, Capability.IMMUTABLE, Uint8Array.of(1))], outputs: [nft(1, Capability.IMMUTABLE, Uint8Array.of(2))] });
      expect(r.real).not.toBe(true); expect(r.admits).toBe(true);
    });
  });
});
