import { beforeAll, describe, expect, it } from 'vitest';
import { TALLIED_CATEGORIES, SINGLE_USE_POLICY } from '../src/covenants/common.js';
import { GUARDED_PRICE_REGISTRY, functionName, unmodelledCovenantScripts } from '../src/covenants/registry.js';
import {
  adjacencyWitness, forgedFunctionNftWitness, leakWitness, preservationWitness, singleUseWitness,
  stateShapeWitness,
} from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import { any, getContext, type Bool, type Z3 } from '../src/z3.js';
import { CAPACITY, decideWhole, realInputShape } from './wholeSystemReport.js';

/**
 * The whole system with every price thread on `PriceContractGuarded`: the published contracts, except
 * that the price contract's `sharePrice` also refuses a borrow whose free outputs 7 to 9 hold any token
 * but one of the new loan's loanKey category without capability.
 *
 * Under that registry `singleUse` is an invariant of the system, so this file proves the full
 * `SINGLE_USE_POLICY`, not `SYSTEM_POLICY`: every clause assumed of the inputs is discharged on the
 * outputs, each witness with its positive control, and every modelled function is still alive, so the
 * guard does not hold by blocking borrows.
 *
 * Two conditions stay outside the proof. `migrateContract` is excluded from the registry as before, so
 * the result holds while the oracle migration key keeps every price thread on this code; one thread
 * left on `PriceContract` is the published system, where `whole-system-origin-proof.test.ts` finds the
 * borrow that keeps its origin-proof NFT. And the base case is the chain state when the last thread
 * moves, not genesis: every origin-proof NFT still unspent on `LoanKeyOriginProof`.
 */
let z3: Z3;
let built: BuiltWholeSystem;

beforeAll(async () => {
  z3 = await getContext();
  built = buildWholeSystem(z3, {
    ...CAPACITY,
    categories: TALLIED_CATEGORIES,
    policy: SINGLE_USE_POLICY,
    registry: GUARDED_PRICE_REGISTRY,
    unmodelledScripts: unmodelledCovenantScripts(GUARDED_PRICE_REGISTRY),
  });
});

/** "Some input runs this function, on the UTXO the deployment actually puts there" (see whole-system.test.ts). */
function runsForReal(script: number, abiIndex: number): Bool {
  return any(z3, built.sites
    .filter((site) => site.script === script && site.abiIndex === abiIndex && site.paths > 0)
    .map((site) => {
      const indicator = z3.Bool.const(site.selector);
      const shape = realInputShape(z3, built.tx.inputs[site.index]!, script, SINGLE_USE_POLICY);
      return shape === null ? indicator : z3.And(indicator, shape);
    }));
}

const witnesses: { label: string; build: () => Bool }[] = [
  { label: 'leak', build: () => leakWitness(z3, built.tx, SINGLE_USE_POLICY) },
  { label: 'preservation', build: () => preservationWitness(z3, built.tx, SINGLE_USE_POLICY) },
  { label: 'forged', build: () => forgedFunctionNftWitness(z3, built.tx, SINGLE_USE_POLICY) },
  { label: 'adjacency', build: () => adjacencyWitness(z3, built.tx, SINGLE_USE_POLICY) },
  { label: 'state-shape', build: () => stateShapeWitness(z3, built.tx, SINGLE_USE_POLICY) },
  { label: 'single-use', build: () => singleUseWitness(z3, built.tx, SINGLE_USE_POLICY) },
];

describe('whole-system proof with the guarded price contract', () => {
  it('the registry covers every covenant of the system', () => {
    expect(unmodelledCovenantScripts(GUARDED_PRICE_REGISTRY)).toEqual([]);
  });

  for (const witness of witnesses) {
    it(`${witness.label}: unsat, and the positive control fires`, async () => {
      const { verdict, report } = await decideWhole(built, `guarded-${witness.label}`, [witness.build()]);
      expect(verdict, report).toBe('unsat');
      const control = await decideWhole(
        built, `control-guarded-${witness.label}`, [witness.build()], { withoutCovenants: true },
      );
      expect(control.verdict).toBe('sat');
    });
  }

  describe('every covenant function the registry models is alive', () => {
    const functions = [...GUARDED_PRICE_REGISTRY].flatMap(([script, entry]) =>
      (entry.abiIndices ?? entry.artifact.abi.map((_, i) => i))
        .map((abiIndex) => ({ script, abiIndex, name: functionName(entry, abiIndex) })));
    for (const fn of functions) {
      it(fn.name, async () => {
        const { verdict, report } = await decideWhole(built, `guarded-alive-${fn.name}`, [runsForReal(fn.script, fn.abiIndex)]);
        expect(verdict, report).toBe('sat');
      });
    }
  });
});
