import { beforeAll, describe, expect, it } from 'vitest';
import { TALLIED_CATEGORIES, SCRIPT, SYSTEM_POLICY } from '../src/covenants/common.js';
import { SYSTEM_REGISTRY, functionName, unmodelledCovenantScripts } from '../src/covenants/registry.js';
import {
  adjacencyWitness, forgedFunctionNftWitness, leakWitness, preservationWitness, stateShapeWitness,
} from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import { any, getContext, type Bool, type Z3 } from '../src/z3.js';
import { CAPACITY, decideWhole, realInputShape } from './wholeSystemReport.js';

/**
 * The proof. One symbolic transaction, no transaction template anywhere.
 *
 * Everything the model knows is: the CashTokens tally, the invariant assumed of the inputs
 * (`SYSTEM_POLICY`), and one rule per input — if this input's locking script is a registered covenant,
 * that covenant's bytecode runs at this index. The solver chooses how many inputs and outputs there
 * are, which covenant sits where, which function each one runs, and whether several operations share
 * the transaction. Nothing pins an index, a category or a script.
 *
 * Each of the five invariants `SYSTEM_POLICY` assumes of the inputs is discharged on the outputs by
 * its own witness, so the induction is closed rather than assumed:
 *
 *   ownership          -> leakWitness                (a privileged capability off its owner)
 *   function-NFT sites -> forgedFunctionNftWitness   (a function NFT off its script)
 *   function NFTs live -> preservationWitness        (a spent function NFT not recreated)
 *   sidecar adjacency  -> adjacencyWitness           (a state NFT with no sidecar after it)
 *   state identifiers  -> stateShapeWitness          (a loan/price output with the wrong first byte)
 *
 * Each witness also gets a positive control: dropping the covenant implications must make it sat, or
 * the unsat above would prove nothing.
 */
let z3: Z3;
let built: BuiltWholeSystem;
beforeAll(async () => {
  z3 = await getContext();
  built = buildWholeSystem(z3, {
    ...CAPACITY,
    categories: TALLIED_CATEGORIES,
    policy: SYSTEM_POLICY,
    registry: SYSTEM_REGISTRY,
    unmodelledScripts: unmodelledCovenantScripts(SYSTEM_REGISTRY),
  });
  const { interpretations, totalPaths, deadSites, maxOutputIndex, interpretMs } = built.stats;
  // A measurement, not an assertion: `deadSites` are the (function, index) pairs the contracts' own
  // `require(this.activeInputIndex == K)` rules out, which is the model working as intended. The
  // capacity cuts are the ones that need an argument, so those are asserted below.
  console.log(
    `whole-system build: ${interpretations} interpretations in ${interpretMs}ms, ${totalPaths} paths, `
    + `${deadSites} dead sites, max output index ${maxOutputIndex}`,
  );
});

/** Every (covenant script, ABI function) the registry models, with its name. */
function modelledFunctions(): { script: number; abiIndex: number; name: string }[] {
  return [...SYSTEM_REGISTRY].flatMap(([script, entry]) =>
    (entry.abiIndices ?? entry.artifact.abi.map((_, i) => i))
      .map((abiIndex) => ({ script, abiIndex, name: functionName(entry, abiIndex) })));
}

/**
 * "Some input runs this function, on the UTXO the deployment actually puts there."
 *
 * `runsSomewhere` alone is too weak to mean non-vacuity: a covenant that derives its category from its
 * own input — `manage` reads `paryonTokenId` off the function NFT it runs on — is equally happy in a
 * parallel universe of junk categories, so the liveness check would pass without the real system ever
 * appearing. This pins the running input to the category, capability and identifier the policy gives
 * that script (`realInputShape`), where there is one.
 */
function runsForReal(script: number, abiIndex: number): Bool {
  const disjuncts = built.sites
    .filter((site) => site.script === script && site.abiIndex === abiIndex && site.paths > 0)
    .map((site) => {
      const indicator = z3.Bool.const(site.selector);
      const shape = realInputShape(z3, built.tx.inputs[site.index]!, script, SYSTEM_POLICY);
      return shape === null ? indicator : z3.And(indicator, shape);
    });
  return any(z3, disjuncts);
}

const witnesses: { name: string; label: string; build: () => Bool }[] = [
  { name: 'no privileged capability can leak', label: 'leak', build: () => leakWitness(z3, built.tx, SYSTEM_POLICY) },
  {
    name: 'no function NFT is lost', label: 'preservation',
    build: () => preservationWitness(z3, built.tx, SYSTEM_POLICY),
  },
  {
    name: 'no function NFT can be forged', label: 'forged',
    build: () => forgedFunctionNftWitness(z3, built.tx, SYSTEM_POLICY),
  },
  {
    name: 'every state NFT keeps its sidecar next to it', label: 'adjacency',
    build: () => adjacencyWitness(z3, built.tx, SYSTEM_POLICY),
  },
  {
    name: 'every loan and price output keeps its state identifier', label: 'state-shape',
    build: () => stateShapeWitness(z3, built.tx, SYSTEM_POLICY),
  },
];

describe('whole-system proof', () => {
  it('the registry covers every covenant of the system', () => {
    expect(unmodelledCovenantScripts(SYSTEM_REGISTRY)).toEqual([]);
  });

  it('the capacity cuts exactly the sites it is known to cut', () => {
    // Where the *bound*, not a contract, pruned a path: the build then concludes that covenant cannot
    // sit at that index, which is a hole unless the shape is genuinely outside the bound. All five are.
    // `Loan.interact` and `StabilityPool.interact` read their function NFT at `activeInputIndex + 2`
    // and `StabilityPoolSidecar.attach` reads it at `activeInputIndex + 1`, so a loan or pool that late
    // needs a 10th input, more than this build carries. Every operation places the loan at input 0, 1
    // or 6 and the pool at 0 or 4, so none is lost; a loan or pool that late in a longer input list is
    // outside the proof. A cut anywhere else fails here.
    expect(built.cutSites.map((site) => `${site.name}@${site.index} (${site.reads.join(',')})`)).toEqual([
      'Loan.interact@7 (in9)',
      'Loan.interact@8 (in9)',
      'StabilityPool.interact@7 (in9)',
      'StabilityPool.interact@8 (in9)',
      'StabilityPoolSidecar.attach@8 (in9)',
    ]);
  });

  it('is satisfiable (the model is not vacuously over-constrained)', async () => {
    const { verdict, report } = await decideWhole(built, 'base');
    expect(verdict, report).toBe('sat');
  });

  describe('every covenant function the registry models is alive', () => {
    // A function no input can run contributes nothing: its share of the proof would be vacuous. This
    // asserts that for each one there IS a transaction in which the solver runs it.
    for (const fn of modelledFunctions()) {
      it(fn.name, async () => {
        const { verdict, report } = await decideWhole(built, `alive-${fn.name}`, [runsForReal(fn.script, fn.abiIndex)]);
        expect(verdict, report).toBe('sat');
      });
    }
  });

  it('a genesis mint needs an outpoint at index 0, and the contract says so', async () => {
    // `LoanKeyFactory.create` derives a brand-new category from `tx.inputs[0].outpointTransactionHash`,
    // which CashTokens only allows when that input spends an output at index 0. The contract states the
    // precondition itself (`require(tx.inputs[0].outpointIndex == 0)`) and, outpoint indices being
    // modelled, the model decides it — so no genesis rule is assumed anywhere.
    const runs = built.runsSomewhere(SCRIPT.LOANKEY_FACTORY, 0);
    const notGenesis = built.tx.inputs[0]!.outpointIndex.neq(0);
    const { verdict, report } = await decideWhole(built, 'genesis-needs-vout0', [runs, notGenesis]);
    expect(verdict, report).toBe('unsat');
  });

  describe('the invariant is preserved: every witness is unsatisfiable', () => {
    for (const witness of witnesses) {
      it(`${witness.name} (${witness.label} witness unsat)`, async () => {
        const { verdict, report } = await decideWhole(built, witness.label, [witness.build()]);
        expect(verdict, report).toBe('unsat');
      });
    }
  });

  describe('positive controls: without the covenants, every witness fires', () => {
    // Consensus and the inductive hypothesis alone do not stop any of these, so each unsat above is
    // the contracts' doing and not an artefact of an over-constrained or contradictory witness.
    for (const witness of witnesses) {
      it(`${witness.label} is satisfiable without the covenant implications`, async () => {
        const { verdict } = await decideWhole(built, `control-${witness.label}`, [witness.build()], {
          withoutCovenants: true,
        });
        expect(verdict, `the ${witness.label} witness cannot fire even unconstrained: it proves nothing`)
          .toBe('sat');
      });
    }
  });
});
