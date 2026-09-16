import { beforeAll, describe, expect, it } from 'vitest';
import { Capability } from '../src/model.js';
import { CAT, LOAN_CATEGORIES, SCRIPT, SYSTEM_POLICY } from '../src/covenants/common.js';
import { LOAN_SUBSYSTEM_REGISTRY, unmodelledCovenantScripts } from '../src/covenants/registry.js';
import { forgedFunctionNftWitness, leakWitness, preservationWitness } from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import { any, getContext, type Z3 } from '../src/z3.js';
import { decideWhole } from './wholeSystemReport.js';

/**
 * The whole-system proof for the loan subsystem: no transaction shape is written down anywhere.
 *
 * Every other artifact test is a *template*: it declares which covenant runs at which input index,
 * pins the input shapes by hand, and names the indices allowed to carry a privileged capability. Here
 * the only statements are the CashTokens tally, the inductive hypothesis on the inputs, and one rule
 * per input: if this input's locking script is a registered covenant, then that covenant's bytecode
 * runs at this index. The solver picks how many inputs and outputs there are, which covenant sits
 * where, and whether several operations share the transaction — batching included. See
 * `src/script/wholeSystem.ts` for why removing the pins can only widen the admitted set, and
 * `src/covenants/registry.ts` for the one scope assumption that remains while only this subsystem is
 * registered (UTXOs of the covenants this build cannot execute stay out of the transaction).
 *
 * Capacity: 8 inputs, 9 outputs. The proof is about transactions within that bound.
 */
const CAPACITY = { nInputs: 8, nOutputs: 9 };

let z3: Z3;
let built: BuiltWholeSystem;
beforeAll(async () => {
  z3 = await getContext();
  built = buildWholeSystem(z3, {
    ...CAPACITY,
    categories: LOAN_CATEGORIES,
    policy: SYSTEM_POLICY,
    registry: LOAN_SUBSYSTEM_REGISTRY,
    unmodelledScripts: unmodelledCovenantScripts(LOAN_SUBSYSTEM_REGISTRY),
  });
  const { interpretations, totalPaths, deadSites, outOfCapacity, maxOutputIndex, interpretMs } = built.stats;
  // Not an assertion, a measurement: `deadSites` are (function, index) pairs the contracts' own
  // `require(this.activeInputIndex == K)` rules out, and `outOfCapacity` is where the *bound* — not a
  // contract — cut a path, which is exactly what a reader of a bounded proof needs to know.
  console.log(
    `whole-system build: ${interpretations} interpretations in ${interpretMs}ms, ${totalPaths} paths, `
    + `${deadSites} dead sites, ${outOfCapacity} paths cut by the capacity, max output index ${maxOutputIndex}`,
  );
});

/** Every distinct (covenant script, ABI function) the registry models. */
function registeredFunctions(): { script: number; abiIndex: number; name: string }[] {
  const seen = new Set<string>();
  return built.sites.filter((site) => {
    const key = `${site.script}:${site.abiIndex}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).map(({ script, abiIndex, name }) => ({ script, abiIndex, name }));
}

describe('whole-system loan subsystem — no transaction template', () => {
  it('is satisfiable (the model is not vacuously over-constrained)', async () => {
    const { verdict, report } = await decideWhole(built, 'base');
    expect(verdict, report).toBe('sat');
  });

  it('admits a genuine loan operation (the shape is discovered, not pinned)', async () => {
    // Nothing says a loan exists; this asserts one does and lets the solver assemble the rest of the
    // transaction from the bytecode. Without it, leak-freedom could hold because no loan is spendable.
    const loanInput = any(z3, built.tx.inputs.map((utxo) => z3.And(
      utxo.present, utxo.script.eq(SCRIPT.LOAN), utxo.category.eq(CAT.PARYON), utxo.capability.eq(Capability.MUTABLE),
    )));
    const { verdict, report } = await decideWhole(built, 'real-loan', [loanInput]);
    expect(verdict, report).toBe('sat');
  });

  describe('every registered covenant function is alive in the model', () => {
    // A function no input can run contributes nothing: its share of the proof would be vacuous. This
    // asserts that for each one there IS a transaction in which it runs.
    for (const fn of [
      { script: SCRIPT.LOAN, abiIndex: 0, name: 'Loan.interact' },
      { script: SCRIPT.LOAN_SIDECAR, abiIndex: 0, name: 'LoanTokenSidecar.attach' },
      { script: SCRIPT.FN_MANAGE, abiIndex: 0, name: 'manageLoan.manage' },
      { script: SCRIPT.FN_CHANGE_INTEREST, abiIndex: 0, name: 'changeInterest.changeInterest' },
      { script: SCRIPT.FN_PAY_INTEREST, abiIndex: 0, name: 'payInterest.payInterest' },
      { script: SCRIPT.COLLECTOR, abiIndex: 0, name: 'Collector.collect' },
      { script: SCRIPT.COLLECTOR, abiIndex: 1, name: 'Collector.payToStabilityPool' },
      { script: SCRIPT.PRICE, abiIndex: 0, name: 'PriceContract.updatePrice' },
      { script: SCRIPT.PRICE, abiIndex: 1, name: 'PriceContract.sharePrice' },
    ]) {
      it(fn.name, async () => {
        const { verdict, report } = await decideWhole(built, `alive-${fn.name}`, [built.runsSomewhere(fn.script, fn.abiIndex)]);
        expect(verdict, report).toBe('sat');
      });
    }

    it('the registry list above matches the registry', () => {
      expect(registeredFunctions().map((fn) => fn.name).sort()).toEqual([
        'Collector.collect', 'Collector.payToStabilityPool', 'Loan.interact', 'LoanTokenSidecar.attach',
        'PriceContract.sharePrice', 'PriceContract.updatePrice', 'changeInterest.changeInterest',
        'manageLoan.manage', 'payInterest.payInterest',
      ]);
    });
  });

  it('no privileged capability can leak (leak witness unsat)', async () => {
    const { verdict, report } = await decideWhole(built, 'leak', [leakWitness(z3, built.tx, SYSTEM_POLICY)]);
    expect(verdict, report).toBe('unsat');
  });

  it('no function NFT is lost (preservation witness unsat)', async () => {
    // No `preservedInputsOnlyAt` restriction: in the whole-system model every function NFT's own
    // covenant runs, so there is no ungoverned one to exclude.
    const { verdict, report } = await decideWhole(built, 'preservation', [preservationWitness(z3, built.tx, SYSTEM_POLICY)]);
    expect(verdict, report).toBe('unsat');
  });

  it('no function NFT can be forged (authenticity witness unsat)', async () => {
    const { verdict, report } = await decideWhole(built, 'forged', [forgedFunctionNftWitness(z3, built.tx, SYSTEM_POLICY)]);
    expect(verdict, report).toBe('unsat');
  });
});
