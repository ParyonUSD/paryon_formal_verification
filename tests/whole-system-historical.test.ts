import { beforeAll, describe, expect, it } from 'vitest';
import { LOAN_CATEGORIES, SCRIPT, SYSTEM_POLICY } from '../src/covenants/common.js';
import {
  LOAN_SUBSYSTEM_REGISTRY, unmodelledCovenantScripts, type CovenantRegistry,
} from '../src/covenants/registry.js';
import { forgedFunctionNftWitness, leakWitness } from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import type { Artifact } from '../src/script/fromArtifact.js';
import { getContext, type Z3 } from '../src/z3.js';
import { decideWhole } from './wholeSystemReport.js';
import manageBuggy from './fixtures/manageBuggy.js';

/**
 * The historical manage-close leak, caught with no template at all.
 *
 * `tests/historical-leak.test.ts` proves the pre-fix `manage.cash` leaks the loan's mutable NFT — but
 * it has to be told the transaction: the price contract at input 0, the loan at 1, its sidecar at 2,
 * the manage function NFT at 3, the loanKey at 4, and which of those may carry a capability. Someone
 * had to know the shape of the attack to write that down.
 *
 * This is the same bug found with none of it. The registry says only "the FN_MANAGE script runs this
 * artifact"; the solver assembles the whole transaction — that a loan must sit next to its sidecar and
 * two before its function NFT, that the price contract has to be present and recreated, that the close
 * branch frees the mutable NFT — out of the bytecode. That is the property the whole-system
 * formulation is for: it can find an attack nobody thought to template.
 */
const CAPACITY = { nInputs: 8, nOutputs: 9 };

let z3: Z3;
let buggy: BuiltWholeSystem;
beforeAll(async () => {
  z3 = await getContext();
  // Only one entry differs from the proven build: the manage function's artifact.
  const registry: CovenantRegistry = new Map(LOAN_SUBSYSTEM_REGISTRY);
  registry.set(SCRIPT.FN_MANAGE, { artifact: manageBuggy as unknown as Artifact });
  buggy = buildWholeSystem(z3, {
    ...CAPACITY,
    categories: LOAN_CATEGORIES,
    policy: SYSTEM_POLICY,
    registry,
    unmodelledScripts: unmodelledCovenantScripts(registry),
  });
});

describe('whole-system: the pre-fix manage still leaks, with no template', () => {
  it('the leak witness is satisfiable', async () => {
    const { verdict, report } = await decideWhole(buggy, 'buggy-manage-leak', [leakWitness(z3, buggy.tx, SYSTEM_POLICY)]);
    // The counterexample is printed on failure; on success it is the finding, so log it either way.
    console.log(report);
    expect(verdict).toBe('sat');
  });

  it('and so is the function-NFT authenticity witness (the freed mutable forges a function NFT)', async () => {
    // The same unburned mutable loan NFT can instead be spent into an immutable NFT of the paryon
    // category with a one-byte commitment — the shape `Loan.interact` accepts as its delegate — on any
    // script. The template proof reports this half only under its governed-inputs restriction.
    const { verdict, report } = await decideWhole(
      buggy, 'buggy-manage-forged', [forgedFunctionNftWitness(z3, buggy.tx, SYSTEM_POLICY)],
    );
    console.log(report);
    expect(verdict).toBe('sat');
  });
});
