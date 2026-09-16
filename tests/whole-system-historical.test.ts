import { beforeAll, describe, expect, it } from 'vitest';
import { LOAN_CATEGORIES, SCRIPT, SYSTEM_POLICY } from '../src/covenants/common.js';
import { SYSTEM_REGISTRY, unmodelledCovenantScripts, type CovenantRegistry } from '../src/covenants/registry.js';
import { leakWitness } from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import type { Artifact } from '../src/script/artifact.js';
import { getContext, type Z3 } from '../src/z3.js';
import { CAPACITY, decideWhole } from './wholeSystemReport.js';
import manageBuggy from './fixtures/manageBuggy.js';
import parityUpdatePeriodBuggy from './fixtures/parityUpdatePeriodBuggy.js';

/**
 * Two real historical capability leaks, and one deliberately broken composition. All three are found
 * with no transaction template: the registry says only which script runs which artifact, and the
 * solver assembles the attack out of the bytecode.
 *
 * That is the point of the whole-system formulation. The template proofs caught the same two bugs, but
 * only because someone had already written down the shape of the attack — the price contract at input
 * 0, the loan at 1, its sidecar at 2, the manage NFT at 3, and which inputs were allowed to carry a
 * capability. Here nothing is written down, so the check can find an attack nobody thought to template.
 */
let z3: Z3;
beforeAll(async () => { z3 = await getContext(); });

/**
 * The system build with one registry entry replaced or removed.
 *
 * `keepUnmodelledInputs` drops the scope restriction that normally keeps the UTXOs of an unregistered
 * covenant off the inputs. Removing a covenant from the registry otherwise removes both its output
 * pins *and* its UTXOs, and the second cancels the first; the control wants only the first — the
 * covenant's code gone while its UTXOs are still spendable.
 */
function buildWith(
  override: (registry: CovenantRegistry) => void, keepUnmodelledInputs = false,
): BuiltWholeSystem {
  const registry: CovenantRegistry = new Map(SYSTEM_REGISTRY);
  override(registry);
  return buildWholeSystem(z3, {
    ...CAPACITY,
    categories: LOAN_CATEGORIES,
    policy: SYSTEM_POLICY,
    registry,
    unmodelledScripts: keepUnmodelledInputs ? [] : unmodelledCovenantScripts(registry),
  });
}

async function expectLeak(built: BuiltWholeSystem, label: string): Promise<void> {
  const { verdict, report } = await decideWhole(built, label, [leakWitness(z3, built.tx, SYSTEM_POLICY)]);
  console.log(report); // on success the counterexample IS the finding, so print it either way
  expect(verdict).toBe('sat');
}

describe('historical leaks, caught without a template', () => {
  it('pre-fix manage: closing a loan without burning its mutable NFT leaks it', async () => {
    // Fixed 2026-04. The close branch did not send the loan's mutable NFT to an OP_RETURN, leaving its
    // output slot free. The solver has to discover that a loan sits next to its outpoint-adjacent
    // sidecar with the manage function NFT two slots on, and that the price contract must be present.
    await expectLeak(
      buildWith((r) => r.set(SCRIPT.FN_MANAGE, { artifact: manageBuggy as unknown as Artifact })),
      'buggy-manage-leak',
    );
  });

  it('pre-fix Borrowing.updatePeriodState: the output cap checked the wrong index', async () => {
    // Fixed 2025-11 (paryon_contracts 3e9cf60). The contract capped the transaction at 2 outputs "to
    // protect minting capability" but checked the optional change output at `tx.outputs[2]`, a slot the
    // cap makes unreachable, leaving output 1 free next to a paryon *minting* input.
    await expectLeak(
      buildWith((r) => {
        const borrowing = r.get(SCRIPT.BORROWING)!;
        r.set(SCRIPT.BORROWING, { ...borrowing, artifact: parityUpdatePeriodBuggy as unknown as Artifact });
      }),
      'buggy-updateperiodstate-leak',
    );
  });
});

describe('composition matters: a missing covenant is a leak', () => {
  it('without the Redemption covenant, the redemption mutable NFT leaks', async () => {
    // The whole-system replacement for the old per-template "composition matters" controls: the proof
    // holds because each covenant constrains its own outputs, and dropping one has to break it.
    // Without `Redemption`'s code, spending a redemption's mutable NFT pins nothing and it goes
    // straight to an attacker — so the unsat in whole-system.test.ts is a statement about the
    // contracts, not about a model that cannot express a leak.
    await expectLeak(buildWith((r) => r.delete(SCRIPT.REDEMPTION), true), 'no-redemption-leak');
  });
});
