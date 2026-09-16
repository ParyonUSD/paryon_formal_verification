import { beforeAll, describe, expect, it } from 'vitest';
import { SCRIPT, SYSTEM_POLICY, TALLIED_CATEGORIES } from '../src/covenants/common.js';
import { SYSTEM_REGISTRY, type CovenantRegistry } from '../src/covenants/registry.js';
import {
  adjacencyWitness, forgedFunctionNftWitness, leakWitness, preservationWitness, stateShapeWitness,
} from '../src/policy.js';
import { buildWholeSystem, type BuiltWholeSystem } from '../src/script/wholeSystem.js';
import { getContext, type Bool, type Z3 } from '../src/z3.js';
import { CAPACITY, decideWhole } from './wholeSystemReport.js';

/**
 * Which covenants the proof actually rests on.
 *
 * `whole-system.test.ts` shows the five witnesses are unsatisfiable; this shows *why* — that the unsat
 * is each covenant's code doing work, not a model that cannot express a violation. For every
 * registered covenant in turn, its bytecode is removed from the registry while its UTXOs stay
 * spendable, and the witnesses are decided again. A covenant that pins outputs must make at least one
 * of them fire.
 *
 * The exceptions are named and expected: `LoanKeyOriginEnforcer`, `LoanKeyOriginProof` and
 * `RedemptionSidecar` check input adjacency and authenticity and pin no output at all, so removing
 * them cannot open a violation. The old per-template "composition matters" controls checked one
 * partner each; this checks all 26.
 *
 * It is the slow file in the suite (26 builds, 5 native queries each) and lives on its own for that.
 */
const NO_OUTPUT_PINS: number[] = [SCRIPT.ORIGIN_ENFORCER, SCRIPT.ORIGIN_PROOF, SCRIPT.REDEMPTION_SIDECAR];

let z3: Z3;
beforeAll(async () => { z3 = await getContext(); });

/** The system build with one covenant's code removed, its UTXOs still spendable. */
function buildWithout(script: number): BuiltWholeSystem {
  const registry: CovenantRegistry = new Map(SYSTEM_REGISTRY);
  registry.delete(script);
  return buildWholeSystem(z3, {
    ...CAPACITY,
    categories: TALLIED_CATEGORIES,
    policy: SYSTEM_POLICY,
    registry,
    // Not `unmodelledCovenantScripts(registry)`: keeping the removed covenant's UTXOs off the inputs
    // would also remove the spends its missing pins would have governed, and the two cancel out.
    unmodelledScripts: [],
  });
}

function witnessesOf(built: BuiltWholeSystem): { label: string; assertion: Bool }[] {
  return [
    { label: 'leak', assertion: leakWitness(z3, built.tx, SYSTEM_POLICY) },
    { label: 'preservation', assertion: preservationWitness(z3, built.tx, SYSTEM_POLICY) },
    { label: 'forged', assertion: forgedFunctionNftWitness(z3, built.tx, SYSTEM_POLICY) },
    { label: 'adjacency', assertion: adjacencyWitness(z3, built.tx, SYSTEM_POLICY) },
    { label: 'state-shape', assertion: stateShapeWitness(z3, built.tx, SYSTEM_POLICY) },
  ];
}

describe('every covenant that pins an output is load-bearing', () => {
  const started = Date.now();
  const table: string[] = [];

  for (const [script, entry] of SYSTEM_REGISTRY) {
    const name = entry.artifact.contractName;
    it(`without ${name}`, async () => {
      const built = buildWithout(script);
      const fired: string[] = [];
      for (const witness of witnessesOf(built)) {
        const { verdict } = await decideWhole(built, `without-${name}-${witness.label}`, [witness.assertion]);
        if (verdict === 'sat') fired.push(witness.label);
      }
      table.push(`  ${name.padEnd(24)} ${fired.length > 0 ? fired.join(', ') : '— (pins no output)'}`);
      if (NO_OUTPUT_PINS.includes(script)) {
        expect(fired, `${name} pins no output, so nothing should break without it`).toEqual([]);
      } else {
        expect(fired.length, `nothing breaks without ${name}: the proof does not rest on its code`)
          .toBeGreaterThan(0);
      }
    }, 120_000);
  }

  it('reports what each removal breaks', () => {
    console.log(`witnesses that fire when a covenant's code is removed (${Math.round((Date.now() - started) / 1000)}s):`);
    console.log(table.sort().join('\n'));
    expect(table).toHaveLength(SYSTEM_REGISTRY.size);
  });
});
