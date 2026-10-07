import { Capability, NO_CATEGORY, Script, type SymbolicTx, type Utxo } from '../src/model.js';
import type { LeakPolicy } from '../src/policy.js';
import { CAT, SCRIPT } from '../src/covenants/ids.js';
import { modelNative, Z3_INSTALL_HINT, type Bool, type Z3 } from '../src/z3.js';
import type { BuiltWholeSystem } from '../src/script/wholeSystem.js';

/**
 * The capacity every whole-system build uses: transactions with at most 9 inputs and 11 outputs.
 *
 * 9 inputs is the smallest that admits every operation: `swapInRedemption` requires
 * `this.activeInputIndex == 8`, so at 8 inputs the whole swap (both loan functions and
 * `Redemption.swapTargetLoan`) is dead. 11 outputs is the smallest that keeps the proof meaningful:
 * `Borrowing.borrow` and `Redeemer.createRedemption` read output 9, so 10 slots are pinned and an
 * eleventh is needed for the unpinned slot a leak would have to land in (`buildWholeSystem` refuses a
 * capacity without one).
 */
export const CAPACITY = { nInputs: 9, nOutputs: 11 };

/**
 * Turning a whole-system counterexample back into a readable transaction.
 *
 * A template's counterexample is easy to read because the shape is known; here the solver chose the
 * shape, so the report has to say what it chose: which covenant sits at each input, which of its
 * functions the model says runs there, and every field that can carry a capability.
 */
const CATEGORY_NAME = new Map<number, string>(Object.entries(CAT).map(([name, id]) => [id, name]));
const SCRIPT_NAME = new Map<number, string>([
  [Script.ATTACKER, 'ATTACKER'],
  [Script.BURN, 'BURN'],
  ...Object.entries(SCRIPT).map(([name, id]): [number, string] => [id, name]),
]);
const CAPABILITY_NAME = new Map<number, string>([
  [Capability.NONE, '-'], [Capability.IMMUTABLE, 'immutable'],
  [Capability.MUTABLE, 'MUTABLE'], [Capability.MINTING, 'MINTING'],
]);

/**
 * The shape the deployment gives a UTXO sitting on a covenant script, derived from the policy rather
 * than hand-written: the function NFTs' category, capability and identifier, and the owners' privileged
 * (category, capability) pairs, and, under a policy with `singleUse`, the proofs' category. Null for the
 * sidecars and the loanKey origin pair (the proof too under a policy without `singleUse`), which hold
 * categories the policy says nothing about.
 *
 * The liveness checks use it so that "this covenant function is alive" means it runs on the real UTXO.
 * Without it the solver can satisfy them with a parallel universe: `manage` takes its paryon category
 * from its own input, so a junk category with a matching NFT on an attacker script runs it just fine.
 */
export function realInputShape(z3: Z3, utxo: Utxo, script: number, policy: LeakPolicy): Bool | null {
  for (const rule of policy.functionNfts ?? []) {
    const commitment = rule.commitments?.[script];
    if (commitment === undefined) continue;
    return z3.And(
      utxo.present, utxo.category.eq(rule.category), utxo.capability.eq(Capability.IMMUTABLE),
      utxo.commitment.eq(commitment), utxo.commitmentLength.eq(rule.commitmentLength),
    );
  }
  for (const rule of policy.singleUse ?? []) {
    if (rule.script !== script) continue;
    return z3.And(utxo.present, utxo.category.eq(rule.category), utxo.capability.eq(Capability.IMMUTABLE));
  }
  for (const rule of policy.ownership) {
    if (!rule.scripts.includes(script)) continue;
    return z3.And(utxo.present, utxo.category.eq(rule.category), utxo.capability.eq(rule.capability));
  }
  return null;
}

const int = (model: Map<string, string>, name: string): number => Number(model.get(name) ?? '0');
const bool = (model: Map<string, string>, name: string): boolean => model.get(name) === 'true';

function describeSlot(model: Map<string, string>, txPrefix: string, side: 'in' | 'out', i: number): string | null {
  const prefix = `${txPrefix}${side}${i}.`;
  const get = (name: string): number => int(model, `${prefix}${name}`);
  if (!bool(model, `${prefix}present`)) return null;
  const category = get('category');
  const capability = get('capability');
  const script = get('script');
  const parts = [
    `${side}${i}`,
    `script=${SCRIPT_NAME.get(script) ?? script}(${script})`,
    `cat=${category === NO_CATEGORY ? 'none' : `${CATEGORY_NAME.get(category) ?? category}(${category})`}`,
    `cap=${CAPABILITY_NAME.get(capability) ?? capability}`,
    `commit=${get('commitment')}/len=${get('commitmentLength')}/head=0x${get('commitmentHead').toString(16).padStart(2, '0')}`,
    `fts=${get('fts')} value=${get('value')}`,
  ];
  if (side === 'in') parts.push(`outpoint=${get('outpointTx')}:${get('outpointIndex')}`);
  return parts.join(' ');
}

/** A full, readable counterexample: every present slot plus the covenant functions the model runs. */
export function describeCounterexample(built: BuiltWholeSystem, model: Map<string, string>): string {
  const tx: SymbolicTx = built.tx;
  const lines: string[] = [];
  lines.push('inputs:');
  tx.inputs.forEach((_utxo, i) => {
    const slot = describeSlot(model, tx.prefix, 'in', i);
    if (slot === null) return;
    const running = built.sites
      .filter((site) => site.index === i && bool(model, site.selector)).map((site) => site.name);
    lines.push(`  ${slot}${running.length > 0 ? `  runs: ${running.join(', ')}` : '  runs: -'}`);
  });
  lines.push('outputs:');
  tx.outputs.forEach((_utxo, i) => {
    const slot = describeSlot(model, tx.prefix, 'out', i);
    if (slot !== null) lines.push(`  ${slot}`);
  });
  return lines.join('\n');
}

/**
 * Decide one whole-system query in a native z3 process and, when it is satisfiable, render the
 * counterexample. `unknown` is a hard failure: a witness query that read it as "not sat" would pass a
 * control that should have found a leak.
 */
export async function decideWhole(
  built: BuiltWholeSystem, label: string, extra: Bool[] = [], options: { withoutCovenants?: boolean } = {},
): Promise<{ verdict: 'sat' | 'unsat'; report: string }> {
  let result: Awaited<ReturnType<typeof modelNative>>;
  try {
    result = await modelNative(built.solverFor(extra, options), label);
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    throw new Error(err.code === 'ENOENT' ? Z3_INSTALL_HINT : err.message);
  }
  if (result.verdict !== 'sat') {
    if (result.verdict === 'unknown') throw new Error(`native z3 returned unknown for ${label}`);
    return { verdict: 'unsat', report: '' };
  }
  return { verdict: 'sat', report: `\ncounterexample for ${label}:\n${describeCounterexample(built, result.model)}\n` };
}
