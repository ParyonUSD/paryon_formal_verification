import { Capability, NO_CATEGORY, Script, type SymbolicTx } from '../src/model.js';
import { CAT, SCRIPT } from '../src/covenants/ids.js';
import { modelNative, Z3_INSTALL_HINT, type Bool } from '../src/z3.js';
import type { BuiltWholeSystem } from '../src/script/wholeSystem.js';

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
    `commit=${get('commitment')}/len=${get('commitmentLength')}`,
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
  built: BuiltWholeSystem, label: string, extra: Bool[] = [],
): Promise<{ verdict: 'sat' | 'unsat'; report: string }> {
  let result: Awaited<ReturnType<typeof modelNative>>;
  try {
    result = await modelNative(built.solverFor(extra), label);
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
