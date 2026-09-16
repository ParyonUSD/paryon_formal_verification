import { paryonArtifacts } from '@paryonusd/contracts';
import { describe, expect, it } from 'vitest';
import { SCRIPT } from '../src/covenants/ids.js';
import { SYSTEM_REGISTRY, functionName } from '../src/covenants/registry.js';

/**
 * The coverage ledger: every function of every published artifact is either **modelled** — its
 * contract is in `SYSTEM_REGISTRY` and the function is among the ABI indices that registry entry
 * models — or **excluded** in the registry with a written reason.
 *
 * It exists because `Borrowing.updatePeriodState`, a minting-NFT function with a real historical leak,
 * once went unverified while its artifact looked "covered". Registration alone is not coverage, so the
 * other half of the ledger lives in `whole-system.test.ts`, which asserts that every modelled function
 * is *alive*: that there is a transaction in which the solver actually runs it.
 */
interface ArtifactLike {
  contractName: string;
  bytecode: string;
  abi: readonly { name: string }[];
}
function collect(node: unknown, out: ArtifactLike[] = []): ArtifactLike[] {
  if (!node || typeof node !== 'object') return out;
  const a = node as Partial<ArtifactLike>;
  if (a.abi && typeof a.bytecode === 'string' && typeof a.contractName === 'string') out.push(a as ArtifactLike);
  else for (const child of Object.values(node)) collect(child, out);
  return out;
}

/** Registry entries by contract name (the registry is keyed by script id). */
const byContract = new Map([...SYSTEM_REGISTRY].map(([script, entry]) => [entry.artifact.contractName, { script, entry }]));

describe('every artifact function is modelled or excluded with a reason', () => {
  const artifacts = collect(paryonArtifacts);

  for (const artifact of artifacts) {
    for (const [abiIndex, fn] of artifact.abi.entries()) {
      it(`${artifact.contractName}.${fn.name}`, () => {
        const registered = byContract.get(artifact.contractName);
        expect(registered, `${artifact.contractName} is not in SYSTEM_REGISTRY`).toBeDefined();
        const { entry } = registered!;
        const modelled = (entry.abiIndices ?? entry.artifact.abi.map((_, i) => i)).includes(abiIndex);
        const excluded = entry.excluded?.[abiIndex];
        expect(modelled || excluded !== undefined, `${fn.name} is neither modelled nor excluded`).toBe(true);
        expect(modelled && excluded !== undefined, `${fn.name} is both modelled and excluded`).toBe(false);
        if (excluded !== undefined) expect(excluded.length, 'an exclusion needs a reason').toBeGreaterThan(20);
      });
    }
  }

  it('the registry has no stale entries', () => {
    const published = new Set(artifacts.map((a) => a.contractName));
    const stale = [...byContract.keys()].filter((name) => !published.has(name));
    expect(stale).toEqual([]);
    // Every exclusion names a real ABI index of its own artifact.
    const badExclusions = [...SYSTEM_REGISTRY.values()].flatMap((entry) =>
      Object.keys(entry.excluded ?? {}).map(Number)
        .filter((abiIndex) => entry.artifact.abi[abiIndex] === undefined)
        .map((abiIndex) => `${entry.artifact.contractName}[${abiIndex}]`));
    expect(badExclusions).toEqual([]);
    expect(artifacts.length).toBeGreaterThan(20);
  });

  it('every registered script id is distinct and known', () => {
    const known = new Set<number>(Object.values(SCRIPT));
    const unknown = [...SYSTEM_REGISTRY.keys()].filter((id) => !known.has(id));
    expect(unknown).toEqual([]);
    // Every registered function has a name the whole-system test can report.
    for (const [, entry] of SYSTEM_REGISTRY) {
      for (const abiIndex of entry.abiIndices ?? entry.artifact.abi.map((_, i) => i)) {
        expect(functionName(entry, abiIndex)).toMatch(/^\w+\.\w+$/);
      }
    }
  });
});
