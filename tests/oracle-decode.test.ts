import { OpcodesBch2023, decodeAuthenticationInstructions, hexToBin } from '@bitauth/libauth';
import { paryonArtifacts } from '@paryonusd/contracts';
import { describe, expect, it } from 'vitest';
import { scriptToBytecode } from '../src/oracle/concrete.js';
import { asmToScript, type Script } from '../src/script/script.js';

/**
 * The artifact decoder (`asmToScript`, from @cashscript/utils) is the one CashScript-provided step in
 * the pipeline. Cross-check it against libauth on every ParyonUSD artifact: an independent ASM reading
 * using libauth's opcode table must decode to the same instruction sequence, and re-encoding our decoded
 * script with libauth then decoding it again must round-trip.
 */
interface ArtifactLike { contractName: string; bytecode: string }

function collectArtifacts(node: unknown, out: ArtifactLike[] = []): ArtifactLike[] {
  if (!node || typeof node !== 'object') return out;
  const candidate = node as Partial<ArtifactLike> & { abi?: unknown };
  if (typeof candidate.bytecode === 'string' && typeof candidate.contractName === 'string' && candidate.abi) out.push(candidate as ArtifactLike);
  else for (const child of Object.values(node)) collectArtifacts(child, out);
  return out;
}

/** Read CashScript ASM with libauth's opcode names only (no CashScript code involved). */
function asmToScriptViaLibauth(asm: string): Script {
  const table = OpcodesBch2023 as unknown as Record<string, number | string>;
  return asm.split(/\s+/).filter(Boolean).map((token) => {
    if (token.startsWith('OP_')) {
      const op = table[token];
      if (typeof op !== 'number') throw new Error(`unknown opcode ${token}`);
      return op;
    }
    return hexToBin(token);
  });
}

/** Push-only instructions carry their data; everything else is an opcode. */
function libauthDecodedToScript(bytecode: Uint8Array): Script {
  return decodeAuthenticationInstructions(bytecode).map((instr) => ('data' in instr && instr.opcode <= 0x4e ? instr.data : instr.opcode));
}

const eq = (a: Script, b: Script): boolean =>
  a.length === b.length && a.every((x, i) => {
    const y = b[i]!;
    if (x instanceof Uint8Array && y instanceof Uint8Array) return x.length === y.length && x.every((byte, k) => byte === y[k]);
    return x === y;
  });

describe('artifact decoding vs libauth', () => {
  const artifacts = collectArtifacts(paryonArtifacts);
  it('finds the ParyonUSD artifacts', () => { expect(artifacts.length).toBeGreaterThan(20); });

  for (const artifact of artifacts) {
    it(`${artifact.contractName}: cashscript ASM decode == libauth ASM decode == libauth bytecode round-trip`, () => {
      // Compare by pushed value: cashscript reads OP_0 as an empty data push where libauth names opcode 0, and the
      // minimal push encoder turns 1-byte constants 1..16 into OP_N. The interpreter treats all of these identically.
      const normalise = (s: Script): Script => s.map((x) => (typeof x === 'number' && x >= 0x51 && x <= 0x60 ? Uint8Array.of(x - 0x50) : x === 0 ? new Uint8Array() : x));
      const ours = asmToScript(artifact.bytecode);
      expect(eq(normalise(ours), normalise(asmToScriptViaLibauth(artifact.bytecode)))).toBe(true);
      expect(eq(normalise(libauthDecodedToScript(scriptToBytecode(ours))), normalise(ours))).toBe(true);
    });
  }
});
