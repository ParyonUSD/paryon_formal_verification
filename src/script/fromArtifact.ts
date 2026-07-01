import { addConsensusRules } from '../consensus.js';
import { declareTx, type SymbolicTx } from '../model.js';
import { inputsRespectInvariant, privilegedInputsOnlyAt, type LeakPolicy } from '../policy.js';
import type { Z3, Z3Solver } from '../z3.js';
import { asmToScript } from './script.js';
import { ARG, interpret, seedSelector, type Path, type SVal } from './interpreter.js';

/** Minimal shape of a CashScript artifact we consume. */
export interface Artifact {
  contractName: string;
  bytecode: string;
  constructorInputs: readonly { name: string; type: string }[];
  abi: readonly { name: string; inputs: readonly { name: string; type: string }[] }[];
}

/** One covenant whose bytecode is symbolically executed at a fixed input index. */
export interface CovenantSpec {
  artifact: Artifact;
  activeIndex: number;
  /** Constructor-arg seeds (bottom of stack), in declaration order. */
  seeds?: SVal[];
  /** ABI function index (default 0; loan/partner functions are single-function). */
  abiIndex?: number;
}

export interface ArtifactConfig {
  nInputs: number;
  nOutputs: number;
  /** Category ids the consensus tally is enforced over (the system'solver category universe). */
  categories: number[];
  policy: LeakPolicy;
  designatedInputs: number[];
  /** Template scaffolding: input categories/capabilities/scripts, partner covenants, id bindings. */
  setup: (z3: Z3, solver: Z3Solver, tx: SymbolicTx) => void;
}

export interface BuiltArtifact {
  tx: SymbolicTx;
  policy: LeakPolicy;
  /** One solver per reachable combination of script paths, each fully loaded. */
  solvers: Z3Solver[];
}

function cartesian<T>(lists: T[][]): T[][] {
  return lists.reduce<T[][]>((acc, list) => acc.flatMap((combo) => list.map((x) => [...combo, x])), [[]]);
}

/**
 * Build the leak-check solvers for a transaction whose covenant logic is derived
 * by symbolically executing the contracts' compiled artifact bytecode. Pass one
 * `CovenantSpec` per contract that runs in the transaction (e.g. swapOut + swapIn).
 * The template `setup` still declares the transaction shape (inputs) and any
 * partner covenants kept hand-modelled.
 */
export function buildFromArtifact(z3: Z3, specs: CovenantSpec[], cfg: ArtifactConfig): BuiltArtifact {
  const tx = declareTx(z3, cfg.nInputs, cfg.nOutputs);

  const perCovenantPaths: Path[][] = specs.map((spec) => {
    const script = asmToScript(spec.artifact.bytecode);
    const abiIndex = spec.abiIndex ?? 0;
    const fn = spec.artifact.abi[abiIndex]!;
    // Stack at contract entry (bottom -> top): function args, then the selector
    // (multi-function contracts only), then constructor args pushed by the redeem
    // prefix in reverse so the first declared constructor param ends up on top.
    const multiFunction = spec.artifact.abi.length > 1;
    const initialStack: SVal[] = [
      ...fn.inputs.map(() => ARG),
      ...(multiFunction ? [seedSelector(abiIndex)] : []),
      ...(spec.seeds ?? []).slice().reverse(),
    ];
    return interpret(z3, tx, script, { activeIndex: spec.activeIndex, initialStack });
  });

  const combos = cartesian(perCovenantPaths);
  const solvers = combos.map((combo) => {
    const solver = new z3.Solver();
    addConsensusRules(z3, solver, tx, cfg.categories);
    cfg.setup(z3, solver, tx);
    solver.add(inputsRespectInvariant(z3, tx, cfg.policy));
    solver.add(privilegedInputsOnlyAt(z3, tx, cfg.policy, cfg.designatedInputs));
    for (const path of combo) for (const c of path.constraints) solver.add(c);
    return solver;
  });

  return { tx, policy: cfg.policy, solvers };
}
