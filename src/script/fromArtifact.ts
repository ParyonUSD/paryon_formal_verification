import { consensusRules } from '../consensus.js';
import { declareTx, type SymbolicTx } from '../model.js';
import { inputsRespectInvariant, privilegedInputsOnlyAt, type LeakPolicy } from '../policy.js';
import { newSolver, type Bool, type Z3, type Z3Solver } from '../z3.js';
import { asmToScript } from './script.js';
import { ARG, interpret, seedSelector, type InterpretStats, type Path, type SVal } from './interpreter.js';

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
  /**
   * Input indices governed by a covenant in this template: the only inputs that may carry a privileged
   * (mutable/minting) or preserved (function-NFT) class. The active input of every interpreted covenant
   * is governed implicitly; list here the ones a `setup` pins but no spec runs (partners dropped in a
   * "composition matters" control, hand-pinned privileged inputs).
   */
  designatedInputs: number[];
  /** Template scaffolding: input categories/capabilities/scripts, partner covenants, id bindings. */
  setup: (z3: Z3, solver: Z3Solver, tx: SymbolicTx) => void;
}

export interface BuiltArtifact {
  tx: SymbolicTx;
  policy: LeakPolicy;
  /** The reachable combinations of script paths, as the constraints each contributes. */
  paths: Bool[][];
  /**
   * A fresh, fully loaded solver for one path combo plus extra assertions (a witness). Every query
   * gets its own solver: it is exported as SMT-LIB and decided in a native z3 process (see
   * `checkNative`), so there is no incremental state to share.
   */
  solverFor(path: number, extra?: Bool[]): Z3Solver;
  /** Every solver created by `solverFor`, kept referenced (see there). */
  keepAlive: Z3Solver[];
  /**
   * Inputs governed by a covenant this template runs (designated + every interpreted covenant's
   * active input). The preservation query restricts preserved-class NFTs to these; the leak query
   * needs no such restriction and stays cheaper without it.
   */
  governedInputs: number[];
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
  const stats: InterpretStats = { maxOutputIndex: -1 };

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
    return interpret(z3, tx, script, { activeIndex: spec.activeIndex, initialStack, stats });
  });

  // A leak needs an output slot no covenant pins. If the template's capacity ends exactly at the highest
  // index the covenants touch, the attacker's extra output has nowhere to go and the check is vacuous:
  // UNSAT because the template is too small, not because the contracts are safe. Demand a free slot.
  // (Explicit output-count caps in the bytecode then make that slot absent, which is the real constraint.)
  if (cfg.nOutputs < stats.maxOutputIndex + 2) {
    throw new Error(
      `template has ${cfg.nOutputs} output slots but a covenant references output ${stats.maxOutputIndex}; `
      + `allow at least ${stats.maxOutputIndex + 2} so an unpinned output can exist`,
    );
  }

  const combos = cartesian(perCovenantPaths);
  // Inputs governed by a covenant this template runs: the designated privileged inputs plus the active
  // input of every interpreted covenant (the function NFTs sit there).
  const governed = [...new Set([...cfg.designatedInputs, ...specs.map((spec) => spec.activeIndex)])];
  // Built once and shared by every query (see consensusRules on why sharing matters). The template's
  // `setup` is captured through a collector so its constraints are expressions, not solver state.
  const setup: Bool[] = [];
  cfg.setup(z3, { add: (...cs: Bool[]) => { setup.push(...cs); } } as unknown as Z3Solver, tx);
  const shared: Bool[] = [
    ...consensusRules(z3, tx, cfg.categories),
    ...setup,
    inputsRespectInvariant(z3, tx, cfg.policy),
    privilegedInputsOnlyAt(z3, tx, cfg.policy, cfg.designatedInputs),
  ];
  const paths = combos.map((combo) => combo.flatMap((path) => path.constraints));
  // Every solver handed out stays referenced for the build's lifetime: z3-solver frees a solver from a
  // garbage-collection finalizer, and a free racing a running `check()` in the worker thread was
  // observed to hang or corrupt Z3. Memory is reclaimed when the test file's process exits.
  const keepAlive: Z3Solver[] = [];
  const solverFor = (path: number, extra: Bool[] = []): Z3Solver => {
    const solver = newSolver(z3);
    solver.add(...shared, ...paths[path]!, ...extra);
    keepAlive.push(solver);
    return solver;
  };

  return { tx, policy: cfg.policy, paths, solverFor, governedInputs: governed, keepAlive };
}
