import { consensusRules } from '../consensus.js';
import { Script, declareTx, type SymbolicTx } from '../model.js';
import { inputsRespectInvariant, type LeakPolicy } from '../policy.js';
import type { CovenantRegistry, RegisteredCovenant } from '../covenants/registry.js';
import { any, newSolver, type Bool, type Z3, type Z3Solver } from '../z3.js';
import { asmToScript } from './script.js';
import { ARG, interpret, seedSelector, type InterpretStats, type SVal } from './interpreter.js';

/**
 * The whole-system build: one symbolic transaction in which the *solver* picks the shape.
 *
 * A template says "the loan is at input 1, its manage function at input 3, the price contract at
 * input 0", pins those inputs, and names the indices allowed to carry a privileged capability. Each of
 * those is a hand-written assumption, and together they scope every proof to one canonical
 * single-operation transaction. This builder removes all of them and replaces them with one rule:
 *
 *   for every input index i and every registered covenant script S,
 *     input_i.script == S  =>  OR over S's functions f, OR over the paths of f at index i, of that
 *                              path's constraints
 *
 * Nothing else. The consensus tally, the inductive hypothesis (`inputsRespectInvariant`) and those
 * implications are the whole model, so the solver is free to choose how many inputs and outputs there
 * are, which covenant sits where, and whether several operations share the transaction. Absent slots
 * are modelled by `present`, so a single build at maximum capacity covers every smaller shape too.
 *
 * Why it can only ever be too permissive: dropping the pins removes constraints, and a model with
 * fewer constraints describes a *superset* of the real transactions, so UNSAT here still implies UNSAT
 * on chain. The two restrictions it does add are facts, not scaffolding — a BURN output is
 * provably unspendable so it can never be an input, and a covenant script this build cannot execute is
 * kept off the inputs because the build would otherwise leave its outputs unconstrained (see
 * `unmodelledCovenantScripts`; register every subsystem and that set is empty).
 *
 * The bound is the capacity: this build reasons about transactions with at most `nInputs` inputs and
 * `nOutputs` outputs. `stats.outOfCapacity` counts the paths the capacity, rather than the contracts,
 * pruned.
 */
export interface WholeSystemConfig {
  nInputs: number;
  nOutputs: number;
  /** Category ids the consensus tally is enforced over. */
  categories: number[];
  /** The one global invariant, assumed of the inputs; see SYSTEM_POLICY. */
  policy: LeakPolicy;
  registry: CovenantRegistry;
  /** Covenant scripts outside the registry: kept off the inputs (scope, see the file comment). */
  unmodelledScripts?: number[];
  /** Safety valve per (covenant, function, index) interpretation. */
  maxPathsPerFunction?: number;
}

/** One (covenant script, function, input index) interpretation and what it produced. */
export interface FunctionSite {
  script: number;
  abiIndex: number;
  name: string;
  index: number;
  /** Reachable paths; 0 means the function cannot run at this index (e.g. it pins another one). */
  paths: number;
  /**
   * Name of the model boolean that is true exactly when this covenant's script sits at this input and
   * this function of it runs. Reading it back from a counterexample says which operation the solver
   * chose at each input, which is what makes a whole-system counterexample legible.
   */
  selector: string;
}

export interface WholeSystemStats {
  /** How many (covenant, function, index) triples were symbolically executed. */
  interpretations: number;
  /** Total reachable paths across all of them (the size of the disjunction). */
  totalPaths: number;
  /** Interpretations that produced no path at all (the function cannot run at that index). */
  deadSites: number;
  /** Highest output index any covenant read at any index. */
  maxOutputIndex: number;
  /** Wall-clock milliseconds spent interpreting. */
  interpretMs: number;
}

/**
 * A (covenant, function, index) site where the *capacity*, not the contract, pruned a path: the
 * function read a UTXO index the build does not carry.
 *
 * Within the bound this is faithful, not a gap: no transaction with at most `nInputs` inputs has an
 * input at that index, so the covenant genuinely cannot run there and `script == S => false` is the
 * right answer. What it does mark is where the *capacity* decided something rather than a contract, so
 * every one is surfaced and the tests enumerate the set they accept — a cut appearing anywhere else
 * means the capacity has begun deciding something new.
 */
export interface CutSite {
  script: number;
  abiIndex: number;
  name: string;
  index: number;
  /** The out-of-capacity reads that pruned it, as `in9` / `out11`. */
  reads: string[];
}

export interface BuiltWholeSystem {
  tx: SymbolicTx;
  policy: LeakPolicy;
  /** Consensus + hypothesis + covenant implications: everything every query starts from. */
  shared: Bool[];
  /**
   * A fresh solver carrying `shared` plus the given assertions. Every query gets its own solver: it is
   * exported as SMT-LIB and decided in a native z3 process (`checkNative`), so there is no incremental
   * state to share and no push/pop.
   *
   * `withoutCovenants` drops the per-input covenant implications and keeps only the consensus rules
   * and the inductive hypothesis. It is the positive control for every witness: a witness that is
   * unsat with the covenants and *sat* without them is unsat *because of the contracts*, which is the
   * claim. One that is unsat either way proves nothing and is a bug in the witness.
   */
  solverFor(extra?: Bool[], options?: { withoutCovenants?: boolean }): Z3Solver;
  /** Every solver handed out, kept referenced (z3-solver frees from a GC finalizer; see fromArtifact). */
  keepAlive: Z3Solver[];
  /** "Some input runs this function": its script at that index AND one of its paths there. */
  runsSomewhere(script: number, abiIndex: number): Bool;
  sites: FunctionSite[];
  /** Sites the capacity pruned; see {@link CutSite}. A test must enumerate the accepted set. */
  cutSites: CutSite[];
  stats: WholeSystemStats;
}

export function buildWholeSystem(z3: Z3, cfg: WholeSystemConfig): BuiltWholeSystem {
  const tx = declareTx(z3, cfg.nInputs, cfg.nOutputs);
  const stats: InterpretStats = { maxOutputIndex: -1 };
  const cutSites: CutSite[] = [];
  const startedAt = Date.now();

  const sites: FunctionSite[] = [];
  const implications: Bool[] = [];
  const definitions: Bool[] = [];
  // "function f of covenant S runs somewhere", one disjunct per input index, for the liveness checks.
  const runs = new Map<string, Bool[]>();
  const key = (script: number, abiIndex: number): string => `${script}:${abiIndex}`;
  let totalPaths = 0;

  for (const [scriptId, entry] of cfg.registry) {
    const code = asmToScript(entry.artifact.bytecode); // decoded once, shared by every index
    const abiIndices = entry.abiIndices ?? entry.artifact.abi.map((_, i) => i);
    for (const abiIndex of abiIndices) runs.set(key(scriptId, abiIndex), []);

    for (let i = 0; i < cfg.nInputs; i++) {
      const perFunction: Bool[] = [];
      for (const abiIndex of abiIndices) {
        // Per-site stats so a capacity-pruned path can be attributed to the site that made the read;
        // `maxOutputIndex` is merged back into the build-wide figure the free-slot guard uses.
        const siteStats: InterpretStats = { maxOutputIndex: -1 };
        const paths = interpret(z3, tx, code, {
          activeIndex: i,
          initialStack: initialStackFor(entry, abiIndex),
          stats: siteStats,
          ...(cfg.maxPathsPerFunction === undefined ? {} : { maxPaths: cfg.maxPathsPerFunction }),
        });
        stats.maxOutputIndex = Math.max(stats.maxOutputIndex, siteStats.maxOutputIndex);
        const name = `${entry.artifact.contractName}.${entry.artifact.abi[abiIndex]?.name ?? abiIndex}`;
        if (siteStats.beyondCapacity !== undefined) {
          cutSites.push({
            script: scriptId, abiIndex, index: i, name,
            reads: siteStats.beyondCapacity.map((r) => `${r.side}${r.index}`).sort(),
          });
        }
        // A disjunction of conjunctions, never a cartesian product of solvers: one build decides
        // everything, and the solver picks the branch.
        const reachable = any(z3, paths.map((path) => z3.And(...path.constraints)));
        // A named indicator, *defined* as "this script is here and this function of it runs", so it
        // adds no freedom and a counterexample can be read back operation by operation.
        const selector = `${tx.prefix}runs.s${scriptId}.f${abiIndex}.in${i}`;
        const indicator = z3.Bool.const(selector);
        definitions.push(z3.Eq(indicator, z3.And(tx.inputs[i]!.script.eq(scriptId), reachable)));
        perFunction.push(indicator);
        runs.get(key(scriptId, abiIndex))!.push(indicator);
        sites.push({ script: scriptId, abiIndex, index: i, paths: paths.length, selector, name });
        totalPaths += paths.length;
      }
      // No function of S can run at index i (every one pins a different index) => S is not there.
      implications.push(z3.Implies(tx.inputs[i]!.script.eq(scriptId), any(z3, perFunction)));
    }
  }
  const interpretMs = Date.now() - startedAt;

  // A BURN output is an OP_RETURN nulldata: provably unspendable, so it is never an input.
  const noBurnInputs = tx.inputs.map((utxo) => z3.Not(utxo.script.eq(Script.BURN)));
  // Covenant scripts this build cannot execute stay off the inputs (see the file comment).
  const unmodelled = cfg.unmodelledScripts ?? [];
  const inScope = tx.inputs.flatMap((utxo) => unmodelled.map((id) => z3.Not(utxo.script.eq(id))));

  // A leak needs an output slot no covenant pins. If the capacity ended exactly at the highest index a
  // covenant reads, the attacker's extra output would have nowhere to go and every witness would be
  // unsat because the model is too small, not because the contracts are safe.
  if (cfg.nOutputs < stats.maxOutputIndex + 2) {
    throw new Error(
      `capacity is ${cfg.nOutputs} outputs but a covenant references output ${stats.maxOutputIndex}; `
      + `allow at least ${stats.maxOutputIndex + 2} so an unpinned output can exist`,
    );
  }

  const base: Bool[] = [
    ...consensusRules(z3, tx, cfg.categories),
    inputsRespectInvariant(z3, tx, cfg.policy),
    ...noBurnInputs,
    ...inScope,
  ];
  const covenants: Bool[] = [...definitions, ...implications];
  const shared: Bool[] = [...base, ...covenants];

  const keepAlive: Z3Solver[] = [];
  const solverFor = (extra: Bool[] = [], options: { withoutCovenants?: boolean } = {}): Z3Solver => {
    const solver = newSolver(z3);
    solver.add(...(options.withoutCovenants === true ? base : shared), ...extra);
    keepAlive.push(solver);
    return solver;
  };

  return {
    tx,
    policy: cfg.policy,
    shared,
    solverFor,
    keepAlive,
    runsSomewhere: (script, abiIndex) => any(z3, runs.get(key(script, abiIndex)) ?? []),
    sites,
    cutSites,
    stats: {
      interpretations: sites.length,
      totalPaths,
      deadSites: sites.filter((site) => site.paths === 0).length,
      maxOutputIndex: stats.maxOutputIndex,
      interpretMs,
    },
  };
}

/**
 * The stack at contract entry (bottom -> top): function args, then the selector for a multi-function
 * contract, then the constructor args pushed by the redeem prefix in reverse. Identical to
 * what the redeem prefix pushes on chain; the only free choice here is the active index.
 */
function initialStackFor(entry: RegisteredCovenant, abiIndex: number): SVal[] {
  const fn = entry.artifact.abi[abiIndex]!;
  const multiFunction = entry.artifact.abi.length > 1;
  return [
    ...fn.inputs.map(() => ARG),
    ...(multiFunction ? [seedSelector(abiIndex)] : []),
    ...(entry.seeds ?? []).slice().reverse(),
  ];
}
