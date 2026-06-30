import type { SymbolicTx } from '../src/model.js';
import type { Z3, Z3Solver } from '../src/z3.js';

/**
 * A covenant models one spend path, pinned at fixed input/output indices within a
 * transaction. `constrain` transcribes its `require`s into Z3 assertions.
 *
 * Real ParyonUSD covenants are now derived from artifact bytecode (see `src/script`);
 * this hand abstraction remains for small illustrative tests (e.g. the leak-policy unit test).
 */
export interface Covenant {
  readonly name: string;
  constrain(z3: Z3, s: Z3Solver, tx: SymbolicTx): void;
}

/** Compose several covenants into one transaction by asserting all of them. */
export function compose(z3: Z3, s: Z3Solver, tx: SymbolicTx, covenants: Covenant[]): void {
  for (const c of covenants) c.constrain(z3, s, tx);
}
