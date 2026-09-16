# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`paryon_formal_verification` is a bounded model checker that proves the ParyonUSD CashScript contracts
cannot **leak an NFT capability** — no consensus-valid transaction allowed by the covenants can place a
mutable/minting capability of an internal-authority category on an attacker-controlled output. It uses
Z3 (via `z3-solver` wasm bindings to build, a native z3 process to decide) and symbolically executes the
compiled `@paryonusd/contracts` artifact bytecode.

There are **no transaction templates**. One symbolic transaction of fixed capacity (9 inputs, 11
outputs) is built, and the solver chooses the shape: how many inputs and outputs, what each carries,
which covenant sits where, which function runs, and whether operations are batched. The whole model is
the consensus tally, the system invariant assumed of the inputs, and one rule per input — *if this
input's script is a registered covenant, that covenant's bytecode runs at this index*.

Read `README.md`, `docs/scope.md` and `docs/artifact-derivation.md` before substantive work; they carry
the soundness argument, the ledger of invariants, and the per-file map, and are kept current.

## Commands

```bash
pnpm install
pnpm typecheck                       # tsc --noEmit
pnpm lint                            # eslint
pnpm check                           # typecheck + lint (run before considering work done)
pnpm test                            # every test file, each in its own process (run-tests.ts via tsx)
pnpm test:watch                      # vitest watch, for iterating
pnpm exec vitest run tests/<file>    # a single file (fast iteration)
scripts/install-z3.sh                # the native z3 the proofs are decided in (.tools/, git-ignored)
```

**`pnpm test` deliberately spawns one process per test file** (`run-tests.ts`). This is load-bearing,
not incidental: `z3-solver` allocates a large `WebAssembly.Memory` per Z3 init and never frees it, and a
reused Z3 `Context` bloats. Do not "optimize" this into a single vitest run.

`ORACLE_SEED` / `ORACLE_CASES` scale the differential oracle. `Z3_SMT_DIR` keeps the `.smt2` files any
SMT solver can re-check. `Z3_BIN` overrides the native binary.

## Two-layer soundness obligation (the key architectural split)

Understand which side any change lives on before touching it:

- **`src/consensus.ts` + the interpreter (`src/script/interpreter.ts`) must be FAITHFUL.** The
  consensus tally is the trusted base. The interpreter is the stack machine (opcode dispatch, stack
  routing, CAT/SPLIT, index arithmetic, branch forking); a mis-routed value or a mis-matched branch
  would silently constrain the *wrong* output — an error the superset argument does **not** catch.
- **Everything else only needs to be CONSERVATIVE.** `src/script/capability.ts` (which comparisons
  carry a capability), and dropping BCH values / token amounts / commitment contents, only ever
  *remove* constraints. Fewer constraints = a superset of real transactions, so UNSAT on the model
  implies UNSAT on chain.

When adding modelling, bias toward dropping constraints (safe) over adding them (must be provably
faithful). If you add a constraint, add the construct to the fuzzer's exact subset
(`src/oracle/scriptgen.ts`) so libauth has to agree with it in both directions.

## The layout

The engine under `src/` is general BCH/CashTokens and imports nothing from `src/covenants/`:

- `src/z3.ts` — Z3 context, solver, and the native decision procedure. **Every proof is an expected
  `unsat`, so a decision that answers "unsat" when z3 did not run passes the whole suite.** The verdict
  reader is strict for that reason; `tests/native-decision.test.ts` guards it.
- `src/model.ts` — symbolic UTXO/tx model: category, capability, script, commitment (integer reading,
  length, leading byte), outpoint (transaction identity, index), presence.
- `src/consensus.ts` — the CashTokens tally + structural and outpoint rules.
- `src/policy.ts` — the invariant *mechanism*: the five clauses of `LeakPolicy`, the hypothesis on
  inputs (`inputsRespectInvariant`), and one witness per clause.
- `src/script/` — `script.ts` (ASM decode), `value.ts` (symbolic stack values), `interpreter.ts` (the
  stack machine), `capability.ts` (the capability abstraction), `wholeSystem.ts` (the build).

ParyonUSD-specific, and the only hand-written inputs to the proof:

- `src/covenants/ids.ts` — the category/script id registry (small ints; only equality matters).
- `src/covenants/registry.ts` — which script runs which artifact, with which constructor seeds.
- `src/covenants/common.ts` — the identifiers the contracts authenticate by, and `SYSTEM_POLICY`.

## How to add a contract

Register it. That is the whole procedure:

1. Give its locking script an id in `src/covenants/ids.ts` (and a category id if it introduces one).
2. Add an entry to `SYSTEM_REGISTRY` in `src/covenants/registry.ts`: the artifact, the constructor
   `seeds` in declaration order (`seedScript` for a locking-script parameter, `seedCategory` for a
   tokenId parameter, `seedOpaque` for anything that cannot feed a capability comparison), and
   `abiIndices` if only some functions are modelled — every function left out needs an `excluded`
   entry with a reason, or `tests/coverage.test.ts` fails.
3. If it holds a privileged capability, add it to `SYSTEM_POLICY.ownership`. If it is a sidecar
   authenticated by outpoint adjacency, add the pair to `SIDECAR_PAIRS`. If its state NFT carries a
   fixed identifier byte, add it to `STATE_SHAPES`. Each of these is assumed of the inputs and must be
   discharged on the outputs by its witness — the tests will tell you if it is not.
4. Run `pnpm exec vitest run tests/whole-system.test.ts`. A new function must show up alive; if the
   capacity cut list changed, understand why before updating it.

Do **not** add a transaction shape, an input pin, or an index assumption. If a witness goes SAT, the
answer is either a genuine finding or a named missing precision — never a pin.

## How to read a counterexample

A SAT witness prints the whole transaction (`tests/wholeSystemReport.ts`): every present input and
output with its script, category, capability, commitment (integer / length / leading byte), satoshi
value and fungible amount, inputs also with their outpoint as `tx:index`, and for each input the
covenant functions the model says run there. Work backwards from the output the witness fired on: find
which covenant was supposed to pin it, and why the model let that covenant be absent or take a
different branch. The usual answers, in order of likelihood:

1. a *missing precision* — the model dropped a comparison the contract makes (check `capability.ts`:
   is the comparison one it models at all?);
2. a *missing invariant* — the contracts authenticate each other by a fact the hypothesis does not
   carry (that is where adjacency, the state identifiers and the function-NFT site binding came from);
3. a genuine multi-operation finding.

## Capacity, and what the bound means

9 inputs and 11 outputs: the smallest that admits every operation (`swapInRedemption` pins itself to
input 8) while leaving the unpinned output slot a leak needs (`Borrowing.borrow` reads output 9). The
builder refuses a capacity without that free slot.

When a covenant reads a UTXO index the build does not carry, the path is pruned and
`script == S ⇒ OR(paths)` collapses to `script == S ⇒ false` at that index — the build concludes that
covenant cannot sit there. That is a hole by construction, so `cutSites` returns every one and
`tests/whole-system.test.ts` enumerates the accepted set with the argument for each. Never widen that
list without writing down why the shape is outside the bound anyway.

## Scope boundary (what this tool does NOT check)

Only the capability-leak invariant; everything else (BCH values, token/interest math, dust, timelocks,
signatures, arithmetic, commitment contents beyond the leading byte and length) is deliberately
abstracted away and covered by sibling tools. Don't add functional-correctness checks here — see the
README's Scope section and `docs/scope.md` for why the omissions are sound and where each concern lives.
