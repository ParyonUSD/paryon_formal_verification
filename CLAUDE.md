# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

`paryon_formal_verification` (formerly `z3-solver-ts`) is a bounded model checker that proves the
ParyonUSD CashScript contracts cannot **leak an NFT capability** — i.e. no consensus-valid transaction
allowed by the covenants can place a mutable/minting capability of an internal-authority category on an
output other than an owning covenant or a burn (invariant preservation, so the induction closes). It uses Z3 (via `z3-solver` wasm bindings) and symbolically executes the
compiled `@paryonusd/contracts` artifact bytecode.

The proof lifts a single transaction to the full covenant lifetime by induction (see
`inputsRespectInvariant` — the inputs are assumed already invariant-respecting). Read `README.md`,
`docs/scope.md`, and `docs/artifact-derivation.md` before substantive work; they carry the soundness
argument and the per-file map, and are kept current.

## Commands

```bash
pnpm install
pnpm typecheck                       # tsc --noEmit
pnpm lint                            # eslint
pnpm check                           # typecheck + lint (run before considering work done)
pnpm test                            # every test file, each in its own process (run-tests.ts via tsx)
pnpm test:watch                      # vitest watch, for iterating
pnpm exec vitest run tests/<file>    # a single file (fast iteration)
scripts/install-z3.sh                # native z3 (pinned release) into .tools/; the artifact proofs need it
```

The artifact proofs (`expectArtifactSafe`/`expectArtifactLeaks`) are decided by a **native z3 process
per query** from SMT-LIB text (`checkNative` in `src/z3.ts`; `Z3_BIN` overrides the binary, `Z3_SMT_DIR`
keeps the `.smt2` files). Do not move them back onto the wasm bindings' `check()`: under the larger
builds its garbage-collection finalizer races the worker thread and produced hangs, heap corruption and
OOM aborts that depended on process history. The wasm side still builds every expression and runs the
oracle/unit queries; keep queries there small.

**`pnpm test` deliberately spawns one process per test file** (`run-tests.ts`). This is load-bearing,
not incidental: `z3-solver` allocates a large `WebAssembly.Memory` per Z3 init and never frees it, and
a reused Z3 `Context` bloats. Sharing a process/context across files makes later solves crawl and can
make the run exit non-zero even when all tests pass. Do not "optimize" this into a single vitest run.

## Two-layer soundness obligation (the key architectural split)

The correctness argument rests on a superset/abstraction split — understand which side any change lives
on before touching it:

- **`src/consensus.ts` + the interpreter (`src/script/interpreter.ts`) must be FAITHFUL.** The
  consensus tally is the trusted base (it enforces the CashTokens no-mint/no-mutable-without-input and
  `nft_out <= nft_in` rules). The interpreter is the stack machine (opcode dispatch, stack routing,
  CAT/SPLIT, branch forking); a mis-routed value or mis-matched branch would silently constrain the
  *wrong* output — an error the superset argument does **not** catch.
- **Everything else only needs to be CONSERVATIVE.** `src/script/capability.ts` (which comparisons
  carry a capability), and dropping BCH values / token amounts / most commitment contents, only ever
  *remove* constraints. Fewer constraints = a superset of real transactions, so UNSAT on the model
  implies UNSAT on chain. These can widen the admitted tx set but never hide a leak.

When adding modelling, bias toward dropping constraints (safe) over adding them (must be provably
faithful).

**The faithful half is checked against libauth**, not trusted: `src/oracle/` + `tests/oracle-*.test.ts`
evaluate random concrete transactions and scripts with libauth's BCH VM / token validation and require
the model to admit whatever libauth accepts (and to agree both ways on the exact subset). Any change to
`interpreter.ts`, `capability.ts`, `consensus.ts` or `value.ts` must keep these green; a failure prints
the seed, the script disassembly and the transaction. `ORACLE_CASES` / `ORACLE_SEED` scale and re-seed
the fuzzing (e.g. `ORACLE_CASES=1000 ORACLE_SEED=7 pnpm exec vitest run tests/oracle-interpreter.test.ts`);
stay at or below ~1000 cases per run, since Z3's wasm heap is never reclaimed within a process (1500 hits
the 2 GB limit) — sweep further with more seeds, not more cases. (The wasm worker's teardown abort that used to make
`historical-leak.test.ts` flaky is gone with the native runtime.) Class
identities (`ATTACKER`, `BURN`, covenant ids, commitment ints) are only *necessary* conditions for byte
equality, so their equalities are marked `lossy` and the interpreter asserts them only in positive
position (never their negation); do not "simplify" that away, and do not encode it with free Z3
booleans (that blew up Z3's memory on the manage regression build).

## Engine vs ParyonUSD instantiation

The engine under `src/` is general BCH/CashTokens and imports nothing from `src/covenants/`:

- `src/z3.ts` — Z3 context + helpers (`getContext`, `any`, types `Z3`/`Z3Solver`/`Bool`/`Num`).
- `src/model.ts` — symbolic UTXO/tx model; `Capability`/`Script` enums; category/script id bounds
  (`MAX_CATEGORY`/`MAX_SCRIPT`) that keep the solver's domain finite.
- `src/consensus.ts` — the trusted CashTokens tally + structural rules (`addConsensusRules`).
- `src/policy.ts` — the leak-property *mechanism*, parameterised by a `LeakPolicy`: `leakWitness`,
  `inputsRespectInvariant` (inductive hypothesis), `privilegedInputsOnlyAt` (which inputs may carry a
  privileged cap), `isInternalPrivileged`.
- `src/script/` — artifact interpreter: `script.ts` (ASM decode via `@cashscript/utils`), `value.ts`
  (symbolic stack value language), `interpreter.ts` (stack machine), `capability.ts` (capability
  abstraction), `fromArtifact.ts` (loads artifacts, seeds the stack, builds one solver per reachable
  script-path combo).
- `src/oracle/` — the libauth differential oracle: `concrete.ts` (concrete transactions, libauth
  bridge, the abstraction `fixTx`), `scriptgen.ts` (random covenant-shaped scripts, exact/wide modes).

ParyonUSD-specific:

- `src/covenants/ids.ts` — the category/script id registry (small ints; only equality matters, real
  32-byte ids are checked by the sibling `verify_contract_deployment` tool).
- `src/covenants/common.ts` — leak policy *values*, ownership map, function-NFT id enums
  (`LoanFunction`/`PoolFunction`), input-shape helpers (`loanInput`, `functionNftInput`, `pin`, …).
- `tests/*.test.ts` — per-transaction templates; each hand-writes only the input `setup` (tx shape)
  and the leak policy, then calls `buildFromArtifact`. `tests/partners.ts` holds recreation/sidecar
  partner `CovenantSpec`s.

## The artifact-derivation pipeline (`buildFromArtifact`)

Every covenant's output pins are derived from bytecode — no covenant is hand-modelled. Flow:
`asmToScript` (artifact bytecode → `(opcode|data)[]`) → `interpret` runs it per co-present covenant,
emitting a Z3 constraint only for capability-moving comparisons (category equality, locking-bytecode
equality, output-count caps; values/amounts/arithmetic stay opaque) → `fromArtifact` seeds the stack
as `[funcArgs, selector?, constructorReversed]` and builds one `Z3Solver` per reachable script-path
combo (cartesian product of per-covenant paths). `docs/artifact-derivation.md` lists the subtleties
the bytecode forced correct (suffix-class category comparison, correlated OP_IF branches, runtime
OP_RETURN burn detection, multi-function selector dispatch, concrete index arithmetic).

## Test structure

Assertion helpers live in `tests/assertions.ts`: `expectArtifactSafe` (≥1 path realisable AND every
path leak-free — the standard check), `expectArtifactLeaks` (a "composition matters" control: drop a
partner covenant and show the leak reappears), plus lower-level `expectSat`/`expectNoLeak`/`expectLeak`.
Coverage is organized by subsystem: `artifact-loan`, `artifact-redemption`, `artifact-pool`,
`artifact-loankey`, `artifact-price`, plus `consensus`/`policy`/`historical-leak` unit tests and the
libauth oracle tests `oracle-interpreter`/`oracle-consensus`/`oracle-decode`. `tests/coverage.test.ts` is
the function-level ledger: every artifact function must be verified by a template or excluded with a
reason — classify new functions there. `expectArtifactSafe` checks the leak witness *and* the
function-NFT preservation witness (policy `preserve`); `buildFromArtifact` refuses a template whose
output capacity leaves no unpinned slot, so bump `nOutputs` when it complains. `designatedInputs` must
list every input a `setup` pins with a privileged or function-NFT class that no interpreted covenant
governs (e.g. a partner dropped in a "composition matters" control).

## Scope boundary (what this tool does NOT check)

Only the capability-leak invariant; everything else (BCH values, token/interest math, dust, timelocks,
signatures, arithmetic, commitment contents beyond the function-identifier byte) is deliberately
abstracted away and covered by sibling tools. Don't add functional-correctness checks here — see the
README's Scope section and `docs/scope.md` for why the omissions are sound and where each concern lives.
