# Paryon Formal Verification

Bounded model checking of the ParyonUSD CashScript contracts for NFT-capability leaks, using [Z3](https://github.com/Z3Prover/z3) via its TypeScript bindings.

It symbolically executes the compiled `@paryonusd/contracts` bytecode. There is no hand-transcribed contract logic anywhere in this repo, and no hand-written transaction shapes either.

## Running it

You need Node.js and pnpm, and a native z3 for the proofs.

```bash
pnpm install
scripts/install-z3.sh   # the pinned z3 release into .tools/ (Linux x64); elsewhere set Z3_BIN to a z3 binary
pnpm check              # typecheck and lint
pnpm test               # every proof and test
```

`pnpm test` runs each test file in its own process, because the z3 wasm bindings never free their memory. The full run takes a while; `pnpm exec vitest run tests/<file>` runs one file. `ORACLE_SEED` and `ORACLE_CASES` set the seed and volume of the differential oracle, and `Z3_SMT_DIR` keeps the `.smt2` files of each proof for re-checking with any SMT solver.

## The property

For every internal-authority category (paryon, pool, redeemer, loanKeyFactory), no transaction allowed by CashTokens consensus and the system's covenants can place that category's mutable or minting capability on an output other than a covenant that rightfully owns it, or a provable burn.

It is checked as *invariant preservation*. The transaction's inputs are assumed to satisfy the system invariant — they existed before this transaction, so under the induction they already do — and every output is then required to satisfy the same invariant. That is what lifts a single-transaction result to "the attacker can never come to hold such a capability" over the whole lifetime of the deployment, with the genesis state as the base case. A privileged NFT parked on the *wrong* covenant counts as a leak: that covenant's code does not protect it.

One documented exception is outside the proof by design. `PriceContract.migrateContract` lets whoever spends a token of the fifth deploy category, the oracle migration key, move the paryon-mutable price authority to new contract code. The migration key is an explicit admin trust assumption of the system (see the contracts' `contract_overview.md`), so that function is excluded in the registry with its reason rather than modelled.

## How it is checked: one transaction, no templates

The model is a single symbolic transaction with a fixed capacity — 9 inputs, 11 outputs — in which the **solver** chooses everything: how many inputs and outputs there are, what each one carries, which covenant sits at which index, which of its functions runs, and whether several operations share the transaction. Absent slots are modelled by a `present` flag, so one build at maximum capacity covers every smaller shape, batched operations included.

Everything the model knows is:

1. the CashTokens token-validation tally (`src/consensus.ts`), the trusted base;
2. the system invariant, assumed of the inputs (`SYSTEM_POLICY` in `src/covenants/common.ts`);
3. one rule per input — **if this input's locking script is a registered covenant, that covenant's bytecode runs at this index**:

   ```
   for every input index i and every registered covenant script S:
       input_i.script == S  ⟹  OR over S's functions f, OR over the paths of f at index i,
                                of the constraints that path emits
   ```

`src/script/wholeSystem.ts` builds that as one disjunction of conjunctions — not a product of solvers — from `interpret(artifact_S, function f, activeIndex = i)`. A function that pins its own index (`require(this.activeInputIndex == 3)`) simply produces no path at the other indices, so the contracts do their own pruning: 200 of the 270 (covenant, function, index) sites are dead for that reason.

Nothing pins a category, a script or an index. The shapes that used to be written by hand are *derived*: given only "the FN_MANAGE script runs the manage artifact", the solver reconstructs that a loan must sit next to its outpoint-adjacent sidecar with its function NFT two slots on, and that the price contract has to be present and recreated.

## The ledger of invariants

`SYSTEM_POLICY` is the system invariant, stated once. Each clause is **assumed** of the transaction's inputs and **discharged** on its outputs by its own witness — asserted alongside consensus and the covenants, and expected `unsat`. That is what closes the induction instead of assuming it.

| clause | what it says | discharged by |
|---|---|---|
| `ownership` | each privileged (category, capability) sits only on the covenants that own it | `leakWitness` |
| `functionNfts` | each function NFT sits on its own function script carrying its own identifier byte, and every paryon immutable NFT with a non-empty commitment is one of them | `forgedFunctionNftWitness` |
| `functionNfts` | a function NFT that is spent is recreated in place | `preservationWitness` |
| `adjacency` | the UTXO one outpoint index after a loan / pool / redemption is its sidecar | `adjacencyWitness` |
| `stateShapes` | a loan's commitment starts `0x01` and a price contract's starts `0x00` | `stateShapeWitness` |

The last three are not bookkeeping: the covenants authenticate each other by exactly these facts and by nothing else. `Loan.interact` accepts its sidecar on outpoint adjacency alone and never checks its locking script; `manage` tells the price contract from the loan by the first commitment byte, not by the script; `Redeemer.createRedemption` accepts the startRedemption function NFT by category and leading byte without checking its length. Each was an assumption a per-transaction template used to make silently by pinning an input.

Every witness also has a **positive control**: dropping the covenant implications must make it satisfiable. An `unsat` that survives the controls is the contracts' doing, not an over-constrained model.

**The base case is the deployment.** The companion tool `verify_contract_deployment` must establish the same five facts of the genesis state against the same artifacts: that every privileged NFT was minted with the capability and commitment it should have on its owning contract (`ownership`), that each function NFT was minted once on its own function contract with its own one-byte identifier and that no other paryon immutable NFT with a non-empty commitment was created (`functionNfts`), that each loan / pool / redemption was created immediately before its sidecar in the genesis outputs (`adjacency`), and that the loan and price state NFTs carry their identifier bytes (`stateShapes`). Neither half stands alone: a proof about artifacts nobody deployed, or a verified-honest deployment of contracts nobody proved safe. Which of these the deployment tool checks today, and which are still open there, is tracked next to `SYSTEM_POLICY` in `src/covenants/common.ts`.

## Origin proofs: a clause outside the invariant

One fact the covenants authenticate each other by is not about capabilities: the loanKey origin proof, an immutable factory NFT, must be used once. `LoanKeyOriginEnforcer` takes it one outpoint on as proof of its loanKey's origin by category and position alone, and the loanKey category becomes the loan's id, which redemptions find the loan by. A proof that outlives its borrow moves no capability, so `leakWitness` cannot see it, yet it can vouch for a copy of a live loanKey and open a second loan with an existing loan's id.

The `singleUse` clause states it: an origin proof sits on `LoanKeyOriginProof` one outpoint after its enforcer, only the factory's minting NFT creates one, and anything else that spends one burns it. `singleUseWitness` checks it on the outputs. The published contracts do not preserve it: `borrow` pins outputs 0 and 2 to 6, the price contract's `sharePrice` recreates itself at output 1, and outputs 7 to 9 are left open to any non-paryon token, the proof included. So the clause lives in `SINGLE_USE_POLICY` rather than `SYSTEM_POLICY`, and the other witnesses never assume it.

`tests/whole-system-origin-proof.test.ts` has the solver build the borrow that keeps its proof. It also shows that one rule would close the clause: no output from 7 on carries the factory category when the Borrowing contract is at input 0. That rule is written into the query, not compiled from bytecode, and it is enough only together with the published `sharePrice` keeping output 1 to the price contract itself. The only covenant in every borrow whose code can change is the price contract, through `migrateContract`. That function is excluded from the registry as an admin trust assumption, so a price contract that enforces the rule closes the clause only for as long as the oracle migration key keeps every price thread on that code. It cannot be proven unconditionally.

`PriceContractGuarded` is such a price contract: `PriceContract` with a stricter form of the rule in `sharePrice`, where the free outputs of a borrow may hold no token or only one of the new loan's loanKey category without capability. `tests/whole-system-guarded-price.test.ts` puts its compiled bytecode on the price script and proves the whole of `SINGLE_USE_POLICY`: every clause, `singleUse` included, is unsatisfiable with its positive control, and every modelled function, `Borrowing.borrow` included, is still alive. With one price thread left on `PriceContract` the system is the published one, where the origin-proof test above finds the borrow, so the migration must move every thread.

The base case moves too. The published contracts let a proof survive its borrow from genesis on, so for a fix that arrives by migration the induction starts at the migration, not at genesis: at that moment no origin proof may exist anywhere but unspent on `LoanKeyOriginProof`, one outpoint after its enforcer. A proof kept before the migration could still back one more loan with an existing loan's id afterwards.

## The only hand-written inputs

Two files, and both are reviewable against the chain:

- `src/covenants/registry.ts` — which locking script runs which artifact, with which constructor arguments. No transaction shape; the same bindings `verify_contract_deployment` checks on chain.
- `src/covenants/common.ts` — the identifiers the contracts authenticate each other by, and `SYSTEM_POLICY`, the invariant above.

`src/covenants/ids.ts` assigns each category and script a small integer. The property only ever needs *identity*, so distinct small ints capture it exactly and keep the solver in a tiny finite domain; the real 32-byte token ids and ~35-byte P2SH32 scripts are checked on chain by `verify_contract_deployment`.

## Coverage

`tests/coverage.test.ts` is the ledger: every function of every published artifact is either modelled by a registry entry or excluded there with a written reason. Registration alone is not coverage, so `tests/whole-system.test.ts` asserts that each of the 30 modelled functions is *alive* — that there is a transaction in which the solver runs it, on the UTXO the deployment actually puts on that script. A function nothing can run would contribute a vacuous share of the proof.

Two real, independently discovered historical capability leaks are the end-to-end check (`tests/whole-system-historical.test.ts`): swapping a pre-fix artifact into the registry makes the leak witness satisfiable again. They are `manage` closing a loan without burning its mutable NFT (fixed 2026-04) and `Borrowing.updatePeriodState` checking the wrong change-output index next to the paryon minting NFT (fixed 2025-11, paryon_contracts `3e9cf60`). Both are now found with *no* description of the attack: the registry says only which script runs which artifact. A third case removes the Redemption covenant from the registry and shows the leak return, so the proof is known to depend on each covenant's code.

## The bound

The proof is about transactions with at most 9 inputs and 11 outputs, and says nothing about larger ones. That is the whole limitation, and it is uniform: it is not that particular shapes inside the bound are missed, but that transactions outside it are simply not examined. Nine inputs is the smallest that admits every operation (`swapInRedemption` pins itself to input 8); eleven outputs is the smallest that keeps the check meaningful, since `Borrowing.borrow` and `Redeemer.createRedemption` read output 9 and a leak needs a slot no covenant pins — the builder refuses a capacity without one.

Within the bound, a path pruned for reading input 9 is *faithful*: no transaction with at most 9 inputs has one, so the covenant genuinely cannot run there and `script == S ⇒ false` at that index is the right answer. The builder still returns those sites and the test enumerates them (`Loan.interact` and `StabilityPool.interact` read their function NFT two inputs on, `StabilityPoolSidecar.attach` one input on, so a loan or pool at input 7 or 8 would need a tenth input), as a regression guard: a cut appearing anywhere else means the capacity has started deciding something new, and fails the suite.

Batching is covered — the solver may put several operations in one transaction, and nothing in the model discourages it — but only within 9 × 11, and nearly every pair of operations needs more inputs than that (a loan operation alone takes four or five). So practical coverage of batched transactions is thin, and widening the bound is the way to deepen it.

## Decided in a native Z3 process

The proofs are decided by a native z3 process per query, from SMT-LIB text the bindings emit (`scripts/install-z3.sh` installs the pinned release into `.tools/`; `Z3_SMT_DIR` keeps the `.smt2` files as audit artifacts any SMT solver can re-check). The wasm bindings build the expressions and run the oracle and unit queries, but they proved unreliable for the larger proofs: their garbage-collection finalizer releases Z3 references while a check runs in a worker thread, which produced hangs and heap corruption that depended on process history.

Every proof here is an expected `unsat`, so a decision procedure that answers "unsat" when it did not run would pass the whole suite without deciding anything. The first token of z3's output must therefore be exactly `sat`, `unsat` or `unknown`, and anything else throws; `tests/native-decision.test.ts` drives both entry points against stub binaries that time out, exit non-zero, print errors or return truncated models.

## Scope

This repo proves one global safety invariant over the whole space of adversarial transactions, but it deliberately abstracts away BCH values, token amounts, and most commitment contents. It is not a functional-correctness check: it does not verify the interest math, collateral ratios, debt accounting, or that each individual `require` fires. That is the job of the companion `paryon_testing_suite`, which builds a valid transaction for each contract on the real VM (libauth `MockNetworkProvider`) and mutates it to trigger every `require`.

The three ParyonUSD verification tools cover different axes, all against the same artifacts:

- `paryon_testing_suite` — functional correctness and per-`require` coverage (concrete, real VM).
- this repo — exhaustive proof of the capability-leak invariant over all consensus-valid transactions within the bound.
- `verify_contract_deployment` — the live chain runs these artifacts, from a genesis state satisfying the invariant.

See [docs/scope.md](docs/scope.md) for the full breakdown of what is and is not checked, and which code is general BCH/CashTokens machinery versus ParyonUSD-specific. What is still worth proving or improving, and where a proof assistant would and would not help, is in [docs/future-work.md](docs/future-work.md).

## Layout

The engine (general BCH/CashTokens, no ParyonUSD knowledge) lives in `src/`: `z3.ts`, `model.ts`, `consensus.ts`, `policy.ts`, `covenant.ts`, `script/*`, and the libauth differential oracle in `oracle/*`. The ParyonUSD instantiation is `src/covenants/` and `tests/`. See [docs/scope.md](docs/scope.md) for the per-file map.

The artifact interpreter is split by soundness obligation. `script/interpreter.ts` is the stack machine and must be **faithful** — a mis-routed value or a mis-matched ELSE silently emits a constraint about the wrong UTXO, which the superset argument does not protect against. `script/capability.ts` is the abstraction that decides which comparisons carry a capability, and only needs to be **conservative**: it drops constraints and never adds them, so it can only widen the transaction set it admits.

The move away from templates is not a pure widening, and should not be read as one. Removing the per-transaction pins removed constraints, but `SYSTEM_POLICY` *adds* hypotheses about the inputs that no template ever assumed — sidecar adjacency, the state identifier bytes, the function-NFT identifier↔script binding, and paryon immutable NFTs with a non-empty commitment being exactly the function NFTs. What makes that sound is not a superset argument but the induction: each added hypothesis is discharged on the outputs by its own witness in the same build, so the only thing left on trust is the genesis state.

## Checked against libauth (the differential oracle)

The model is an idealised VM: values, amounts, arithmetic, signatures, hashes and VM limits are abstracted away. That is sound only if the abstraction never *rejects* a transaction the real VM accepts, and that claim is not something the superset argument can establish by itself. So the faithful half is tested differentially against [libauth](https://github.com/bitauth/libauth), whose BCH VM and CashTokens validation are cross-validated with BCHN on the shared VMB test vectors. Nothing in the oracle depends on CashScript.

`src/oracle/` builds *concrete* transactions (real 32-byte categories, real locking bytecode, real commitments, real outpoints), hands them to libauth as-is, and abstracts the same transaction into the model (`fixTx`). Four tests hold the two sides against each other:

- `tests/oracle-interpreter.test.ts` — random covenant-shaped scripts (`src/oracle/scriptgen.ts`, with operands routed through a menu of stack-shuffle patterns) are run by libauth's VM and by the symbolic interpreter. Whatever libauth accepts, the model must admit on some path. On the *exact* subset — category identity, capability suffixes, outpoint identity and index arithmetic, commitment leading bytes, positive script-identity and commitment requirements, counts, boolean combinators and branches on those — the verdicts must agree in both directions, which rules out passing the soundness check by admitting everything.
- `tests/oracle-commitment.test.ts` — targeted cases for the commitment abstraction, where random search does not reach: a commitment field at the front of a concatenation, whose leading byte is the field's only when the field is non-empty.
- `tests/oracle-consensus.test.ts` — random token transactions against libauth's `verifyTransactionTokens`: whatever libauth accepts, the hand-written tally admits; the modelled rules are shown to reject exactly what libauth rejects. The tally is deliberately weaker (no fungible conservation, a coarser commitment identity), which is reported, not asserted away.
- `tests/oracle-decode.test.ts` — the one CashScript-provided step, the ASM decoder, is cross-checked on every ParyonUSD artifact against an independent reading with libauth's opcode table and a libauth encode/decode round-trip.

Every case is reproducible from its seed (`ORACLE_SEED`) and the volume scales with `ORACLE_CASES`. See [docs/artifact-derivation.md](docs/artifact-derivation.md) for the abstraction gaps building the oracle turned up.
