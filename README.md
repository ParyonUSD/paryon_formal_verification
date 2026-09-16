# Paryon Formal Verification

Bounded model checking of the ParyonUSD CashScript contracts for NFT-capability leaks, using [Z3](https://github.com/Z3Prover/z3) via its TypeScript bindings.

It uses the real CashScript artifacts and resolves instantiated locking bytecodes in-process, keeping one stack.

## The property

For every internal-authority category (the five ParyonUSD deploy categories), no transaction allowed by CashTokens consensus and the system's covenants can place that category's mutable or minting capability on an output other than a covenant that rightfully owns it, or a provable burn.

We check it per transaction template: assert `consensus ∧ covenants ∧ leak` and expect `unsat`. A `sat` result is a concrete counterexample transaction. The witness is invariant preservation, not merely "no attacker output": the inputs are assumed to satisfy the ownership invariant (every privileged NFT sits on its owning covenant), so the outputs are required to satisfy the same invariant, which is what lets the single-transaction result lift to "the attacker can never come to hold such a capability" by induction over the covenant lifetime (deploy state is the base case). A privileged NFT parked on the wrong covenant would count as a leak: that covenant's code does not protect it. The per-template ownership list is therefore a reviewed specification of where each capability may legitimately go.

A second, liveness-flavoured witness rides on the same machinery: every *function NFT* (the immutable NFTs whose presence on their function script makes each covenant operation possible) that a transaction spends must be recreated in place, with the same category, script and commitment. Losing one is not a leak but bricks that operation for everyone. `FUNCTION_NFTS` in `src/covenants/common.ts` lists them; `expectArtifactSafe` checks both witnesses on every path.

Two guards keep templates honest. The builder refuses a template whose output capacity ends exactly at the highest output index a covenant touches, since a leak needs an unpinned slot and a too-small template would prove nothing. And `tests/coverage.test.ts` is a ledger of every function of every published artifact: each is either verified by a named template or excluded with a reason, so a new or forgotten function fails the suite.

## Trust chain

This repo proves the inductive step over the compiled `@paryonusd/contracts` artifacts: no transaction satisfying the covenants can move a privileged capability off its rightful covenant. It assumes a clean base case, namely that every privileged mutable/minting NFT already sits on its owning covenant (the `inputsRespectInvariant` ownership hypothesis).

That base case, and the fact that the live chain runs these artifacts, is established by the companion tool `verify_contract_deployment`. Against the same artifacts, it confirms the genesis transactions deployed the expected contract addresses, that each privileged NFT was minted with the exact capability and commitment it should have, that the PUSD supply sits only on the Borrowing contract, and that no unexpected NFT/fungible outputs escaped at genesis.

Neither half stands alone: a proof about artifacts nobody deployed, or a verified-honest deployment of contracts nobody proved safe. Together they yield the real guarantee that the live system can never leak a privileged capability. Both bottom out on the same published artifacts.

## Scope

This repo proves one global safety invariant (no capability leak) over the whole space of adversarial transactions, but it deliberately abstracts away BCH values, token amounts, and most commitment contents. It is not a functional-correctness check: it does not verify the interest math, collateral ratios, debt accounting, or that each individual `require` fires. That is the job of the companion `paryon_testing_suite`, which builds a valid transaction for each of the 26 contracts on the real VM (libauth `MockNetworkProvider`) and mutates it to trigger every `require`.

The three ParyonUSD verification tools cover different axes, all against the same artifacts:

- `paryon_testing_suite` - functional correctness and per-`require` coverage (concrete, real VM).
- this repo - exhaustive proof of the capability-leak invariant over all consensus-valid transactions.
- `verify_contract_deployment` - the live chain runs these artifacts from an honest base state.

See [docs/scope.md](docs/scope.md) for the full breakdown of what is and is not checked, and which code is general BCH/CashTokens machinery versus ParyonUSD-specific.

## Layout

The engine (general BCH/CashTokens) lives in `src/` (`z3.ts`, `model.ts`, `consensus.ts`, `policy.ts`, `covenant.ts`, `script/*`, and the libauth differential oracle in `oracle/*`); the ParyonUSD instantiation lives in `src/covenants/` (the `ids.ts` registry and `common.ts` policy/helpers) and `tests/`. The consensus tally is the trusted base: without a minting input it enforces `minting_out == 0`, `mutable_out <= mutable_in`, and `nft_out <= nft_in` per category. See [docs/scope.md](docs/scope.md) for the per-file map.

The artifact interpreter is split by soundness obligation. `script/interpreter.ts` is the stack machine and must be faithful (a mis-routed value or mis-matched branch would silently constrain the wrong output, which the superset argument does not catch). `script/capability.ts` is the abstraction that decides which comparisons carry a capability, and only needs to be conservative: it drops constraints and never adds them, so it can only widen the transaction set it admits.

## Checked against libauth (the differential oracle)

The model is an idealised VM: values, amounts, arithmetic, signatures, hashes and VM limits are abstracted away. That is sound only if the abstraction never *rejects* a transaction the real VM accepts, and that claim is not something the superset argument can establish by itself. So the faithful half is tested differentially against [libauth](https://github.com/bitauth/libauth), whose BCH VM and CashTokens validation are cross-validated with BCHN on the shared VMB test vectors. Nothing in the oracle depends on CashScript.

`src/oracle/` builds *concrete* transactions (real 32-byte categories, real locking bytecode, real commitments), hands them to libauth as-is, and abstracts the same transaction into the model (`fixTx`). Three tests then hold the two sides against each other:

- `tests/oracle-interpreter.test.ts` — random covenant-shaped scripts (`src/oracle/scriptgen.ts`, with operands routed through a menu of stack-shuffle patterns) are run by libauth's VM and by the symbolic interpreter. Whatever libauth accepts, the model must admit on some path. On the *exact* subset (category identity, positive script-identity and commitment requirements, counts, boolean combinators and branches on those) the verdicts must agree in both directions, which rules out passing the soundness check by admitting everything.
- `tests/oracle-consensus.test.ts` — random token transactions against libauth's `verifyTransactionTokens`: whatever libauth accepts, the hand-written tally admits; the three modelled rules are shown to reject exactly what libauth rejects. The tally is deliberately weaker (no fungible conservation, no immutable-commitment matching), which is reported, not asserted away.
- `tests/oracle-decode.test.ts` — the one CashScript-provided step, the ASM decoder, is cross-checked on every ParyonUSD artifact against an independent reading with libauth's opcode table and a libauth encode/decode round-trip.

Every case is reproducible from its seed (`ORACLE_SEED`) and the volume scales with `ORACLE_CASES`. Building the oracle turned a latent abstraction gap into a fix: equalities on *class* identities (every P2PKH is `ATTACKER`, every nulldata is `BURN`, commitment ints identify several byte strings) are only necessary conditions for byte equality, so the interpreter now asserts them only where the script requires them true and never asserts their negation. The exact-mode generator also pins down that a suffix appended to a raw `tokenCategory` field is a category only when that field was bare, which the model decides exactly. See [docs/artifact-derivation.md](docs/artifact-derivation.md).

## Coverage

Every contract's covenant output pins are derived from the compiled `@paryonusd/contracts` bytecode by symbolic execution (no hand-transcribed contract logic), across all four subsystems:

| Subsystem | Transactions verified | Test file |
|---|---|---|
| Loan functions | changeInterest, manage, payInterest | `tests/artifact-loan.test.ts` |
| Redemption | startRedemption, finalize (redeem), swap | `tests/artifact-redemption.test.ts` |
| Stability pool | addLiquidity, withdraw, newPeriod, liquidate, payout | `tests/artifact-pool.test.ts` |
| Borrowing + loanKey | borrow, updatePeriodState, loanKey-factory create | `tests/artifact-loankey.test.ts` |
| Price contract | updatePrice (sharePrice as a partner everywhere) | `tests/artifact-price.test.ts` |

Each transaction is checked for non-vacuity (a valid tx is `sat`) and leak-freedom (consensus + covenants + leak is `unsat`). Several carry a `composition matters` test that drops a delegated partner covenant and shows the leak reappear, proving the cross-contract protection is load-bearing.

Two real, independently discovered historical capability leaks serve as end-to-end sanity checks (`tests/historical-leak.test.ts`): the pre-fix contracts, compiled with the cashc of their era, produce a satisfiable leak witness, and the fixed ones do not. They are `manage` closing a loan without burning its mutable NFT (fixed 2026-04) and `Borrowing.updatePeriodState` checking the wrong change-output index next to the paryon minting NFT (fixed 2025-11, paryon_contracts `3e9cf60`).

No covenant is hand-modelled; every contract (including the recreation/sidecar partners `PriceContract.sharePrice`, `StabilityPool.interact`, `LoanTokenSidecar`, `StabilityPoolSidecar`) has its constraints derived from bytecode. The only hand-written part of each test is the input `setup` (the transaction shape) and the leak policy. See [docs/artifact-derivation.md](docs/artifact-derivation.md) for the pipeline, the subtleties the bytecode forced us to get right, and the modelling assumptions worth reviewing.
