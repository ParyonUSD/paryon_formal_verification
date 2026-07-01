# Paryon Formal Verification

Bounded model checking of the ParyonUSD CashScript contracts for NFT-capability leaks, using [Z3](https://github.com/Z3Prover/z3) via its TypeScript bindings.

It uses the real CashScript artifacts and resolves instantiated locking bytecodes in-process, keeping one stack.

## The property

For every internal-authority category (the five ParyonUSD deploy categories), no transaction allowed by CashTokens consensus and the system's covenants can place that category's mutable or minting capability on an output controlled by anyone but a system covenant (or a provable burn).

We check it per transaction template: assert `consensus ∧ covenants ∧ leak` and expect `unsat`. A `sat` result is a concrete counterexample transaction. The single-transaction result lifts to "the attacker can never come to hold such a capability" by induction over the covenant lifetime (deploy state is the base case).

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

The engine (general BCH/CashTokens) lives in `src/` (`z3.ts`, `model.ts`, `consensus.ts`, `policy.ts`, `covenant.ts`, `script/*`); the ParyonUSD instantiation lives in `src/covenants/` (the `ids.ts` registry and `common.ts` policy/helpers) and `tests/`. The consensus tally is the trusted base: without a minting input it enforces `minting_out == 0`, `mutable_out <= mutable_in`, and `nft_out <= nft_in` per category. See [docs/scope.md](docs/scope.md) for the per-file map.

The artifact interpreter is split by soundness obligation. `script/interpreter.ts` is the stack machine and must be faithful (a mis-routed value or mis-matched branch would silently constrain the wrong output, which the superset argument does not catch). `script/capability.ts` is the abstraction that decides which comparisons carry a capability, and only needs to be conservative: it drops constraints and never adds them, so it can only widen the transaction set it admits.

## Coverage

Every contract's covenant output pins are derived from the compiled `@paryonusd/contracts` bytecode by symbolic execution (no hand-transcribed contract logic), across all four subsystems:

| Subsystem | Transactions verified | Test file |
|---|---|---|
| Loan functions | changeInterest, manage, payInterest | `tests/artifact-loan.test.ts` |
| Redemption | startRedemption, finalize (redeem), swap | `tests/artifact-redemption.test.ts` |
| Stability pool | addLiquidity, withdraw, newPeriod, liquidate, payout | `tests/artifact-pool.test.ts` |
| Borrowing + loanKey | borrow, loanKey-factory create | `tests/artifact-loankey.test.ts` |

Each transaction is checked for non-vacuity (a valid tx is `sat`) and leak-freedom (consensus + covenants + leak is `unsat`). Several carry a `composition matters` test that drops a delegated partner covenant and shows the leak reappear, proving the cross-contract protection is load-bearing.

No covenant is hand-modelled; every contract (including the recreation/sidecar partners `PriceContract.sharePrice`, `StabilityPool.interact`, `LoanTokenSidecar`, `StabilityPoolSidecar`) has its constraints derived from bytecode. The only hand-written part of each test is the input `setup` (the transaction shape) and the leak policy. See [docs/artifact-derivation.md](docs/artifact-derivation.md) for the pipeline, the subtleties the bytecode forced us to get right, and the modelling assumptions worth reviewing.
