# Scope and architecture

What this repo checks, what it deliberately does not, and which code is general BCH/CashTokens
machinery versus ParyonUSD-specific.

## What is checked

One property: **NFT-capability non-leak**, checked as preservation of the system invariant. For the
internal-authority categories, no transaction allowed by the CashTokens token-validation rules and the
system's covenants can place a *mutable or minting* capability of those categories on an output other
than a covenant that rightfully owns it, or a provable burn. See the README for the formal statement,
the induction, and the ledger of invariants.

The model captures exactly what governs capability movement:

- the per-category CashTokens token tally (minting / mutable / immutable-or-fungible counts, the
  "no minting/mutable created without the matching input" rules, and immutable-commitment matching);
- structural presence / contiguity and the category ↔ token consistency of each UTXO;
- token-category **identity + capability suffix** (including `tokenCategory.split(32)[1]`, the
  capability byte on its own), locking-script **identity** (covenant / burn / attacker), output
  **count** caps;
- NFT commitment **identity** as three fields: an integer reading, a byte **length**, and the
  **leading byte** every covenant discriminates on (`0x00` price, `0x01` loan, `0x02`..`0x08` the loan
  functions);
- **outpoints**: the identity of the transaction an input spends and the output index within it, so
  the adjacency checks the loan and pool covenants authenticate their sidecar with decide exactly, as
  does the genesis precondition `tx.inputs[0].outpointIndex == 0`;
- satoshi **values** and fungible **amounts** where a contract *compares* them (`tokenAmount == 0`,
  `value == 1000`, `out.value >= in.value`): exact model integers. Arithmetic on them is exact only
  against a constant (`outpointIndex + 1`); sums of two symbolic quantities stay opaque.

Alongside the leak witness, four more discharge the rest of the invariant: **forged-function-NFT**
(authenticity), **function-NFT preservation** (liveness), **sidecar adjacency**, and **state identifier**.
Each is listed with what it assumes and what discharges it in the README's ledger.

## What is NOT checked (and why that's sound)

These are out of scope and the model asserts nothing about them:

- **BCH value conservation and miner fees** (the satoshi balance of inputs vs outputs).
- **Fungible-token amount conservation** (PUSD debt, collateral, staked balances, interest/fee math).
  Amounts and values appear in the model only where a contract compares them directly; products,
  quotients and sums of two symbolic quantities are opaque.
- **Standardness, including the dust threshold.** Dust is *not* a flat 540/546 sats: a standard node
  requires an output's value to be at least `444 + 3 * outputSize` sats, so token-bearing outputs need
  more than a pre-token P2PKH did. ~1000 sats is the practical default for P2PKH/P2SH outputs and
  custom locking bytecode may need higher; OP_RETURN outputs are exempt. None of this can move an NFT
  capability, so it is not modelled.
- **nftCommitment contents** beyond the integer reading, the length and the leading byte (loan / pool /
  price / redemption *state* is treated opaquely; it is split and reconstructed without constraint).
- **Locktime / sequence (timelock) semantics, signatures, and arithmetic results** (treated opaque).

Dropping all of the above is sound *for a leak-freedom proof*: fewer constraints describe a
**superset** of real transactions, so `UNSAT` on the model implies `UNSAT` on chain. They are genuinely
separate concerns, covered by separate tools:

- functional correctness + per-`require` coverage (incl. the value/arithmetic logic): `paryon_testing_suite`;
- the proof's base case + "the live chain runs these artifacts": `verify_contract_deployment`;
- value-conservation and commitment-integrity as their own properties: not yet built.

## The bound

The proof is a *bounded* one: transactions with at most 9 inputs and 11 outputs. Within that bound the
solver is free, so batched and multi-operation transactions are covered. Outside it nothing is claimed.

The bound has one sharp edge, and the builder surfaces it rather than hiding it. When a covenant reads
a UTXO index the build does not carry, the path is pruned and `script == S ⇒ OR(paths)` collapses to
`script == S ⇒ false` at that index: the build concludes that covenant cannot sit there. `cutSites`
returns every such site and `tests/whole-system.test.ts` enumerates the accepted set with the argument
for why those shapes are outside the bound anyway (`Loan.interact` and `StabilityPool.interact` read
their function NFT two inputs on, so a loan or pool at input 7 or 8 needs a tenth input). A cut
anywhere else fails the suite.

## How the abstraction is validated

The model is an idealised VM, and the soundness argument has one direction the superset reasoning
cannot cover: the real VM must never *accept* a transaction the model rejects. That direction is
tested differentially against libauth (`tests/oracle-*.test.ts`, engine in `src/oracle/`):
random concrete transactions and scripts are evaluated by libauth's BCH VM and CashTokens validation
and abstracted into the model, and whatever libauth accepts the model must admit. On the constructs
the model claims to capture exactly the verdicts must agree both ways. libauth is the oracle because
it is cross-validated with BCHN on the shared VMB test vectors; the oracle depends on nothing from
CashScript, and the CashScript ASM decoder itself is cross-checked against libauth on every artifact.

Where random search cannot reach a construct — the leading byte of a concatenation starting with a
possibly-empty commitment field needs the output commitment to be exactly the input's plus the appended
bytes — `tests/oracle-commitment.test.ts` drives the case directly.

Known, deliberate imprecisions the oracle reports rather than flags: the tally ignores fungible
conservation, and its immutable-NFT commitment identity is the integer reading plus the length rather
than the bytes (so it matches `0x00` with `0x80`). Both are coarsenings, which only admit more; and
script-identity / commitment equalities are exact only as positive requirements (under negation they
carry no constraint, by construction: see `docs/artifact-derivation.md`).

## BCH/CashTokens engine vs ParyonUSD-specific

The engine is reusable for any CashScript/CashTokens system; only the registry, the policy and the
category/script id assignment are ParyonUSD-specific.

**Engine (general, no ParyonUSD knowledge):**

| file | role |
|---|---|
| `src/z3.ts` | Z3 context, solver, and the native decision procedure (`checkNative` / `modelNative`) |
| `src/model.ts` | symbolic UTXO/tx model; capability + category encoding; commitment and outpoint fields; enum-domain bounds |
| `src/consensus.ts` | CashTokens token-validation tally + structural and outpoint rules (the trusted base) |
| `src/policy.ts` | the invariant *mechanism*: the five clauses, the hypothesis on inputs, and a witness per clause |
| `src/covenant.ts` | `Covenant` interface + `compose` (small, used by an illustrative test) |
| `src/script/artifact.ts` | the shape of a CashScript artifact this project consumes |
| `src/script/script.ts` | opcode table + ASM decoding (from `@cashscript/utils`) and CScriptNum helpers |
| `src/script/value.ts` | the symbolic value language: the abstract stack values and their constructors |
| `src/script/interpreter.ts` | the stack machine — opcode dispatch, stack routing, CAT/SPLIT, index arithmetic, branch forking. Obligation: **faithful** (the half the superset argument does *not* protect) |
| `src/script/capability.ts` | the capability abstraction — which comparisons can move a capability, and their Z3 constraints. Obligation: **conservative** (drops constraints only) |
| `src/script/wholeSystem.ts` | the whole-system build: per-input covenant implications, the shared constraints, and the solvers each query gets |
| `src/oracle/concrete.ts` | the differential oracle's concrete side: concrete transactions, the libauth bridge, and the abstraction `fixTx` into the model |
| `src/oracle/scriptgen.ts` | random covenant-shaped script generator (exact / wide modes) for the interpreter-vs-libauth test |

**ParyonUSD-specific (the instantiation):**

| file | role |
|---|---|
| `src/covenants/ids.ts` | the category/script id registry: which contracts exist (arbitrary identity ints) |
| `src/covenants/registry.ts` | which script runs which artifact, with which constructor arguments |
| `src/covenants/common.ts` | the identifiers the contracts authenticate by, and `SYSTEM_POLICY` — the invariant |
| `tests/whole-system*.test.ts` | the proof, the historical regressions and the composition control |

The category set the tally ranges over is passed in via the build config (`LOAN_CATEGORIES` from
`common.ts`), so the engine itself imports nothing from `src/covenants`. Identities are modelled as
small ints because the property only needs equality; the real 32-byte tokenIds and ~35-byte P2SH32
scripts are checked on chain by `verify_contract_deployment`.
