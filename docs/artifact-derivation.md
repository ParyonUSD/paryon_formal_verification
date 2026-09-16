# Constraints derived from artifact bytecode (`src/script/`)

The covenant output pins were the error-prone hand-transcribed part, so they are **generated from the
compiled `@paryonusd/contracts` bytecode** — this is the source of truth (it is what runs on-chain),
and the hand-written loan-function models have been removed in favour of it. The pipeline:

1. `@cashscript/utils` `asmToScript` turns the published `@paryonusd/contracts` artifact bytecode
   into a canonical `(opcode | data)[]`.
2. `interpreter.ts` symbolically executes it over an abstract stack, emitting a Z3 constraint
   **only** for comparisons that can move a capability: token-category equality (→ category +
   suffix-class), locking-bytecode equality (→ script id), and output-count caps. Commitments,
   values, amounts and arithmetic are opaque (sound: a superset).
3. `fromArtifact.ts` seeds constructor args + function args (stack layout
   `[funcArgs, selector?, constructorReversed]`), runs one interpreter per co-present contract,
   and builds one solver per reachable script-path combo.

## What the bytecode-derived version forced us to get right

Each is a real subtlety the hand model papered over:

- **tokenCategory is bytes, not a (cat,cap) pair.** Immutable NFTs and fungible-only UTXOs both
  serialise to a bare 32-byte category, so equality is compared by a *suffix class*
  (empty / bare / +0x01 / +0x02), not by capability id.
- **Correlated branches.** `closeLoan` is tested by several `OP_IF`/`OP_NOTIF`; forking each
  independently invented an infeasible "neither recreated nor burned" path (a false leak). The
  interpreter tracks decided conditions by SVal identity (OP_DUP shares the reference).
- **OP_RETURN burns are built at runtime** (`0x6a … OP_CAT`); a constant locking script starting
  `0x6a` is classified as the provably-unspendable BURN sink (and `0x76` P2PKH as user/ATTACKER).
- **Multi-function dispatch + disjunctive guards.** A seeded function **selector** picks one branch
  of a multi-function contract (`Redemption.finalizeRedemption` / `swapTargetLoan`, `Collector`,
  `Borrowing`); `OP_BOOLOR` of two category equalities (the `out == 0x || out == paryon` anti-leak
  guards) is propagated as a real disjunction; and forking an `OP_IF` asserts the branch condition so
  an `outputs.length > N`-guarded optional output is constrained on the right path.
- **Concrete arithmetic on indices.** `OP_1ADD`/`OP_1SUB` stay concrete on concrete bytes (so a
  computed output index / `outputs.length <= idx+1` cap resolves), and numeric compares go opaque —
  never silently 0 — when an operand is unresolved.
- **Genesis.** `OP_OUTPOINTTXHASH` used as a category base (`LoanKeyFactory` minting a fresh per-loan
  loanKey) yields a distinct genesis category, outside the tallied set and not an internal authority.
- **Commitments.** The NFT commitment is modelled as an integer, resolved only where a contract
  branches on a small constant — the function-NFT identifiers (`LoanFunction` / `PoolFunction`, e.g.
  `StabilityPool.interact`'s `commitment == 0x02` selecting its output index). Everything else (loan
  state etc.) is split/reconstructed opaquely. Pinning the function ids is what lets the recreation
  partners pick the right output index instead of forking into a spurious branch.

## What the libauth oracle forced us to get right

`tests/oracle-interpreter.test.ts` runs random covenant-shaped scripts through libauth's VM and the
symbolic interpreter side by side (see README, "Checked against libauth"). Building it surfaced:

- **Class identities are not exact identities.** `ATTACKER` stands for every user script, `BURN` for
  every nulldata, and one covenant id for every instance of that contract; a commitment int identifies
  several byte strings (`0x` and `0x00` both read as 0). So `out.bytecode == <p2pkh>` ⇒ `out.script
  == ATTACKER` holds, but not the converse, and asserting the converse under `OP_NOT` / in an else
  branch would *exclude* real transactions — an unsoundness the superset argument does not see.
  `capability.ts` therefore marks such equalities *lossy*, and the interpreter is polarity-aware: a
  lossy predicate is asserted where the script requires it true (`OP_VERIFY`, the taken side of a
  branch), conjunctions/disjunctions inherit the mark, and its negation is never asserted (`OP_NOT`
  and the untaken side of a branch contribute nothing). Category equality needs no such treatment
  (category ids and the suffix class are exact), which is why it stays exact under negation. (A first
  attempt encoded the same thing as `necessary ∧ fresh-free-boolean`; semantically identical, but the
  extra free booleans sent Z3's pseudo-boolean theory into a multi-gigabyte blow-up on the manage
  regression build, so the polarity encoding is the one that stays.)
- **A capability suffix on a raw `tokenCategory` field.** `paryonTokenId + 0x01` where
  `paryonTokenId` is the active input's category is a category string only if that field was bare
  (32 bytes); an empty or already-suffixed base gives a 1- or 34-byte string that equals no category,
  though two such strings can equal *each other*. The suffix class therefore encodes the full
  structure (classes 4..9 in `APPEND_CLASS`, next to the four introspection classes), so the equality
  decides exactly instead of being dropped — dropping it loses the price/loan authentication in
  `manage`, which the historical-leak regression test caught, and collapsing the non-category cases
  into one class made `0x + 02` equal `0x + 01`, which the oracle caught.
- **Concrete truth values.** `OP_NOT`, `OP_BOOLAND`, `OP_BOOLOR` and `OP_0NOTEQUAL` on concrete byte
  strings now use the VM's truthiness (CScriptNum non-zero; negative zero is false) instead of going
  opaque, and commitment constants beyond the exact-integer range carry no constraint rather than
  crashing the interpreter.

## Coverage of the artifact derivation

Every covenant is now derived from artifact bytecode — there are **no hand-modelled covenants left**.
The only hand-written part of each test is the input `setup` (the transaction shape: which input is
the loan/price/pool/etc.), plus the leak policy.

- **Loan functions** (single-function contracts): all 8 derived.
- **Redemption system** (`tests/artifact-redemption.test.ts`): `Redeemer.createRedemption` (minting
  authority, script-typed constructor seeds), `Redemption.finalizeRedemption` + `swapTargetLoan`
  (multi-function), `PriceContract.sharePrice`, and `LoanTokenSidecar.attach` — all derived.
- **Stability-pool subsystem** (`tests/artifact-pool.test.ts`): `AddLiquidity`, `WithdrawFromPool`,
  `NewPeriodPool`, `LiquidateLoan`, `Payout.claimPayout`, `Collector` (multi-function),
  `StabilityPool.interact`, and `StabilityPoolSidecar.attach` — all derived.
- **Borrowing + loanKey factory** (`tests/artifact-loankey.test.ts`): `Borrowing.borrow` and
  `Borrowing.updatePeriodState` (multi-function, paryon minting authority), `LoanKeyFactory.create`
  (genesis-mints a per-loan loanKey), and `PriceContract.sharePrice` — all derived.

Two covenants are intentionally omitted because they pin no outputs (auth/adjacency only, no
capability effect): `RedemptionSidecar.attach`, `LoanKeyOriginEnforcer.enforce` /
`LoanKeyOriginProof.attach`.

## Modelling notes (assumptions worth reviewing)

- **Scope:** category / capability / locking-script / NFT-count / output-count are modelled.
  BCH values, fungible amounts and nftCommitment contents are omitted — none can move an NFT
  capability, and dropping them yields a sound *superset* of transactions (and keeps Z3 fast).
- **Ownership map** (`LeakPolicy.ownership`): each template states which covenant rightfully
  holds each privileged `(category, capability)` — this is the inductive hypothesis and a
  reviewable claim.
- **Designated privileged inputs** (`privilegedInputsOnlyAt`): each check fixes which input indices
  carry a privileged capability, because on-chain a privileged UTXO can only be spent by running its
  governing covenant. Batching several governed UTXOs into one tx is a distinct (larger) template —
  a known limitation to lift later.
- Enum ids (`category`, `script`) are bounded (`MAX_CATEGORY`/`MAX_SCRIPT`) so the solver searches a
  finite domain; the attacker can still pick any in-range value, so bounds hide no leak.

## Next steps

- Generate the input `setup` (transaction shape) from the artifacts' documented IO layouts too, so
  templates are fully generated rather than partly hand-written.
- Lift the single-operation-per-tx assumption (multi-loan batched templates).
- Layer in value-conservation and commitment-integrity as separate properties.
