# Future work

What is still worth proving or improving with this setup, after the whole-system formulation. Ranked
within each section by value per effort. Items marked *cheap* are hours; *small* a day or two;
*project* weeks. Everything here stays inside the current abstraction (categories, capabilities,
script identities, counts, values and amounts in comparisons, commitment ints/lengths/leading byte,
outpoints) unless stated.

## Properties

1. **Per-owner authority conservation** (*small*). For each `(category, capability, ownerScript)` in
   `SYSTEM_POLICY.ownership`, `#outputs >= #inputs` unless a named function runs (`FN_MANAGE` on
   close, `FN_LIQUIDATE`). One clause proves two things nothing checks today: no privileged authority
   is duplicated (a second Borrowing, Payout or Collector authority is currently prevented by covenant
   accident), and none is burned by a covenant bug except where the design burns it. Formulating it as
   a count rather than a burn allow-list keeps the intentional burns out of a hand-written exception
   list.
2. **Function-NFT uniqueness in flight** (*cheap*). `preservationWitness` proves a spent function NFT
   is recreated, not that it is recreated *once*: with a minting input present, a copy next to the
   original is admitted. Add `#outputs of (category, immutable, fnScript, id) <= #inputs` per site.
3. **Sidecar content** (*cheap*). `adjacency` proves the UTXO after a loan sits on `LOAN_SIDECAR`, not
   what it carries. A `stateShapes`-style clause (script -> category class) closes it; without it a
   wrong sidecar category at genesis or via `borrow` would propagate through `attach`.
4. **The migration key as a modelled input hypothesis** (*small*). Register `migrateContract` and
   assume "no `oracleMigrationKey` token on any input" instead of excluding the function. The trust
   assumption becomes exactly one category, machine-visible, and the leak witness proves nothing else
   moves the price NFT off `PRICE`.
5. **The economic invariant** (*project*). PUSD leaves the Borrowing contract only through `borrow`,
   against a loan whose debt and collateral match the price. This is the highest-value property not
   proven anywhere. It needs byte-exact commitment layouts and the contracts' arithmetic (division,
   multiplication), i.e. nonlinear or bit-vector reasoning; still SMT territory, and a separate model
   rather than an extension of this one.

## Precision that would remove imprecision the model works around

6. **Commitment bytes beyond the first** (*small*). The leading byte was decisive (price vs loan). A
   byte-at-constant-offset map recovers the loan status byte, `interestManager != 0x00` and
   `amountBeingRedeemed == 0`, all of which contracts branch on and all currently opaque.
7. **Exact script identity for covenants** (*small*). Every locking-bytecode equality is lossy, but only
   `ATTACKER` and `BURN` are genuine classes; a covenant's bytecode is fixed by its artifact and
   constructor arguments, so covenant-to-covenant equality could be exact and `!=` checks on covenant
   scripts would stop contributing nothing. Per-instance covenants (loans) need care: the id is a class
   until constructor arguments are modelled.
8. **Pin absent slots fully** (*cheap*). `addStructure` leaves an absent slot's value, commitment
   length and head free, so an absent output can satisfy `value == 1000`. Sound, but it makes
   counterexamples harder to read.
9. **Genesis-category range** (*cheap*). `GENESIS_BASE + outpointTx` lands in 20..28 against registry
   ids <= 11 and `MAX_CATEGORY` 31. It holds by arithmetic nobody checks; add an assertion.

## The bound

10. **Wider one-off builds** (*cheap*). Confirm every witness stays unsat at 12x14 and a couple of
    intermediate capacities. The bound is empirical: adding a slot is *not* monotone, because
    covenants read absolute indices and `OP_TXOUTPUTCOUNT`, so a wider build admits different
    transactions rather than a superset with inert slots. A permutation argument is not available
    without formalising it. The cost driver at larger capacity is `addImmutableMatching`'s
    `nIn x nOut` match matrix under the forged witness (4.5 s at 12x14 for the loan build), not the
    covenant implications (~100 ms, linear in capacity).

## Oracle: constructs the artifacts use that the fuzzer still does not emit

Each of these is a construct whose faithfulness currently rests on code reading only.

11. **A whole-transaction differential oracle** (*small*). The oracle validates `interpret` for one
    script at one index. The mechanism that carries the proof, `script_i == S => OR(paths at i)`
    composed across inputs, is cross-checked by nothing. A concrete multi-covenant transaction
    evaluated input by input with libauth, then abstracted, closes it.
12. **Multi-function selector dispatch** (`n OP_PICK k OP_NUMEQUAL OP_IF ...`) and **computed
    introspection indices** (`OP_1ADD`/`OP_ADD` results fed to `OP_OUTPUT*`): the two constructs
    behind both historical leaks, exercised only by the artifacts themselves.
13. **Genesis path**: `OP_OUTPOINTTXHASH || 0x02` as a category base and `OP_OUTPOINTINDEX == 0`, with
    `outpointIndex: 0` on the concrete side.
14. **Commitment concatenations with a field in the middle or at the end** and `OP_SPLIT` at symbolic
    lengths: the `certainlyNonEmpty` and lower-bound logic has only hand-written cases.
15. **Direct-argument branch conditions**, `OP_CHECKLOCKTIMEVERIFY` / `OP_INPUTSEQUENCENUMBER` paths,
    `OP_ELSE` at nesting depth 3.
16. **Sweep volume in CI** (*cheap*): a nightly multi-seed run at the per-process ceiling, asserted
    rather than run by hand.

## Base case and the deployment checker

17. **Registry and policy derived from `contractAddresses.ts`** (*small*). The registry seeds and the
    ownership map are typed by hand here and again in `verify_contract_deployment`; the two lists
    must agree and nothing says so. A generated JSON consumed by the registry, or a test that diffs
    them, removes the last duplicated trust input.
18. **Exactly-one checks at genesis** (*cheap*): each function address received exactly one NFT (today:
    all eight addresses were seen), the pool-function NFTs and the Collector mutable likewise, the
    loanKey factory minting NFT unique and no `LOANKEY_FACTORY` immutable outside `ORIGIN_PROOF`
    outputs.

## Tooling

19. **cvc5 as a CI job** (*cheap*). The emitted `.smt2` files are QF_LIA; `cvc5 --lang smt2` over all of
    them takes about a minute and turns solver independence from a claim into a test.
20. **Derived IO layout as a checked spec** (*cheap*). The build already computes which indices each
    covenant can occupy (`sites`); asserting the expected table catches a contract upgrade that
    silently moves an `activeInputIndex` pin, the class of the `updatePeriodState` bug.
21. **Counterexample minimisation** (*small*). A greedy "unset each slot, re-check" pass would cut a
    9x11 witness to its five-input core and make findings reviewable in minutes.
22. **Proof-artifact pinning** (*cheap*). Hash the emitted `.smt2` set per commit so a re-run elsewhere
    can be checked for drift in the encoding, not only in verdicts.
23. **Opcode effect table compared against libauth mechanically** (*cheap*). The interpreter's
    arity/stack-effect table (~100 lines) is the faithful half the oracle covers only statistically;
    extracting it and diffing it against libauth's opcode definitions makes that exact.

## Lean, or another proof assistant

What a proof assistant buys is the meta-level: the induction schema, the claim that the witnesses
compose to the invariant, and unbounded statements over transaction sequences. What it does not buy
is the trust that dominates here. Interpreter faithfulness would move into a Lean model of BCH script
and CashTokens (months of formalisation) which then needs the same libauth-style validation, because
a formal semantics can be wrong in exactly the ways an interpreter can. The registry and policy stay
deployment facts either way, and the per-transaction verdicts stay solver output unless SMT proofs
are reconstructed in Lean, a research-grade effort for a gain that a second solver (item 19) mostly
provides. Revisit only if an audit asks for kernel-checked proofs of the meta-argument, and then scope
it to the induction and any bound lemma, not to the VM semantics.
