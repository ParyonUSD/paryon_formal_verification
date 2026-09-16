# Constraints derived from artifact bytecode (`src/script/`)

Every covenant constraint in this repo is **generated from the compiled `@paryonusd/contracts`
bytecode** — it is what runs on-chain, and it is the only source of contract logic here. The pipeline:

1. `@cashscript/utils` `asmToScript` turns the published artifact bytecode into a canonical
   `(opcode | data)[]`.
2. `interpreter.ts` symbolically executes it over an abstract stack, emitting a Z3 constraint **only**
   for comparisons that can move a capability: token-category equality (→ category + suffix class),
   capability-suffix equality, locking-bytecode equality (→ script id), outpoint identity and index,
   output-count caps, and the commitment's integer reading, length and leading byte. Values, amounts,
   commitment *contents* and arithmetic are opaque (sound: a superset).
3. `wholeSystem.ts` runs one interpretation per (covenant, function, input index) and asserts, for
   every input, that its script being that covenant implies one of that covenant's paths there.

## What the bytecode forced us to get right

Each is a real subtlety a hand model would paper over:

- **tokenCategory is bytes, not a (cat, cap) pair.** Immutable NFTs and fungible-only UTXOs both
  serialise to a bare 32-byte category, so equality is compared by a *suffix class*
  (empty / bare / +0x01 / +0x02), not by capability id.
- **The capability byte on its own.** `tokenCategory.split(32)[1]` is the empty string for a bare
  category, `0x01` for mutable and `0x02` for minting — exactly the suffix class. Dropping it made
  `Borrowing.borrow`'s `require(loanKeyCapability == 0x02)` vacuous, and an immutable paryon NFT could
  then pass as the prepared loanKey, after which borrow's own output pins minted a paryon *minting*
  NFT straight to the user.
- **Correlated branches.** `closeLoan` is tested by several `OP_IF`/`OP_NOTIF`; forking each
  independently invented an infeasible "neither recreated nor burned" path (a false leak). The
  interpreter tracks decided conditions by SVal identity (OP_DUP shares the reference).
- **OP_RETURN burns are built at runtime** (`0x6a … OP_CAT`); a constant locking script starting
  `0x6a` is classified as the provably-unspendable BURN sink (and `0x76` P2PKH as user/ATTACKER).
- **Multi-function dispatch + disjunctive guards.** A seeded function **selector** picks one branch of
  a multi-function contract; `OP_BOOLOR` of two category equalities (the `out == 0x || out == paryon`
  anti-leak guards) is propagated as a real disjunction; and forking an `OP_IF` asserts the branch
  condition so an `outputs.length > N`-guarded optional output is constrained on the right path.
- **Index arithmetic.** `OP_1ADD`/`OP_1SUB`/`OP_ADD`/`OP_SUB` stay *concrete* on concrete bytes, so a
  computed output index resolves and `toIndex` can read it; against a resolved model number and a
  constant they become the linear expression, which is what makes
  `inputs[k].outpointIndex == inputs[i].outpointIndex + 1` exact. Two symbolic operands stay opaque.
- **Genesis.** `OP_OUTPOINTTXHASH` used as a category base (`LoanKeyFactory` minting a fresh per-loan
  loanKey) yields a distinct genesis category, outside the tallied set and not an internal authority.
  It is keyed by the *identity of the spent transaction*, not the input's position, because that is
  what a genesis category id is. The precondition needs no rule of its own:
  `LoanKeyFactory.create` states `require(tx.inputs[0].outpointIndex == 0)` itself, and outpoint
  indices are modelled.
- **Commitments.** The commitment is three fields — an integer reading, a byte length, and the leading
  byte. The last is not a luxury: every covenant tells one kind of state NFT from another by it
  (`nftCommitment.split(1)[0] == 0x00` is the price contract, `0x01` a loan, `0x04` the
  startRedemption function NFT), and without it the model could not tell a price contract from a loan
  and used one in the other's place.

## What the libauth oracle forced us to get right

`tests/oracle-interpreter.test.ts` runs random covenant-shaped scripts through libauth's VM and the
symbolic interpreter side by side (see README, "Checked against libauth"). Building and extending it
surfaced:

- **Class identities are not exact identities.** `ATTACKER` stands for every user script, `BURN` for
  every nulldata, and one covenant id for every instance of that contract; a commitment int identifies
  several byte strings (`0x` and `0x00` both read as 0). So `out.bytecode == <p2pkh>` ⇒ `out.script
  == ATTACKER` holds, but not the converse, and asserting the converse under `OP_NOT` / in an else
  branch would *exclude* real transactions — an unsoundness the superset argument does not see.
  `capability.ts` therefore marks such equalities *lossy*, and the interpreter is polarity-aware: a
  lossy predicate is asserted where the script requires it true (`OP_VERIFY`, the taken side of a
  branch), conjunctions/disjunctions inherit the mark, and its negation is never asserted. Category,
  capability-suffix and outpoint equality need no such treatment (those identities are exact), which is
  why they stay exact under negation. (A first attempt encoded the same thing as
  `necessary ∧ fresh-free-boolean`; semantically identical, but the extra free booleans sent Z3's
  pseudo-boolean theory into a multi-gigabyte blow-up, so the polarity encoding is the one that stays.)
- **A capability suffix on a raw `tokenCategory` field.** `paryonTokenId + 0x01` where `paryonTokenId`
  is the active input's category is a category string only if that field was bare (32 bytes); an empty
  or already-suffixed base gives a 1- or 34-byte string that equals no category, though two such
  strings can equal *each other*. The suffix class therefore encodes the full structure (classes 4..9
  in `APPEND_CLASS`, next to the four introspection classes), so the equality decides exactly instead
  of being dropped — dropping it loses the price/loan authentication in `manage`, which the historical
  manage regression caught, and collapsing the non-category cases into one class made `0x + 02` equal
  `0x + 01`, which the oracle caught.
- **Concrete truth values.** `OP_NOT`, `OP_BOOLAND`, `OP_BOOLOR` and `OP_0NOTEQUAL` on concrete byte
  strings use the VM's truthiness (CScriptNum non-zero; negative zero is false) instead of going
  opaque, and commitment constants beyond the exact-integer range carry no constraint rather than
  crashing the interpreter.
- **`OP_CHECKDATASIG` pops three operands, not two.** Everything below it in
  `PriceContract.updatePrice` was mis-routed and its earlier proof ran on a wrong stack. The fuzzer now
  emits CHECKDATASIG, negative constants (the CScriptNum decoder was also not sign-magnitude), NUM2BIN
  and `OP_SIZE` of commitments and categories.
- **A commitment field at the front of a concatenation has no known first byte.** The head of
  `nftCommitment + 0x05` is the field's only when the field is non-empty, and an empty commitment is an
  ordinary run-time value. Claiming it unconditionally made the model *reject* transactions libauth
  accepts. The head is taken only from a part with a statically known byte in it
  (`concreteMinLength >= 1`), which keeps `0x01 + toPaddedBytes(..) + field` — where the prefix is
  concrete but the total length is symbolic — and drops the ambiguous case. Random search does not
  reach this (it needs the output commitment to be exactly the input's plus the appended bytes), so
  `tests/oracle-commitment.test.ts` drives it directly.

## An imprecision of the contracts, recorded

`Borrowing.borrow` pins its borrowed-token output to the **bare** `paryonTokenId` with
`nftCommitment == 0x`:

```
require(tx.outputs[6].tokenCategory == paryonTokenId);
require(tx.outputs[6].nftCommitment == 0x);
```

A bare 32-byte category is "immutable NFT **or** fungible-only" — the two are indistinguishable in the
introspection encoding — and an empty commitment satisfies the second line. With the paryon *minting*
NFT at input 0 lifting the tally, `borrow` can therefore hand the borrower a paryon **immutable NFT
with an empty commitment**, on a locking script of their choosing (output 6's bytecode is not pinned).

It is harmless, and this is why: every consumer of a paryon immutable NFT either requires
`commitment.length == 1` (`Loan.interact`, `StabilityPool.interact`) or reads
`nftCommitment.split(1)[0]` (`Redeemer.createRedemption`), which is a VM error on an empty commitment.
So such an NFT can impersonate nothing. It is recorded here rather than treated as a proof gap, and it
is the reason the `exhaustiveNonEmpty` clause of the function-NFT invariant is stated for *non-empty*
commitments: "every paryon immutable NFT is a function NFT" is simply false, while "every paryon
immutable NFT with a non-empty commitment is a function NFT" is true and is what the covenants need.

## Modelling notes (assumptions worth reviewing)

- **Scope:** category / capability / locking-script / NFT-count / output-count / outpoint /
  commitment-identity are modelled. BCH values, fungible amounts and commitment contents are omitted —
  none can move an NFT capability, and dropping them yields a sound *superset* (and keeps Z3 fast).
- **The invariant** (`SYSTEM_POLICY`) is the reviewable claim, and it is not merely assumed: each of
  its five clauses is discharged on the outputs by its own witness, so the only thing taken on trust is
  the genesis state, which `verify_contract_deployment` checks. See the README's ledger.
- **Enum ids** (`category`, `script`, `outpointTx`) are bounded so the solver searches a finite domain.
  For categories and scripts the attacker can still pick any in-range value, so bounds hide no leak.
  For the outpoint transaction identity the bound is `0..nIn-1`: all that is observable is the partition
  of the inputs into "same source transaction", and every partition of n inputs fits n values.
- **Output capacity:** a leak needs an output slot no covenant pins, so `buildWholeSystem` refuses a
  capacity that ends at the highest index any covenant reads.
- **Class identity of covenant scripts.** One script id stands for every instance of a contract. For
  contracts with constructor arguments (PriceContract, Collector, payInterest, …) that means the model
  treats an instance with *different* constructor arguments as the same script; the registry seeds the
  deployed arguments, and `verify_contract_deployment` is what ties the id to the real P2SH32.

## Next steps

- Lift the 9-input / 11-output bound, or argue it away: the five capacity-cut sites are the only place
  the bound, rather than a contract, decides anything.
- Layer in value-conservation and commitment-integrity as separate properties.
