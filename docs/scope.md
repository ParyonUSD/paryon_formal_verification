# Scope and architecture

What this repo checks, what it deliberately does not, and which code is general BCH/CashTokens
machinery versus ParyonUSD-specific.

## What is checked

One property: **NFT-capability non-leak**. For the internal-authority categories, no transaction
allowed by the CashTokens token-validation rules and the system's covenants can place a *mutable or
minting* capability of those categories on an output controlled by anyone but a system covenant (or a
provable burn). See the README for the formal statement and the inductive framing.

The model captures exactly what governs capability movement:

- the per-category CashTokens token tally (minting / mutable / immutable-or-fungible counts, and the
  "no minting/mutable created without the matching input" rules);
- structural presence / contiguity and the category &harr; token consistency of each UTXO;
- token-category **identity + capability suffix**, locking-script **identity** (covenant / burn /
  attacker), output **count** caps, and the single-byte function-NFT **commitment** identifiers.

## What is NOT checked (and why that's sound)

These are out of scope and the model asserts nothing about them:

- **BCH value conservation and miner fees** (the satoshi balance of inputs vs outputs).
- **Fungible-token amount conservation** (PUSD debt, collateral, staked balances, interest/fee math).
- **Standardness, including the dust threshold.** Dust is *not* a flat 540/546 sats: a standard node
  requires an output's value to be at least `444 + 3 * outputSize` sats, so token-bearing outputs need
  more than a pre-token P2PKH did. ~1000 sats is the practical default for P2PKH/P2SH outputs and
  custom locking bytecode may need higher; OP_RETURN outputs are exempt. None of this can move an NFT
  capability, so it is not modelled.
- **nftCommitment contents** beyond the single-byte function identifier (loan/pool/price/redemption
  *state* is treated opaquely; it is split and reconstructed without constraint).
- **Locktime / sequence (timelock) semantics, signatures, and arithmetic results** (treated opaque).

Dropping all of the above is sound *for a leak-freedom proof*: fewer constraints describe a
**superset** of real transactions, so `UNSAT` on the model implies `UNSAT` on chain. They are genuinely
separate concerns, covered by separate tools:

- functional correctness + per-`require` coverage (incl. the value/arithmetic logic): `paryon_testing_suite`;
- the proof's base case + "the live chain runs these artifacts": `verify_contract_deployment`;
- value-conservation and commitment-integrity as their own properties: not yet built (see README next steps).

## BCH/CashTokens engine vs ParyonUSD-specific

The engine is reusable for any CashScript/CashTokens system; only the registry, policy, and
transaction templates are ParyonUSD-specific.

**Engine (general, no ParyonUSD knowledge):**

| file | role |
|---|---|
| `src/z3.ts` | Z3 context + helpers |
| `src/model.ts` | symbolic UTXO/tx model; capability + category encoding; enum-domain bounds |
| `src/consensus.ts` | CashTokens token-validation tally + structural rules (the trusted base) |
| `src/policy.ts` | the leak-property *mechanism* (`leakWitness`, inductive hypothesis), parameterised by a `LeakPolicy` |
| `src/covenant.ts` | `Covenant` interface + `compose` (small, used by an illustrative test) |
| `src/script/*` | Bitcoin Script symbolic interpreter, CashTokens introspection, artifact loading + stack seeding |

**ParyonUSD-specific (the instantiation):**

| file | role |
|---|---|
| `src/covenants/ids.ts` | the category/script id registry: which contracts exist (arbitrary identity ints) |
| `src/covenants/common.ts` | the leak *policy values* + ownership map, the function-NFT id enums, and input-shape helpers |
| `tests/*.test.ts` | per-transaction templates (input shapes), composing the derived covenants |
| `tests/partners.ts` | the recreation/sidecar partner `CovenantSpec`s |

The category set the tally ranges over is passed in via `ArtifactConfig.categories`
(ParyonUSD uses `LOAN_CATEGORIES` from `ids.ts`/`common.ts`), so the engine itself imports nothing
from `src/covenants`. Identities are modelled as small ints because the property only needs equality;
the real 32-byte tokenIds and ~35-byte P2SH32 scripts are checked on chain by `verify_contract_deployment`.
