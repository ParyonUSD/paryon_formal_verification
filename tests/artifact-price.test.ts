import { paryonArtifacts } from '@paryonusd/contracts';
import { beforeAll, describe, it } from 'vitest';
import { Capability, NO_CATEGORY } from '../src/model.js';
import { CAT, LOAN_CATEGORIES, POLICY, SCRIPT, pin } from '../src/covenants/common.js';
import { buildFromArtifact } from '../src/script/fromArtifact.js';
import { seedOpaque } from '../src/script/interpreter.js';
import { getContext, type Z3 } from '../src/z3.js';
import { expectArtifactSafe } from './assertions.js';

let z3: Z3;
beforeAll(async () => {
  z3 = await getContext();
});

/**
 * The price contract on its own. `sharePrice` (abi 1) is covered as a partner in every template that
 * reads the price; `updatePrice` (abi 0) is the oracle update: the paryon-mutable price NFT with only a
 * fee input, recreated at output 0, with an optional uncapped change output. `migrateContract` (abi 2)
 * is deliberately not verified: it lets the holder of the oracle migration key move the price authority
 * to new contract code, a documented trust assumption of the system, not a property to prove.
 */
describe('price contract — derived from artifact bytecode', () => {
  it('updatePrice (oracle update with fee input + change)', async () => {
    await expectArtifactSafe(z3, buildFromArtifact(z3, [
      // constructor: oraclePublicKey, tokenIdMigrationKey (neither feeds a capability comparison here)
      { artifact: paryonArtifacts.artifactPriceContract, activeIndex: 0, abiIndex: 0, seeds: [seedOpaque, seedOpaque] },
    ], {
      nInputs: 2, nOutputs: 4, categories: LOAN_CATEGORIES, policy: POLICY.updatePrice, designatedInputs: [0],
      setup: (_z3, s, tx) => {
        pin(s, tx.inputs[0]!, { category: CAT.PARYON, capability: Capability.MUTABLE, script: SCRIPT.PRICE });
        pin(s, tx.inputs[1]!, { category: NO_CATEGORY }); // fee BCH
      },
    }));
  });
});
