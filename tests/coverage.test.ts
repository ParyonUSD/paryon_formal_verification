import { paryonArtifacts } from '@paryonusd/contracts';
import { describe, expect, it } from 'vitest';

/**
 * Function-level coverage ledger. Every function of every published artifact must be either verified by
 * a template (listed in COVERED with the file that does it) or excluded with a reason. A new artifact
 * function fails this test until it is classified; a stale entry fails it too. This exists because
 * `Borrowing.updatePeriodState` (a minting-NFT function with a real historical leak) went unverified
 * while its artifact looked "covered" by the `borrow` template.
 */
const COVERED: Record<string, Record<string, string>> = {
  Borrowing: { borrow: 'artifact-loankey', updatePeriodState: 'artifact-loankey' },
  PriceContract: { updatePrice: 'artifact-price', sharePrice: 'partners (every price-reading template)' },
  Loan: {},
  LoanTokenSidecar: { attach: 'partners (loan-recreating templates)' },
  LoanKeyFactory: { create: 'artifact-loankey' },
  changeInterest: { changeInterest: 'artifact-loan' },
  manageLoan: { manage: 'artifact-loan, historical-leak' },
  payInterest: { payInterest: 'artifact-loan' },
  liquidateLoan: { liquidate: 'artifact-pool' },
  redeemLoan: { redeemOrCancel: 'artifact-redemption' },
  startRedemption: { startRedemption: 'artifact-redemption' },
  swapInRedemption: { swapInRedemption: 'artifact-redemption' },
  swapOutRedemption: { swapOutRedemption: 'artifact-redemption' },
  Redeemer: { createRedemption: 'artifact-redemption' },
  Redemption: { finalizeRedemption: 'artifact-redemption', swapTargetLoan: 'artifact-redemption' },
  RedemptionSidecar: {},
  StabilityPool: { interact: 'partners (pool templates)' },
  StabilityPoolSidecar: { attach: 'partners (pool templates)' },
  Collector: { collect: 'artifact-loan (payInterest)', payToStabilityPool: 'artifact-pool (newPeriod)' },
  AddLiquidity: { addToPool: 'artifact-pool' },
  WithdrawFromPool: { withdraw: 'artifact-pool' },
  NewPeriodPool: { newPeriod: 'artifact-pool' },
  LiquidateLoan: { liquidate: 'artifact-pool' },
  Payout: { claimPayout: 'artifact-pool' },
  LoanKeyOriginEnforcer: {},
  LoanKeyOriginProof: {},
};

/** Functions that pin no output, or whose behaviour is a trust assumption rather than a proof obligation. */
const EXCLUDED: Record<string, Record<string, string>> = {
  Loan: { interact: 'delegation only: authenticates the sidecar and function NFT, pins no output' },
  RedemptionSidecar: { attach: 'auth/adjacency only, pins no output' },
  LoanKeyOriginEnforcer: { enforce: 'auth/adjacency only, pins no output' },
  LoanKeyOriginProof: { attach: 'auth/adjacency only, pins no output' },
  PriceContract: {
    migrateContract: 'the oracle migration key may move the price authority to new code by design: a documented trust assumption, not a property to prove',
  },
};

interface ArtifactLike { contractName: string; abi: readonly { name: string }[] }
function collect(node: unknown, out: ArtifactLike[] = []): ArtifactLike[] {
  if (!node || typeof node !== 'object') return out;
  const a = node as Partial<ArtifactLike> & { bytecode?: unknown };
  if (a.abi && typeof a.bytecode === 'string' && typeof a.contractName === 'string') out.push(a as ArtifactLike);
  else for (const child of Object.values(node)) collect(child, out);
  return out;
}

describe('every artifact function is verified or explicitly excluded', () => {
  const artifacts = collect(paryonArtifacts);
  const classified = new Set<string>();

  for (const artifact of artifacts) {
    for (const fn of artifact.abi) {
      const key = `${artifact.contractName}.${fn.name}`;
      classified.add(key);
      it(key, () => {
        const covered = COVERED[artifact.contractName]?.[fn.name];
        const excluded = EXCLUDED[artifact.contractName]?.[fn.name];
        expect(covered !== undefined || excluded !== undefined, `${key} is neither verified nor excluded`).toBe(true);
        expect(covered !== undefined && excluded !== undefined, `${key} is both verified and excluded`).toBe(false);
      });
    }
  }

  it('the ledger has no stale entries', () => {
    const stale = [COVERED, EXCLUDED].flatMap((ledger) =>
      Object.entries(ledger).flatMap(([contract, fns]) => Object.keys(fns).map((fn) => `${contract}.${fn}`)),
    ).filter((key) => !classified.has(key));
    expect(stale).toEqual([]);
    expect(artifacts.length).toBeGreaterThan(20);
  });
});
