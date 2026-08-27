/**
 * In-memory fake `SyncRotationStore` for the handler tests.
 *
 * It records what it was handed and answers whatever the test set, because
 * the property the unit tests can prove here is VALIDATION — that a refused
 * submission never reaches the store at all. Atomicity is not provable
 * against a fake: it is a property of one Postgres transaction, and it is
 * proven in `tests/integration/rotate-dek.test.ts` against a real database.
 */
import type { RotateDekInput, RotateDekResult, SyncRotationStore } from '../../src/contract-types.js';

export interface FakeRotationStore extends SyncRotationStore {
  /** Every submission that got past validation, in order. */
  readonly calls: RotateDekInput[];
  /** What the next call answers. Defaults to a successful rotation to version `baseVersion + 1`. */
  result: RotateDekResult | null;
}

export function createFakeRotationStore(): FakeRotationStore {
  const calls: RotateDekInput[] = [];

  return {
    calls,
    result: null,
    async rotateDek(input: RotateDekInput): Promise<RotateDekResult> {
      calls.push(input);
      return (
        this.result ?? {
          ok: true,
          newVersion: input.blob.baseVersion + 1,
          keptShares: input.shares.length,
          revokedShares: 0,
        }
      );
    },
  };
}
