/**
 * In-memory `AdminMetadataStore` for the admin-API unit tests.
 *
 * It is seeded with REAL-LOOKING material, and that is deliberate: the
 * forbidden-field test asserts that no verifier, KDF descriptor, wrapped DEK
 * or ciphertext appears in any admin response, and an assertion like that is
 * vacuous if the fixture never held such a value in the first place. So each
 * seeded account carries its secrets on the fixture (`AdminSeedSecrets`) where
 * a test can assert their ABSENCE by exact string — while the store itself,
 * mirroring the real one, has no way to return them.
 */
import type {
  AdminAccountPage,
  AdminAccountSummary,
  AdminMetadataStore,
  AdminStats,
  ListAccountsInput,
} from '../../src/admin/admin-store.js';
import type { SyncKeyRecordKind } from '../../src/protocol.js';

/**
 * The material an account really has in the database and which the admin API
 * must never emit. Held beside the store, never inside a summary.
 */
export interface AdminSeedSecrets {
  verifier: string;
  kdfDescriptorSalt: string;
  wrappedDek: string;
  ciphertext: string;
  tokenHash: string;
}

export interface AdminSeedInput {
  id: number;
  handle: string;
  blobSizeBytes?: number;
  keyRecordKinds?: SyncKeyRecordKind[];
}

export interface FakeAdminStore extends AdminMetadataStore {
  seed(input: AdminSeedInput): AdminSeedSecrets;
  /** Test-only: forget everything, so one process-wide server can serve many cases. */
  clear(): void;
}

export function createFakeAdminStore(): FakeAdminStore {
  const summaries = new Map<number, AdminAccountSummary>();
  const secrets = new Map<number, AdminSeedSecrets>();

  return {
    seed(input: AdminSeedInput): AdminSeedSecrets {
      const kinds = input.keyRecordKinds ?? [];
      summaries.set(input.id, {
        id: input.id,
        handle: input.handle,
        createdAt: new Date('2026-08-01T09:00:00.000Z'),
        blob:
          input.blobSizeBytes === undefined
            ? null
            : { sizeBytes: input.blobSizeBytes, updatedAt: new Date('2026-08-03T09:00:00.000Z') },
        keyRecordKinds: kinds,
      });

      const seeded: AdminSeedSecrets = {
        verifier: `verifier-${input.id}-8f2c1b9ae4d07c35a1f6`,
        kdfDescriptorSalt: `kdfsalt-${input.id}-Yk9sTn2QpR4vXw==`,
        wrappedDek: `wrappeddek-${input.id}-3aa71bd05fe6`,
        ciphertext: `ciphertext-${input.id}-0f9d8c7b6a5e4d3c`,
        tokenHash: `tokenhash-${input.id}-c1d2e3f4a5b6`,
      };
      secrets.set(input.id, seeded);
      return seeded;
    },

    clear(): void {
      summaries.clear();
      secrets.clear();
    },

    async listAccounts(input: ListAccountsInput): Promise<AdminAccountPage> {
      const ordered = [...summaries.values()].toSorted((left, right) => left.id - right.id);
      return { accounts: ordered.slice(input.offset, input.offset + input.limit), total: ordered.length };
    },

    async getAccount(accountId: number): Promise<AdminAccountSummary | null> {
      return summaries.get(accountId) ?? null;
    },

    async stats(): Promise<AdminStats> {
      const all = [...summaries.values()];
      const withBlob = all.filter((account) => account.blob !== null);
      return {
        accounts: all.length,
        accountsWithBlob: withBlob.length,
        blobVersions: withBlob.length,
        keyRecords: all.reduce((total, account) => total + account.keyRecordKinds.length, 0),
        blobBytes: withBlob.reduce((total, account) => total + (account.blob?.sizeBytes ?? 0), 0),
      };
    },
  };
}
