/**
 * In-memory fake `SyncStorageAdapter` for the server-handler tests. It
 * implements the same CAS semantics a real backend must (see PROTOCOL.md
 * §10), so the handler tests exercise realistic behaviour — including the
 * conflict paths — without a database.
 */
import type {
  PutBlobResult,
  PutKeyRecordResult,
  SyncBlobRecord,
  SyncKeyRecord,
  SyncStorageAdapter,
} from '../../src/contract-types.js';
import type { SyncKeyRecordKind } from '../../src/protocol.js';

export function createFakeStorageAdapter(): SyncStorageAdapter {
  const blobsByAccount = new Map<number, SyncBlobRecord>();
  const keyRecordsByAccount = new Map<number, Map<SyncKeyRecordKind, SyncKeyRecord>>();

  return {
    async getBlob(accountId: number): Promise<SyncBlobRecord | null> {
      return blobsByAccount.get(accountId) ?? null;
    },

    async putBlobIfVersionMatches(input): Promise<PutBlobResult> {
      const current = blobsByAccount.get(input.accountId);
      const currentVersion = current?.blobVersion ?? 0;
      if (currentVersion !== input.baseVersion) {
        return { ok: false, currentVersion };
      }
      const newVersion = currentVersion + 1;
      blobsByAccount.set(input.accountId, {
        accountId: input.accountId,
        blobVersion: newVersion,
        envelopeVersion: input.envelopeVersion,
        ciphertext: input.ciphertext,
        createdAt: new Date(),
      });
      return { ok: true, newVersion };
    },

    async listKeyRecords(accountId: number): Promise<SyncKeyRecord[]> {
      return [...(keyRecordsByAccount.get(accountId)?.values() ?? [])];
    },

    async putKeyRecord(input): Promise<PutKeyRecordResult> {
      const accountRecords = keyRecordsByAccount.get(input.accountId) ?? new Map<SyncKeyRecordKind, SyncKeyRecord>();
      const existing = accountRecords.get(input.kind) ?? null;
      const existingUpdatedAt = existing?.updatedAt ?? null;

      const matches =
        input.expectedUpdatedAt === null
          ? existingUpdatedAt === null
          : existingUpdatedAt !== null && existingUpdatedAt.getTime() === input.expectedUpdatedAt.getTime();
      if (!matches) {
        return { ok: false, currentUpdatedAt: existingUpdatedAt };
      }

      const full: SyncKeyRecord = {
        accountId: input.accountId,
        kind: input.kind,
        kdfDescriptor: input.kdfDescriptor,
        wrappedDek: input.wrappedDek,
        updatedAt: new Date(),
      };
      accountRecords.set(input.kind, full);
      keyRecordsByAccount.set(input.accountId, accountRecords);
      return { ok: true, record: full };
    },

    async deleteKeyRecord(input): Promise<void> {
      keyRecordsByAccount.get(input.accountId)?.delete(input.kind);
    },
  };
}
