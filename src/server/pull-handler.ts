/**
 * Pull-blob handler core (design spec D4) — read-only. Separated from the
 * Express glue so it's unit-testable against a fake `SyncStorageAdapter`.
 */
import type { SyncBlobRecord, SyncStorageAdapter } from '../contract-types.js';

export type PullBlobResult = { status: 'found'; blob: SyncBlobRecord } | { status: 'not-found' };

export async function handlePullBlob(accountId: number, storage: SyncStorageAdapter): Promise<PullBlobResult> {
  const blob = await storage.getBlob(accountId);
  return blob ? { status: 'found', blob } : { status: 'not-found' };
}
