/**
 * Drizzle-backed `SyncStorageAdapter` — the only module that reads or writes
 * `sync_blobs` / `sync_key_records`.
 *
 * PORTED VERBATIM IN SUBSTANCE from the openplate app's
 * `app/models/sync-storage.server.ts` (M128 spec 02). The concurrency
 * discipline below is security-reviewed and was carried across unchanged; the
 * only differences are the injected `Database` (instead of a module-level
 * singleton) and the account foreign key now pointing at this service's own
 * `accounts` table.
 *
 * CAS concurrency is enforced by a UNIQUE constraint, not by row locking.
 * Every blob write computes `newVersion = currentVersion + 1` and attempts an
 * INSERT of that exact `(accountId, newVersion)` pair. Two concurrent uploads
 * racing the same `baseVersion` can both pass the initial read, but only ONE
 * insert can possibly succeed — the loser hits a Postgres unique violation
 * (23505, caught by `lib/storage-conflict.ts`) and is translated into the
 * same `{ ok: false, currentVersion }` a plain version mismatch would return.
 * This stays correct under READ COMMITTED (Postgres's default) and is simpler
 * than `SELECT ... FOR UPDATE`, with an identical caller-facing contract.
 *
 * The same discipline extends to key records: `expectedUpdatedAt` plays the
 * role `baseVersion` plays for blobs, gated by
 * `sync_key_records_account_kind_idx` — first-time create is an INSERT whose
 * unique violation means conflict; a rotation is an UPDATE gated on an exact
 * `updatedAt` match, where zero rows matched means conflict. A key-record
 * write is never a blind upsert.
 */
import { and, desc, eq, inArray } from 'drizzle-orm';
import type {
  PutBlobResult,
  PutKeyRecordResult,
  SyncBlobRecord,
  SyncKeyRecord,
  SyncStorageAdapter,
} from '../contract-types.js';
import type { SyncKeyRecordKind } from '../protocol.js';
import { BLOB_VERSION_RETENTION } from '../protocol.js';
import { isUniqueViolation } from '../lib/storage-conflict.js';
import type { Database } from './client.js';
import { syncBlobs, syncKeyRecords } from './schema.js';

type SyncKeyRecordRow = typeof syncKeyRecords.$inferSelect;

function mapKeyRecordRow(row: SyncKeyRecordRow): SyncKeyRecord {
  return {
    accountId: row.accountId,
    kind: row.kind,
    kdfDescriptor: row.kdfDescriptor ?? null,
    wrappedDek: row.wrappedDek,
    updatedAt: row.updatedAt,
  };
}

export function createDrizzleStorageAdapter(db: Database): SyncStorageAdapter {
  async function readCurrentBlobVersion(accountId: number): Promise<number> {
    const [row] = await db
      .select({ blobVersion: syncBlobs.blobVersion })
      .from(syncBlobs)
      .where(eq(syncBlobs.accountId, accountId))
      .orderBy(desc(syncBlobs.blobVersion))
      .limit(1);
    return row?.blobVersion ?? 0;
  }

  /** Deletes every blob version for `accountId` past the retention cap, oldest first. */
  async function pruneOldBlobVersions(accountId: number): Promise<void> {
    const rows = await db
      .select({ id: syncBlobs.id })
      .from(syncBlobs)
      .where(eq(syncBlobs.accountId, accountId))
      .orderBy(desc(syncBlobs.blobVersion));
    const staleIds = rows.slice(BLOB_VERSION_RETENTION).map((row) => row.id);
    if (staleIds.length === 0) return;
    await db.delete(syncBlobs).where(inArray(syncBlobs.id, staleIds));
  }

  /** The current `updatedAt` for `(accountId, kind)`, or `null` when no record exists — reported back to a losing CAS write. */
  async function readCurrentKeyRecordUpdatedAt(accountId: number, kind: SyncKeyRecordKind): Promise<Date | null> {
    const [row] = await db
      .select({ updatedAt: syncKeyRecords.updatedAt })
      .from(syncKeyRecords)
      .where(and(eq(syncKeyRecords.accountId, accountId), eq(syncKeyRecords.kind, kind)));
    return row?.updatedAt ?? null;
  }

  return {
    async getBlob(accountId: number): Promise<SyncBlobRecord | null> {
      const [row] = await db
        .select()
        .from(syncBlobs)
        .where(eq(syncBlobs.accountId, accountId))
        .orderBy(desc(syncBlobs.blobVersion))
        .limit(1);
      if (!row) return null;
      return {
        accountId: row.accountId,
        blobVersion: row.blobVersion,
        envelopeVersion: row.envelopeVersion,
        ciphertext: row.ciphertext,
        createdAt: row.createdAt,
      };
    },

    async putBlobIfVersionMatches(input): Promise<PutBlobResult> {
      const currentVersion = await readCurrentBlobVersion(input.accountId);
      if (currentVersion !== input.baseVersion) {
        return { ok: false, currentVersion };
      }

      const newVersion = currentVersion + 1;
      try {
        await db.insert(syncBlobs).values({
          accountId: input.accountId,
          blobVersion: newVersion,
          envelopeVersion: input.envelopeVersion,
          ciphertext: Buffer.from(input.ciphertext),
          sizeBytes: input.ciphertext.byteLength,
        });
      } catch (error) {
        if (!isUniqueViolation(error)) throw error;
        // Lost the race to a concurrent upload — re-read and report the REAL
        // current version, same contract as a plain version mismatch.
        return { ok: false, currentVersion: await readCurrentBlobVersion(input.accountId) };
      }

      await pruneOldBlobVersions(input.accountId);
      return { ok: true, newVersion };
    },

    async listKeyRecords(accountId: number): Promise<SyncKeyRecord[]> {
      const rows = await db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId));
      return rows.map(mapKeyRecordRow);
    },

    async putKeyRecord(input): Promise<PutKeyRecordResult> {
      if (input.expectedUpdatedAt === null) {
        try {
          const [row] = await db
            .insert(syncKeyRecords)
            .values({
              accountId: input.accountId,
              kind: input.kind,
              kdfDescriptor: input.kdfDescriptor ?? null,
              wrappedDek: Buffer.from(input.wrappedDek),
            })
            .returning();
          if (!row) throw new Error('Failed to insert sync key record');
          return { ok: true, record: mapKeyRecordRow(row) };
        } catch (error) {
          if (!isUniqueViolation(error)) throw error;
          return { ok: false, currentUpdatedAt: await readCurrentKeyRecordUpdatedAt(input.accountId, input.kind) };
        }
      }

      const [row] = await db
        .update(syncKeyRecords)
        .set({
          kdfDescriptor: input.kdfDescriptor ?? null,
          wrappedDek: Buffer.from(input.wrappedDek),
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(syncKeyRecords.accountId, input.accountId),
            eq(syncKeyRecords.kind, input.kind),
            eq(syncKeyRecords.updatedAt, input.expectedUpdatedAt),
          ),
        )
        .returning();
      if (!row) {
        return { ok: false, currentUpdatedAt: await readCurrentKeyRecordUpdatedAt(input.accountId, input.kind) };
      }
      return { ok: true, record: mapKeyRecordRow(row) };
    },

    async deleteKeyRecord(input): Promise<void> {
      await db
        .delete(syncKeyRecords)
        .where(and(eq(syncKeyRecords.accountId, input.accountId), eq(syncKeyRecords.kind, input.kind)));
    },
  };
}
