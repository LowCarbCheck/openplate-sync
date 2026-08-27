/**
 * Drizzle-backed `SyncShareStore` — the only module that reads or writes
 * `sync_shares` (ADR-0002).
 *
 * It is a SEPARATE store from `db/storage-adapter.ts` rather than four more
 * methods on it. The owner-only blob and key-record routes must not be able
 * to reach the share graph even by accident, and an instance booted without
 * `SYNC_SHARING` never constructs this factory at all.
 *
 * CAS DISCIPLINE, TRANSPLANTED VERBATIM from the key-record path
 * (PROTOCOL.md §5.4): `expectedUpdatedAt: null` is a first-time INSERT whose
 * unique violation on `sync_shares_pair_idx` means "somebody else got there
 * first"; any other value is an UPDATE gated on an exact `updatedAt` match,
 * where zero rows returned means conflict. A share write is never a blind
 * upsert — a re-wrap after a DEK rotation can race a re-grant, and silently
 * overwriting one with the other would leave a clinician holding a wrap for a
 * DEK that no longer opens the blob.
 *
 * The FOREIGN-KEY VIOLATION path is reported, not thrown: a grant naming an
 * account that does not exist is a client mistake, and letting it become a
 * 500 would both log noise and answer differently from every other failure on
 * this route.
 */
import { and, eq } from 'drizzle-orm';
import type { PutShareResult, SyncShare, SyncShareStore, SyncShareSummary } from '../contract-types.js';
import { isUniqueViolation, sqlstate } from '../lib/storage-conflict.js';
import type { Database } from './client.js';
import { syncShares } from './schema.js';

/** Postgres SQLSTATE for a foreign-key violation — here, a grantee account that does not exist. */
const POSTGRES_FOREIGN_KEY_VIOLATION_CODE = '23503';

type SyncShareRow = typeof syncShares.$inferSelect;

function mapShareRow(row: SyncShareRow): SyncShare {
  return {
    accountId: row.accountId,
    granteeAccountId: row.granteeAccountId,
    wrappedDek: row.wrappedDek,
    recipientKeyFingerprint: row.recipientKeyFingerprint,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function createDrizzleShareStore(db: Database): SyncShareStore {
  /** The current CAS token for one pair, or `null` when no row exists — reported back to a losing write. */
  async function readCurrentUpdatedAt(accountId: number, granteeAccountId: number): Promise<Date | null> {
    const [row] = await db
      .select({ updatedAt: syncShares.updatedAt })
      .from(syncShares)
      .where(and(eq(syncShares.accountId, accountId), eq(syncShares.granteeAccountId, granteeAccountId)));
    return row?.updatedAt ?? null;
  }

  return {
    async putShare(input): Promise<PutShareResult | { ok: false; reason: 'no-such-account' }> {
      if (input.expectedUpdatedAt === null) {
        try {
          const [row] = await db
            .insert(syncShares)
            .values({
              accountId: input.accountId,
              granteeAccountId: input.granteeAccountId,
              wrappedDek: Buffer.from(input.wrappedDek),
              recipientKeyFingerprint: input.recipientKeyFingerprint,
              // MILLISECOND PRECISION, DELIBERATELY, and this is load-bearing
              // for the CAS rather than cosmetic. The token leaves here as an
              // ISO-8601 string, which carries milliseconds; Postgres's own
              // `now()` default carries MICROSECONDS, so a token round-tripped
              // through the wire would come back truncated and never match the
              // stored value again — every re-wrap would 409 forever. Writing
              // a JS `Date` makes the stored value exactly representable in
              // the format the client is given.
              createdAt: new Date(),
              updatedAt: new Date(),
            })
            .returning();
          if (!row) throw new Error('Failed to insert sync share');
          return { ok: true, share: mapShareRow(row) };
        } catch (error) {
          if (sqlstate(error) === POSTGRES_FOREIGN_KEY_VIOLATION_CODE) {
            return { ok: false, reason: 'no-such-account' };
          }
          if (!isUniqueViolation(error)) throw error;
          return {
            ok: false,
            currentUpdatedAt: await readCurrentUpdatedAt(input.accountId, input.granteeAccountId),
          };
        }
      }

      const [row] = await db
        .update(syncShares)
        .set({
          wrappedDek: Buffer.from(input.wrappedDek),
          recipientKeyFingerprint: input.recipientKeyFingerprint,
          updatedAt: new Date(),
        })
        .where(
          and(
            eq(syncShares.accountId, input.accountId),
            eq(syncShares.granteeAccountId, input.granteeAccountId),
            eq(syncShares.updatedAt, input.expectedUpdatedAt),
          ),
        )
        .returning();
      if (!row) {
        return { ok: false, currentUpdatedAt: await readCurrentUpdatedAt(input.accountId, input.granteeAccountId) };
      }
      return { ok: true, share: mapShareRow(row) };
    },

    async listSharesByGrantor(accountId: number): Promise<SyncShareSummary[]> {
      // `wrappedDek` is deliberately absent from this projection: the grantor
      // has no use for a wrap addressed to somebody else's key, so it is never
      // read out of the database on this path at all.
      return db
        .select({
          accountId: syncShares.accountId,
          granteeAccountId: syncShares.granteeAccountId,
          recipientKeyFingerprint: syncShares.recipientKeyFingerprint,
          createdAt: syncShares.createdAt,
          updatedAt: syncShares.updatedAt,
        })
        .from(syncShares)
        .where(eq(syncShares.accountId, accountId));
    },

    async listSharesByGrantee(granteeAccountId: number): Promise<SyncShare[]> {
      const rows = await db.select().from(syncShares).where(eq(syncShares.granteeAccountId, granteeAccountId));
      return rows.map(mapShareRow);
    },

    async getShare(input): Promise<SyncShare | null> {
      const [row] = await db
        .select()
        .from(syncShares)
        .where(and(eq(syncShares.accountId, input.accountId), eq(syncShares.granteeAccountId, input.granteeAccountId)));
      return row ? mapShareRow(row) : null;
    },

    async deleteShare(input): Promise<void> {
      await db
        .delete(syncShares)
        .where(and(eq(syncShares.accountId, input.accountId), eq(syncShares.granteeAccountId, input.granteeAccountId)));
    },
  };
}
