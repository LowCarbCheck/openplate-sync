/**
 * Drizzle implementation of `AdminMetadataStore` — the only module that reads
 * account rows on an operator's behalf.
 *
 * EVERY SELECT HERE NAMES ITS COLUMNS, AND THAT IS THE POINT. Not one query
 * below is a `select()` over a whole table. `accounts` carries the verifier
 * and the KDF descriptor, `sync_blobs` carries the ciphertext, and
 * `sync_key_records` carries the wrapped DEK — so a bare `select()` would put
 * all three in a row object one careless spread away from a response body.
 * Naming the columns means the forbidden material is never read out of
 * Postgres at all, which is a stronger property than filtering it afterwards:
 * a value that was never fetched cannot be leaked by a later edit to a mapper.
 * (`db/account-store.ts` DOES select whole rows, correctly — the auth handlers
 * genuinely need the verifier to check a login. The admin surface never does.)
 *
 * THE BLOB IS DESCRIBED FROM `size_bytes`, NEVER FROM THE BYTES. That column
 * exists precisely so storage can be reported without reading a 2 MiB
 * ciphertext (see `db/schema.ts`), and here it also means the admin path has
 * no code that has ever held a blob in memory.
 *
 * The per-account fan-out (blob summary, key-record kinds) is two extra
 * queries for a whole page rather than N+1: the page's ids go into one
 * `IN (...)` each. A page is at most `MAX_ADMIN_PAGE_LIMIT` rows, and this
 * endpoint is called by one operator at human speed.
 */
import { count, countDistinct, desc, eq, inArray, isNotNull, sum } from 'drizzle-orm';
import type {
  AdminAccountPage,
  AdminAccountSummary,
  AdminBlobSummary,
  AdminMetadataStore,
  AdminStats,
  ListAccountsInput,
} from '../admin/admin-store.js';
import type { SyncKeyRecordKind } from '../protocol.js';
import type { Database } from './client.js';
import { accounts, syncBlobs, syncKeyRecords } from './schema.js';

/** The identity columns — deliberately enumerated, never `select()`. See the module header. */
interface AccountIdentityRow {
  id: number;
  email: string;
  createdAt: Date;
  emailVerifiedAt: Date | null;
}

/** `sum()` comes back as a numeric string (or `null` on an empty table), because a Postgres `bigint` does not fit a JS number by contract. */
function toByteCount(value: string | null): number {
  return value === null ? 0 : Number(value);
}

export function createDrizzleAdminStore(db: Database): AdminMetadataStore {
  /** The newest blob version per account, for the given ids. */
  async function blobSummaries(accountIds: number[]): Promise<Map<number, AdminBlobSummary>> {
    const summaries = new Map<number, AdminBlobSummary>();
    if (accountIds.length === 0) return summaries;

    const rows = await db
      .select({
        accountId: syncBlobs.accountId,
        blobVersion: syncBlobs.blobVersion,
        sizeBytes: syncBlobs.sizeBytes,
        createdAt: syncBlobs.createdAt,
      })
      .from(syncBlobs)
      .where(inArray(syncBlobs.accountId, accountIds))
      .orderBy(desc(syncBlobs.blobVersion));

    // Ordered newest-first, so the FIRST row seen for an account is its
    // current version and every later one is a retained older version.
    for (const row of rows) {
      if (summaries.has(row.accountId)) continue;
      summaries.set(row.accountId, { sizeBytes: row.sizeBytes, updatedAt: row.createdAt });
    }
    return summaries;
  }

  /** Which key-record kinds exist per account, for the given ids. The wrapped DEK column is never named. */
  async function keyRecordKinds(accountIds: number[]): Promise<Map<number, SyncKeyRecordKind[]>> {
    const kinds = new Map<number, SyncKeyRecordKind[]>();
    if (accountIds.length === 0) return kinds;

    const rows = await db
      .select({ accountId: syncKeyRecords.accountId, kind: syncKeyRecords.kind })
      .from(syncKeyRecords)
      .where(inArray(syncKeyRecords.accountId, accountIds));

    for (const row of rows) {
      const existing = kinds.get(row.accountId) ?? [];
      existing.push(row.kind);
      kinds.set(row.accountId, existing);
    }
    return kinds;
  }

  async function summarize(identities: AccountIdentityRow[]): Promise<AdminAccountSummary[]> {
    const ids = identities.map((identity) => identity.id);
    const blobs = await blobSummaries(ids);
    const kinds = await keyRecordKinds(ids);

    return identities.map((identity) => ({
      id: identity.id,
      email: identity.email,
      createdAt: identity.createdAt,
      emailVerifiedAt: identity.emailVerifiedAt,
      blob: blobs.get(identity.id) ?? null,
      keyRecordKinds: (kinds.get(identity.id) ?? []).toSorted(),
    }));
  }

  return {
    async listAccounts(input: ListAccountsInput): Promise<AdminAccountPage> {
      const identities = await db
        .select({
          id: accounts.id,
          email: accounts.email,
          createdAt: accounts.createdAt,
          emailVerifiedAt: accounts.emailVerifiedAt,
        })
        .from(accounts)
        // A stable order, or two pages of the same list can show the same
        // account twice and miss another.
        .orderBy(accounts.id)
        .limit(input.limit)
        .offset(input.offset);

      const [totals] = await db.select({ total: count() }).from(accounts);

      return { accounts: await summarize(identities), total: totals?.total ?? 0 };
    },

    async getAccount(accountId: number): Promise<AdminAccountSummary | null> {
      const [identity] = await db
        .select({
          id: accounts.id,
          email: accounts.email,
          createdAt: accounts.createdAt,
          emailVerifiedAt: accounts.emailVerifiedAt,
        })
        .from(accounts)
        .where(eq(accounts.id, accountId))
        .limit(1);
      if (!identity) return null;

      const [summary] = await summarize([identity]);
      return summary ?? null;
    },

    async stats(): Promise<AdminStats> {
      const [accountTotals] = await db.select({ total: count() }).from(accounts);

      const [verifiedTotals] = await db
        .select({ verified: count() })
        .from(accounts)
        .where(isNotNull(accounts.emailVerifiedAt));

      const [blobTotals] = await db
        .select({
          versions: count(),
          owners: countDistinct(syncBlobs.accountId),
          bytes: sum(syncBlobs.sizeBytes),
        })
        .from(syncBlobs);

      const [keyRecordTotals] = await db.select({ total: count() }).from(syncKeyRecords);

      return {
        accounts: accountTotals?.total ?? 0,
        verifiedAccounts: verifiedTotals?.verified ?? 0,
        accountsWithBlob: blobTotals?.owners ?? 0,
        blobVersions: blobTotals?.versions ?? 0,
        keyRecords: keyRecordTotals?.total ?? 0,
        blobBytes: toByteCount(blobTotals?.bytes ?? null),
      };
    },
  };
}
