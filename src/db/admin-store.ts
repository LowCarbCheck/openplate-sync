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
 * `recovery_code_escrow` JOINS THAT LIST OF COLUMNS NEVER NAMED HERE (M192).
 * It is the one field on `accounts` that a server-side key can turn back into
 * a credential, and an operator's legitimate need for it is served by the
 * mailed reset — which delivers it to the ACCOUNT HOLDER — rather than by an
 * endpoint that would print it into a console.
 *
 * The per-account fan-out (blob summary, key-record kinds) is two extra
 * queries for a whole page rather than N+1: the page's ids go into one
 * `IN (...)` each. A page is at most `MAX_ADMIN_PAGE_LIMIT` rows, and this
 * endpoint is called by one operator at human speed.
 */
import { and, count, countDistinct, desc, eq, gt, inArray, isNull, sum } from 'drizzle-orm';
import type {
  AdminAccountPage,
  AdminAccountSummary,
  AdminBlobSummary,
  AdminMetadataStore,
  AdminStats,
  ListAccountsInput,
} from '../admin/admin-store.js';
import type { AccountRole, SyncKeyRecordKind } from '../protocol.js';
import type { Database } from './client.js';
import { utcDayKey } from '../lib/utc-day.js';
import { accounts, aiUsageDays, signupInvites, syncBlobs, syncKeyRecords } from './schema.js';

/** The identity columns — deliberately enumerated, never `select()`. See the module header. */
interface AccountIdentityRow {
  id: number;
  email: string;
  displayName: string | null;
  role: AccountRole;
  dailyAiLimit: number;
  suspendedAt: Date | null;
  createdAt: Date;
}

/**
 * The columns an operator may see. Named once so the list and the detail read
 * cannot drift, and so the forbidden ones — `verifier`, `recovery_verifier`,
 * `kdf_descriptor`, `recovery_code_escrow` — are absent in one visible place
 * rather than in two.
 */
const IDENTITY_COLUMNS = {
  id: accounts.id,
  email: accounts.email,
  displayName: accounts.displayName,
  role: accounts.role,
  dailyAiLimit: accounts.dailyAiLimit,
  suspendedAt: accounts.suspendedAt,
  createdAt: accounts.createdAt,
} as const;

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

  /** Today's AI spend per account, for the given ids. A count, never a log — see `db/schema.ts`. */
  async function aiUsage(accountIds: number[], day: string): Promise<Map<number, number>> {
    const usage = new Map<number, number>();
    if (accountIds.length === 0) return usage;

    const rows = await db
      .select({ accountId: aiUsageDays.accountId, count: aiUsageDays.count })
      .from(aiUsageDays)
      .where(and(inArray(aiUsageDays.accountId, accountIds), eq(aiUsageDays.day, day)));

    for (const row of rows) usage.set(row.accountId, row.count);
    return usage;
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

  async function summarize(identities: AccountIdentityRow[], day: string): Promise<AdminAccountSummary[]> {
    const ids = identities.map((identity) => identity.id);
    const blobs = await blobSummaries(ids);
    const kinds = await keyRecordKinds(ids);
    const usage = await aiUsage(ids, day);

    return identities.map((identity) => ({
      id: identity.id,
      email: identity.email,
      displayName: identity.displayName,
      role: identity.role,
      dailyAiLimit: identity.dailyAiLimit,
      aiUsedToday: usage.get(identity.id) ?? 0,
      suspendedAt: identity.suspendedAt,
      createdAt: identity.createdAt,
      blob: blobs.get(identity.id) ?? null,
      keyRecordKinds: (kinds.get(identity.id) ?? []).toSorted(),
    }));
  }

  return {
    async listAccounts(input: ListAccountsInput): Promise<AdminAccountPage> {
      const identities = await db
        .select(IDENTITY_COLUMNS)
        .from(accounts)
        // A stable order, or two pages of the same list can show the same
        // account twice and miss another.
        .orderBy(accounts.id)
        .limit(input.limit)
        .offset(input.offset);

      const [totals] = await db.select({ total: count() }).from(accounts);

      return { accounts: await summarize(identities, input.day), total: totals?.total ?? 0 };
    },

    async getAccount(input: { accountId: number; day: string }): Promise<AdminAccountSummary | null> {
      const [identity] = await db
        .select(IDENTITY_COLUMNS)
        .from(accounts)
        .where(eq(accounts.id, input.accountId))
        .limit(1);
      if (!identity) return null;

      const [summary] = await summarize([identity], input.day);
      return summary ?? null;
    },

    async stats(input: { now: Date }): Promise<AdminStats> {
      const [accountTotals] = await db.select({ total: count() }).from(accounts);
      const [adminTotals] = await db.select({ total: count() }).from(accounts).where(eq(accounts.role, 'admin'));

      // PENDING means a letter is outstanding: not redeemed, not revoked, not
      // expired. The three columns together, because any one of them alone
      // would count invitations nobody can use.
      const [inviteTotals] = await db
        .select({ total: count() })
        .from(signupInvites)
        .where(
          and(
            isNull(signupInvites.redeemedAt),
            isNull(signupInvites.revokedAt),
            gt(signupInvites.expiresAt, input.now),
          ),
        );

      const [aiTotals] = await db
        .select({ total: sum(aiUsageDays.count) })
        .from(aiUsageDays)
        .where(eq(aiUsageDays.day, utcDayKey(input.now)));

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
        accountsWithBlob: blobTotals?.owners ?? 0,
        blobVersions: blobTotals?.versions ?? 0,
        keyRecords: keyRecordTotals?.total ?? 0,
        blobBytes: toByteCount(blobTotals?.bytes ?? null),
        pendingInvites: inviteTotals?.total ?? 0,
        admins: adminTotals?.total ?? 0,
        // `sum()` comes back as a numeric string for the same reason
        // `blobBytes` does: a Postgres `bigint` does not fit a JS number by
        // contract, even when this one always will.
        aiRequestsToday: toByteCount(aiTotals?.total ?? null),
      };
    },
  };
}
