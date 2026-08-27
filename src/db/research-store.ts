/**
 * Drizzle-backed `SyncResearchStore` — the only module that reads or writes
 * `research_contributions` and `research_withdrawals` (ADR-0003).
 *
 * A SEPARATE STORE, for the reason `db/share-store.ts` is one: the owner-only
 * blob/key-record path must not be able to reach the study graph even by
 * accident, and an instance booted without `SYNC_RESEARCH` never constructs
 * this factory at all. It is also kept apart from the SHARE store, because a
 * share and a contribution are different artifacts and ADR-0003 opens by
 * forbidding the shortcut that would merge them.
 *
 * THE CAS IS AN INTEGER, NOT A TIMESTAMP, and that is a deliberate difference
 * from `share-store.ts`. `contributionVersion` rides in the envelope's AAD
 * (PROTOCOL.md §3.5), so the researcher can already tell which version she
 * decrypted; the attack the check has to refuse is therefore a ROLLBACK — an
 * older contribution replacing a newer one — and a monotonic integer refuses
 * exactly that. A strictly-greater rule rather than an exact-successor one:
 * the client recomputes the whole window and re-pushes it whole, so a version
 * it skipped (a push that never left the device) must not wedge the lane
 * forever.
 *
 * WITHDRAWAL IS ONE TRANSACTION AND EVERY REFUSAL THROWS. `rotation-store.ts`
 * records why in full: a `return` from a transaction callback COMMITS what has
 * already been written, so a refusal expressed as a return value would leave
 * precisely the half-applied state the transaction exists to prevent. Here
 * that half-state is the worst one this lane has — a contribution deleted with
 * no tombstone behind it, which is an erasure the study is never told to
 * honour.
 */
import { and, eq, lt } from 'drizzle-orm';
import type {
  PutContributionResult,
  ResearchContribution,
  ResearchContributionSummary,
  ResearchWithdrawal,
  SyncResearchStore,
} from '../contract-types.js';
import { sqlstate } from '../lib/storage-conflict.js';
import type { Database } from './client.js';
import { researchContributions, researchWithdrawals } from './schema.js';

type ResearchContributionRow = typeof researchContributions.$inferSelect;

/** The contributor-facing projection of a row. `body` is dropped here as well as in the SELECTs that avoid reading it. */
function mapSummaryRow(row: ResearchContributionRow): ResearchContributionSummary {
  return {
    studyAccountId: row.studyAccountId,
    pseudonym: row.pseudonym,
    schemaTier: row.schemaTier,
    contributionVersion: row.contributionVersion,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

/** Postgres SQLSTATE for a foreign-key violation — here, a study account that does not exist. */
const POSTGRES_FOREIGN_KEY_VIOLATION_CODE = '23503';

/** No row yet. The first contribution therefore only has to be `>= 1`, which every positive integer is. */
const NO_CONTRIBUTION_VERSION = 0;

/**
 * How a withdrawal refuses: thrown INSIDE the transaction so Postgres rolls
 * the delete back, never returned. See the module header.
 */
class WithdrawalRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WithdrawalRefused';
  }
}

export function createDrizzleResearchStore(db: Database): SyncResearchStore {
  /** The stored version for one pair, or `0` when there is no row — reported back to a losing write. */
  async function readCurrentVersion(input: { contributorAccountId: number; studyAccountId: number }): Promise<number> {
    const [row] = await db
      .select({ contributionVersion: researchContributions.contributionVersion })
      .from(researchContributions)
      .where(
        and(
          eq(researchContributions.contributorAccountId, input.contributorAccountId),
          eq(researchContributions.studyAccountId, input.studyAccountId),
        ),
      );
    return row?.contributionVersion ?? NO_CONTRIBUTION_VERSION;
  }

  return {
    async putContribution(input): Promise<PutContributionResult | { ok: false; reason: 'no-such-account' }> {
      try {
        // ONE statement carries the whole compare-and-swap: the insert lands
        // when no row exists, and the `setWhere` decides the update. Doing it
        // as read-then-write would be a lost-update race between two of the
        // contributor's own devices, and the loser would silently roll the
        // cohort back to an older window.
        const [row] = await db
          .insert(researchContributions)
          .values({
            contributorAccountId: input.contributorAccountId,
            studyAccountId: input.studyAccountId,
            pseudonym: input.pseudonym,
            schemaTier: input.schemaTier,
            body: Buffer.from(input.body),
            contributionVersion: input.contributionVersion,
            // Millisecond `Date`s, matching the declared `timestamp(3)`
            // columns rather than relying on them. `rotation-store.ts` does
            // the same: the declaration stops the database holding a tail the
            // wire cannot carry, and writing the value here means the two
            // agree rather than merely coexist.
            createdAt: new Date(),
            updatedAt: new Date(),
          })
          .onConflictDoUpdate({
            target: [researchContributions.contributorAccountId, researchContributions.studyAccountId],
            set: {
              pseudonym: input.pseudonym,
              schemaTier: input.schemaTier,
              body: Buffer.from(input.body),
              contributionVersion: input.contributionVersion,
              updatedAt: new Date(),
            },
            // THE CAS. Zero rows back means the submitted version was not
            // strictly greater than the stored one, and nothing was written.
            setWhere: lt(researchContributions.contributionVersion, input.contributionVersion),
          })
          .returning();

        if (!row) {
          return { ok: false, currentVersion: await readCurrentVersion(input) };
        }
        return { ok: true, contribution: mapSummaryRow(row) };
      } catch (error) {
        if (sqlstate(error) === POSTGRES_FOREIGN_KEY_VIOLATION_CODE) {
          // A contribution needs a real study account — the foreign key cannot
          // store one otherwise. Reported, not thrown: it is a client mistake.
          return { ok: false, reason: 'no-such-account' };
        }
        throw error;
      }
    },

    async listContributionsByContributor(contributorAccountId: number): Promise<ResearchContributionSummary[]> {
      // `body` is deliberately absent from this projection (PROTOCOL.md
      // §5.18): the contributor's own client still holds the source it was
      // reduced from, so megabytes of ciphertext never leave the database on
      // this path at all.
      return db
        .select({
          studyAccountId: researchContributions.studyAccountId,
          pseudonym: researchContributions.pseudonym,
          schemaTier: researchContributions.schemaTier,
          contributionVersion: researchContributions.contributionVersion,
          createdAt: researchContributions.createdAt,
          updatedAt: researchContributions.updatedAt,
        })
        .from(researchContributions)
        .where(eq(researchContributions.contributorAccountId, contributorAccountId));
    },

    async listContributionsByStudy(studyAccountId: number): Promise<ResearchContribution[]> {
      // THE PROJECTION IS THE PROHIBITION. `contributor_account_id` is not
      // selected, so there is no value in scope for a future response shape to
      // accidentally spread into. ADR-0003 prohibition 2 stops at the server,
      // and this is where it stops.
      const rows = await db
        .select({
          pseudonym: researchContributions.pseudonym,
          contributionVersion: researchContributions.contributionVersion,
          schemaTier: researchContributions.schemaTier,
          body: researchContributions.body,
          createdAt: researchContributions.createdAt,
        })
        .from(researchContributions)
        .where(eq(researchContributions.studyAccountId, studyAccountId));
      return rows.map((row) => ({
        pseudonym: row.pseudonym,
        contributionVersion: row.contributionVersion,
        schemaTier: row.schemaTier,
        body: row.body,
        createdAt: row.createdAt,
      }));
    },

    async withdrawContribution(input): Promise<void> {
      await db.transaction(async (tx) => {
        const [deleted] = await tx
          .delete(researchContributions)
          .where(
            and(
              eq(researchContributions.contributorAccountId, input.contributorAccountId),
              eq(researchContributions.studyAccountId, input.studyAccountId),
            ),
          )
          .returning({ pseudonym: researchContributions.pseudonym });

        // Idempotent: nothing enrolled means nothing to erase and nothing to
        // instruct. A tombstone here would be invented from an account id we
        // are forbidden to key one on anyway.
        if (!deleted) return;

        // Re-enrolling and withdrawing again yields the SAME pseudonym — the
        // derivation is deterministic per (root, study) — so a conflict is an
        // ordinary second withdrawal, not a race. Refresh the timestamp: the
        // instruction is "purge this pseudonym", and the study client wants
        // the latest time it was issued.
        const [tombstone] = await tx
          .insert(researchWithdrawals)
          .values({
            studyAccountId: input.studyAccountId,
            pseudonym: deleted.pseudonym,
            withdrawnAt: new Date(),
          })
          .onConflictDoUpdate({
            target: [researchWithdrawals.studyAccountId, researchWithdrawals.pseudonym],
            set: { withdrawnAt: new Date() },
          })
          .returning({ id: researchWithdrawals.id });

        // THROWN, NEVER RETURNED. A contribution deleted without a tombstone
        // is an erasure nobody is instructed to honour — ADR-0003 prohibition
        // 6's failure mode exactly. Returning here would commit the delete.
        if (!tombstone) throw new WithdrawalRefused('withdrawal wrote no tombstone');
      });
    },

    async listWithdrawalsByStudy(studyAccountId: number): Promise<ResearchWithdrawal[]> {
      return db
        .select({
          pseudonym: researchWithdrawals.pseudonym,
          withdrawnAt: researchWithdrawals.withdrawnAt,
        })
        .from(researchWithdrawals)
        .where(eq(researchWithdrawals.studyAccountId, studyAccountId));
    },
  };
}
