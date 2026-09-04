/**
 * The AI spend control: a per-account, per-UTC-day counter that is RESERVED
 * before the upstream call and released only when the provider cannot have
 * billed us.
 *
 * WHY RESERVE-BEFORE RATHER THAN COUNT-AFTER. Counting after the fact has a
 * window in which N parallel requests all read the old count and all go
 * through: the check and the increment are two statements, and a client that
 * retries on error is precisely the client that will fire them together. The
 * reservation is ONE statement whose `WHERE` is the limit, so the database
 * decides, once, per request.
 *
 * ```sql
 * INSERT INTO ai_usage_days (account_id, day, count) VALUES ($1, $2, 1)
 * ON CONFLICT (account_id, day) DO UPDATE SET count = ai_usage_days.count + 1
 * WHERE ai_usage_days.count < $3
 * RETURNING count
 * ```
 *
 * Zero rows back means the limit was already reached. The `WHERE` on the
 * `DO UPDATE` is the whole guarantee: two concurrent requests at `count = limit
 * - 1` serialise on the row lock, and exactly one of them sees a count below
 * the limit.
 *
 * THE INSERT BRANCH IS NOT GUARDED, and it does not need to be: it only fires
 * when no row exists for the day, which means a count of zero, and a caller
 * with `limit = 0` is refused by the route before it ever reaches here
 * (`403 ai-not-allowed`). A limit of zero reaching this method would insert a
 * row with `count = 1`, which is why the route's guard is load-bearing rather
 * than cosmetic.
 *
 * THE RELEASE IS FLOORED AT ZERO. `WHERE count > 0` stops a double release (a
 * retry, a future bug) from driving the counter negative, which would hand out
 * free requests rather than merely miscounting.
 */
import { and, eq, gt, sql } from 'drizzle-orm';
import type { Database } from '../db/client.js';
import { aiUsageDays } from '../db/schema.js';

/**
 * The outcome of a reservation.
 *
 * `used` is the count AFTER a successful reserve, so it is what
 * `X-Quota-Used` reports; on a refusal it is the limit, because that is what
 * the caller has spent.
 */
export type ReserveResult = { ok: true; used: number; limit: number } | { ok: false; used: number; limit: number };

export interface AiQuotaStore {
  /**
   * Takes one unit of the account's allowance for the given UTC day, atomically.
   *
   * Callers MUST have refused a `limit` of 0 before reaching here — see the
   * module header on why the insert branch is unguarded.
   */
  reserve(input: { accountId: number; day: string; limit: number }): Promise<ReserveResult>;
  /** Gives one unit back. Floored at zero, and never throws out of the proxy's hands (see its `releaseQuietly`). */
  release(input: { accountId: number; day: string }): Promise<void>;
  /** How many requests every account together spent on the given day. An operator statistic, never a limit. */
  countRequestsOn(day: string): Promise<number>;
}

export function createDrizzleAiQuotaStore(db: Database): AiQuotaStore {
  return {
    async reserve(input: { accountId: number; day: string; limit: number }): Promise<ReserveResult> {
      const rows = await db
        .insert(aiUsageDays)
        .values({ accountId: input.accountId, day: input.day, count: 1 })
        .onConflictDoUpdate({
          target: [aiUsageDays.accountId, aiUsageDays.day],
          set: { count: sql`${aiUsageDays.count} + 1` },
          // THE LIMIT IS THE PREDICATE, which is what makes this one statement
          // rather than a read and a write with a race between them.
          where: sql`${aiUsageDays.count} < ${input.limit}`,
        })
        .returning({ count: aiUsageDays.count });

      const row = rows[0];
      // Zero rows means the `WHERE` was false: the account is at its limit, so
      // it has spent exactly `limit`.
      if (!row) return { ok: false, used: input.limit, limit: input.limit };
      return { ok: true, used: row.count, limit: input.limit };
    },

    async release(input: { accountId: number; day: string }): Promise<void> {
      await db
        .update(aiUsageDays)
        .set({ count: sql`${aiUsageDays.count} - 1` })
        // Floored at zero: a double release must miscount upward, never
        // downward, because a negative counter is free requests.
        .where(and(eq(aiUsageDays.accountId, input.accountId), eq(aiUsageDays.day, input.day), gt(aiUsageDays.count, 0)));
    },

    async countRequestsOn(day: string): Promise<number> {
      const rows = await db
        .select({ total: sql<number>`coalesce(sum(${aiUsageDays.count}), 0)::int` })
        .from(aiUsageDays)
        .where(eq(aiUsageDays.day, day));
      return rows[0]?.total ?? 0;
    },
  };
}
