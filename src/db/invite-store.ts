/**
 * Drizzle implementation of `InviteStore` — minting, listing and revoking
 * signup invites on the operator's behalf.
 *
 * EVERY SELECT HERE NAMES ITS COLUMNS, for the reason `db/admin-store.ts`
 * gives at length: `token_hash` is the one column on this table that must
 * never reach a response, and the strongest way to guarantee that is never to
 * fetch it. A digest that was never read out of Postgres cannot be leaked by a
 * later edit to a mapper.
 *
 * The raw token exists in exactly one place, for the duration of one HTTP
 * response: the return value of `mint`. It is generated here, hashed here, and
 * the hash is what the row keeps.
 *
 * REVOKE ONLY DELETES UNREDEEMED ROWS. A spent invite is the audit record of
 * an account's provenance; the capability it once represented is already gone,
 * so there is nothing left to revoke and something left to lose.
 */
import { and, count, desc, eq, isNull } from 'drizzle-orm';
import type { InviteStore, InviteSummary, MintInviteInput, MintedInvite } from '../admin/invite-store.js';
import { generateSignupInviteToken } from '../lib/tokens.js';
import type { Database } from './client.js';
import { signupInvites } from './schema.js';

/** The columns an operator may see. `tokenHash` is deliberately absent from this list. */
const SUMMARY_COLUMNS = {
  id: signupInvites.id,
  note: signupInvites.note,
  createdAt: signupInvites.createdAt,
  expiresAt: signupInvites.expiresAt,
  redeemedAt: signupInvites.redeemedAt,
  redeemedAccountId: signupInvites.redeemedAccountId,
} as const;

export function createDrizzleInviteStore(db: Database): InviteStore {
  return {
    async mint(input: MintInviteInput): Promise<MintedInvite> {
      // Same primitive the session tokens use: 256 bits of `randomBytes`,
      // stored only as a SHA-256 digest — plus the `si_` prefix that binds the
      // token to THIS service (see `lib/tokens.ts`).
      const token = generateSignupInviteToken();
      const [row] = await db
        .insert(signupInvites)
        .values({ tokenHash: token.hash, note: input.note, expiresAt: input.expiresAt })
        .returning(SUMMARY_COLUMNS);
      if (!row) throw new Error('Failed to insert invite');
      return { invite: row, token: token.raw };
    },

    async list(input: { limit: number; offset: number }): Promise<{ invites: InviteSummary[]; total: number }> {
      const invites = await db
        .select(SUMMARY_COLUMNS)
        .from(signupInvites)
        .orderBy(desc(signupInvites.createdAt))
        .limit(input.limit)
        .offset(input.offset);

      const [totals] = await db.select({ total: count() }).from(signupInvites);

      return { invites, total: totals?.total ?? 0 };
    },

    async revoke(inviteId: number): Promise<boolean> {
      const deleted = await db
        .delete(signupInvites)
        .where(and(eq(signupInvites.id, inviteId), isNull(signupInvites.redeemedAt)))
        .returning({ id: signupInvites.id });
      return deleted.length > 0;
    },
  };
}
