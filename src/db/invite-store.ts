/**
 * Drizzle implementation of `InviteStore` — minting, listing and revoking
 * addressed signup invites on the operator's behalf.
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
 * REVOKE IS A STAMP, NOT A DELETE, and only on unredeemed rows. A spent invite
 * is the audit record of an account's provenance; a withdrawn one is the
 * record that a letter went out and was taken back, which a missing row cannot
 * say.
 */
import { and, count, desc, eq, isNull } from 'drizzle-orm';
import type {
  InviteStore,
  InviteSummary,
  MintInviteInput,
  MintInviteResult,
  MintedInvite,
  ReissueInviteInput,
} from '../admin/invite-store.js';
import { generateSignupInviteToken } from '../lib/tokens.js';
import type { Database } from './client.js';
import { accounts, signupInvites } from './schema.js';

/** The columns an operator may see. `tokenHash` is deliberately absent from this list. */
const SUMMARY_COLUMNS = {
  id: signupInvites.id,
  email: signupInvites.email,
  displayName: signupInvites.displayName,
  role: signupInvites.role,
  dailyAiLimit: signupInvites.dailyAiLimit,
  createdAt: signupInvites.createdAt,
  expiresAt: signupInvites.expiresAt,
  redeemedAt: signupInvites.redeemedAt,
  revokedAt: signupInvites.revokedAt,
  redeemedAccountId: signupInvites.redeemedAccountId,
} as const;

export function createDrizzleInviteStore(db: Database): InviteStore {
  return {
    async mint(input: MintInviteInput): Promise<MintInviteResult> {
      // Same primitive the session tokens use: 256 bits of `randomBytes`,
      // stored only as a SHA-256 digest — plus the `si_` prefix that binds the
      // token to THIS service (see `lib/tokens.ts`).
      const token = generateSignupInviteToken();

      return await db.transaction(async (tx): Promise<MintInviteResult> => {
        // The address is checked INSIDE the transaction, so an account created
        // between the check and the insert cannot leave a live invite for an
        // address that already has one. There is no unique index that could
        // enforce this instead: the constraint spans two tables.
        const [existing] = await tx
          .select({ id: accounts.id })
          .from(accounts)
          .where(eq(accounts.email, input.email))
          .limit(1);
        if (existing) return { ok: false, reason: 'email-taken' };

        // Supersede first, insert second. The other order would need the new
        // row's id excluded from the update, and this way the window in which
        // two live invites exist is inside one transaction rather than on the
        // wire.
        await tx
          .update(signupInvites)
          .set({ revokedAt: input.now })
          .where(
            and(
              eq(signupInvites.email, input.email),
              isNull(signupInvites.redeemedAt),
              isNull(signupInvites.revokedAt),
            ),
          );

        const [row] = await tx
          .insert(signupInvites)
          .values({
            tokenHash: token.hash,
            email: input.email,
            displayName: input.displayName,
            role: input.role,
            dailyAiLimit: input.dailyAiLimit,
            expiresAt: input.expiresAt,
          })
          .returning(SUMMARY_COLUMNS);
        if (!row) throw new Error('Failed to insert invite');

        return { ok: true, minted: { invite: row, token: token.raw } };
      });
    },

    async reissue(input: ReissueInviteInput): Promise<MintedInvite | null> {
      const token = generateSignupInviteToken();
      // ONE conditional UPDATE, so a resend races a redemption safely: if the
      // invite was spent between the operator clicking and this statement, the
      // predicate is false, nothing is written, and the caller gets `null`
      // rather than a fresh token for an account that already exists.
      const [row] = await db
        .update(signupInvites)
        .set({ tokenHash: token.hash, expiresAt: input.expiresAt })
        .where(
          and(eq(signupInvites.id, input.inviteId), isNull(signupInvites.redeemedAt), isNull(signupInvites.revokedAt)),
        )
        .returning(SUMMARY_COLUMNS);
      if (!row) return null;
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

    async revoke(input: { inviteId: number; revokedAt: Date }): Promise<boolean> {
      const revoked = await db
        .update(signupInvites)
        .set({ revokedAt: input.revokedAt })
        // `isNull(revokedAt)` as well as `isNull(redeemedAt)`: re-revoking keeps
        // the instant the capability actually died, which is the one an
        // operator would look for.
        .where(
          and(eq(signupInvites.id, input.inviteId), isNull(signupInvites.redeemedAt), isNull(signupInvites.revokedAt)),
        )
        .returning({ id: signupInvites.id });
      return revoked.length > 0;
    },
  };
}
