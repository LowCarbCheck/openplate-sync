/**
 * In-memory `InviteStore` for the admin-API tests.
 *
 * It mints REAL tokens through `generateSignupInviteToken` and stores only
 * their digests, exactly as the Drizzle store does — because the property the
 * admin tests care about is what the ROUTES put in a response, and a fake that
 * returned a predictable token would let a leak of the digest pass unnoticed.
 *
 * It also reproduces the two RULES the real transaction enforces: an address
 * that already has an account cannot be invited, and a new invite for an
 * address supersedes the pending one. Neither needs a transaction to be
 * observable from a route test.
 */
import type {
  InviteStore,
  InviteSummary,
  MintInviteInput,
  MintInviteResult,
  MintedInvite,
  ReissueInviteInput,
} from '../../src/admin/invite-store.js';
import { generateSignupInviteToken } from '../../src/lib/tokens.js';

interface FakeInviteRow extends InviteSummary {
  tokenHash: string;
}

export interface FakeInviteStore extends InviteStore {
  /** Test-only: the digest of a minted invite, so a test can assert it never appears in a body. */
  digestOf(inviteId: number): string | undefined;
  /** Test-only: marks an invite spent, to exercise the "revoke keeps redeemed rows" rule. */
  markRedeemed(inviteId: number, accountId: number): void;
  /** Test-only: makes the next mint for this address answer `email-taken`, without an account store. */
  claimEmail(email: string): void;
  /** Test-only: every row, including revoked ones, so a supersede is observable. */
  rows(): InviteSummary[];
}

/**
 * Copied WITHOUT `tokenHash`, mirroring the real store's column-naming
 * projection rather than handing the row out whole.
 */
function summarize(row: FakeInviteRow): InviteSummary {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    role: row.role,
    dailyAiLimit: row.dailyAiLimit,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    redeemedAt: row.redeemedAt,
    revokedAt: row.revokedAt,
    redeemedAccountId: row.redeemedAccountId,
  };
}

export function createFakeInviteStore(): FakeInviteStore {
  const rows: FakeInviteRow[] = [];
  const claimedEmails = new Set<string>();
  let nextId = 1;

  return {
    async mint(input: MintInviteInput): Promise<MintInviteResult> {
      if (claimedEmails.has(input.email)) return { ok: false, reason: 'email-taken' };

      // Supersede the pending invite for this address, as the real store does.
      for (const row of rows) {
        if (row.email === input.email && row.redeemedAt === null && row.revokedAt === null) {
          row.revokedAt = input.now;
        }
      }

      const token = generateSignupInviteToken();
      const row: FakeInviteRow = {
        id: nextId++,
        email: input.email,
        displayName: input.displayName,
        role: input.role,
        dailyAiLimit: input.dailyAiLimit,
        createdAt: new Date('2026-08-31T12:00:00.000Z'),
        expiresAt: input.expiresAt,
        redeemedAt: null,
        revokedAt: null,
        redeemedAccountId: null,
        tokenHash: token.hash,
      };
      rows.push(row);
      return { ok: true, minted: { invite: summarize(row), token: token.raw } };
    },

    async reissue(input: ReissueInviteInput): Promise<MintedInvite | null> {
      const row = rows.find(
        (candidate) => candidate.id === input.inviteId && candidate.redeemedAt === null && candidate.revokedAt === null,
      );
      if (!row) return null;
      // A NEW digest on the SAME row, which is what kills the old link.
      const token = generateSignupInviteToken();
      row.tokenHash = token.hash;
      row.expiresAt = input.expiresAt;
      return { invite: summarize(row), token: token.raw };
    },

    async list(input: { limit: number; offset: number }): Promise<{ invites: InviteSummary[]; total: number }> {
      const page = rows.slice(input.offset, input.offset + input.limit);
      return { invites: page.map(summarize), total: rows.length };
    },

    async revoke(input: { inviteId: number; revokedAt: Date }): Promise<boolean> {
      const row = rows.find(
        (candidate) => candidate.id === input.inviteId && candidate.redeemedAt === null && candidate.revokedAt === null,
      );
      if (!row) return false;
      row.revokedAt = input.revokedAt;
      return true;
    },

    digestOf(inviteId: number): string | undefined {
      return rows.find((row) => row.id === inviteId)?.tokenHash;
    },

    markRedeemed(inviteId: number, accountId: number): void {
      const row = rows.find((candidate) => candidate.id === inviteId);
      if (!row) throw new Error(`no such fake invite: ${inviteId}`);
      row.redeemedAt = new Date('2026-08-31T13:00:00.000Z');
      row.redeemedAccountId = accountId;
    },

    claimEmail(email: string): void {
      claimedEmails.add(email);
    },

    rows(): InviteSummary[] {
      return rows.map(summarize);
    },
  };
}
