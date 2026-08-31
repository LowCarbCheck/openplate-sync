/**
 * In-memory `InviteStore` for the admin-API tests.
 *
 * It mints REAL tokens through `generateToken` and stores only their digests,
 * exactly as the Drizzle store does — because the property the admin tests
 * care about is what the ROUTES put in a response, and a fake that returned a
 * predictable token would let a leak of the digest pass unnoticed.
 */
import type { InviteStore, InviteSummary, MintInviteInput, MintedInvite } from '../../src/admin/invite-store.js';
import { generateToken } from '../../src/lib/tokens.js';

interface FakeInviteRow extends InviteSummary {
  tokenHash: string;
}

export interface FakeInviteStore extends InviteStore {
  /** Test-only: the digest of a minted invite, so a test can assert it never appears in a body. */
  digestOf(inviteId: number): string | undefined;
  /** Test-only: marks an invite spent, to exercise the "revoke keeps redeemed rows" rule. */
  markRedeemed(inviteId: number, accountId: number): void;
}

export function createFakeInviteStore(): FakeInviteStore {
  const rows: FakeInviteRow[] = [];
  let nextId = 1;

  return {
    async mint(input: MintInviteInput): Promise<MintedInvite> {
      const token = generateToken();
      const row: FakeInviteRow = {
        id: nextId++,
        note: input.note,
        createdAt: new Date('2026-08-31T12:00:00.000Z'),
        expiresAt: input.expiresAt,
        redeemedAt: null,
        redeemedAccountId: null,
        tokenHash: token.hash,
      };
      rows.push(row);
      return { invite: { ...row }, token: token.raw };
    },

    async list(input: { limit: number; offset: number }): Promise<{ invites: InviteSummary[]; total: number }> {
      const page = rows.slice(input.offset, input.offset + input.limit);
      // Spread-copied WITHOUT `tokenHash`, mirroring the real store's
      // column-naming projection rather than handing the row out whole.
      return {
        invites: page.map((row) => ({
          id: row.id,
          note: row.note,
          createdAt: row.createdAt,
          expiresAt: row.expiresAt,
          redeemedAt: row.redeemedAt,
          redeemedAccountId: row.redeemedAccountId,
        })),
        total: rows.length,
      };
    },

    async revoke(inviteId: number): Promise<boolean> {
      const index = rows.findIndex((row) => row.id === inviteId && row.redeemedAt === null);
      if (index === -1) return false;
      rows.splice(index, 1);
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
  };
}
