/**
 * The operator's write contract for signup invites — a THIRD interface beside
 * `AccountStore` and `AdminMetadataStore`, for the same reason those two are
 * separate from each other.
 *
 * Minting an invite is an operator action. Nothing a user's own request can do
 * should be able to reach it, and putting these methods on `AccountStore`
 * would leave them one autocomplete away from every auth handler that already
 * holds a store. The two user-facing invite operations live there instead:
 * `redeemInviteAndCreateAccount`, because it has to share a transaction with
 * account creation, and `findInviteAddressing`, because `POST
 * /v1/auth/invite-lookup` is unauthenticated and must never be able to reach a
 * minting method.
 *
 * WHAT MAY LEAVE THIS INTERFACE. `mint` returns the raw token, exactly once,
 * and it is the only method that ever does. Every read returns
 * `InviteSummary`, which has no `tokenHash` field and no method that could be
 * extended to produce one — a projection, not a habit of remembering not to
 * select a column. See ADR-0001, which states the rule this narrows: a raw
 * invite is an operator-born capability, not a user secret, and it may appear
 * in the response that creates it and nowhere else.
 */
import type { AccountRole } from '../protocol.js';

/**
 * Where an invite stands, derived rather than stored.
 *
 * FOUR STATES OUT OF THREE COLUMNS (`redeemed_at`, `revoked_at`,
 * `expires_at`), computed in one place so a list and a detail view can never
 * disagree. `redeemed` wins over `revoked` and both win over `expired`: an
 * invite that was spent and then outlived its expiry is spent, and saying
 * "expired" would hide where an account came from.
 */
export type InviteStatus = 'pending' | 'redeemed' | 'revoked' | 'expired';

/** One invite as an operator sees it. The digest is absent by construction, and the raw token never existed here. */
export interface InviteSummary {
  id: number;
  /** The address the invitation is for. It becomes the account's identity at redemption. */
  email: string;
  displayName: string | null;
  /** The role the redeemed account will get. */
  role: AccountRole;
  /** The daily AI allowance the redeemed account will get. */
  dailyAiLimit: number;
  createdAt: Date;
  expiresAt: Date;
  /** `null` while the invite is still spendable. */
  redeemedAt: Date | null;
  /** Non-`null` once an operator withdrew it, or a newer invite for the same address superseded it. */
  revokedAt: Date | null;
  /** The account the invite produced, or `null` — including when that account was later deleted (the FK is `ON DELETE SET NULL`). */
  redeemedAccountId: number | null;
}

/** The one response in this service that carries a freshly minted secret. */
export interface MintedInvite {
  invite: InviteSummary;
  /**
   * The raw token, returned ONCE and never persisted — only its SHA-256 digest
   * is stored. If the operator loses this, the invite is unusable and the
   * remedy is to mint another; there is no path that recovers it.
   */
  token: string;
}

export interface MintInviteInput {
  /** Already canonicalised by `accounts/auth-input.ts`'s `parseEmail` before it reaches the store. */
  email: string;
  displayName: string | null;
  role: AccountRole;
  dailyAiLimit: number;
  expiresAt: Date;
  /** Stamped on the pending invite this mint supersedes, if there is one. Injected, like every instant in this repo. */
  now: Date;
}

export interface ReissueInviteInput {
  inviteId: number;
  /** The new expiry, computed by the caller from its own clock. */
  expiresAt: Date;
}

/** `email-taken` is the ONLY expected failure: an address that already has an account cannot be invited again. */
export type MintInviteResult = { ok: true; minted: MintedInvite } | { ok: false; reason: 'email-taken' };

export interface InviteStore {
  /**
   * Mints one addressed invite, revoking any older PENDING invite for the same
   * address in the same transaction.
   *
   * SUPERSEDING RATHER THAN REFUSING. An operator who re-invites somebody has
   * almost always lost the first letter or watched it not arrive; answering
   * `409` would make them hunt for a row to delete first. Two live invites for
   * one address would be two capabilities where the operator believes there is
   * one, so the older is withdrawn rather than left alongside.
   */
  mint(input: MintInviteInput): Promise<MintInviteResult>;
  /**
   * Mints a NEW token for an existing pending invite, replacing its digest and
   * extending its expiry. `null` when there is no such pending invite.
   *
   * THE SAME ROW, NOT A NEW ONE, and that is the difference from minting again.
   * An operator resending is saying "the first letter did not arrive", not
   * "invite this person twice": a second row would leave the first live until
   * something revoked it, and the list would show two invitations where the
   * operator believes there is one. Replacing the digest also kills the old
   * link, which is the honest meaning of "resend".
   */
  reissue(input: ReissueInviteInput): Promise<MintedInvite | null>;
  list(input: { limit: number; offset: number }): Promise<{ invites: InviteSummary[]; total: number }>;
  /**
   * Revokes an UNREDEEMED invite. Returns `false` when there was no such
   * spendable invite — a redeemed one is kept for audit and has no capability
   * left to withdraw.
   *
   * A STAMP, NOT A DELETE, since M192: an operator looking at the list needs to
   * see that a letter went out and was withdrawn, which a missing row does not
   * say.
   */
  revoke(input: { inviteId: number; revokedAt: Date }): Promise<boolean>;
}

/** Derives an invite's status from its three lifecycle columns. The ONE place that decides. */
export function inviteStatus(invite: InviteSummary, now: Date): InviteStatus {
  if (invite.redeemedAt !== null) return 'redeemed';
  if (invite.revokedAt !== null) return 'revoked';
  if (invite.expiresAt.getTime() <= now.getTime()) return 'expired';
  return 'pending';
}
