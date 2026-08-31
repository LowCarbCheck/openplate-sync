/**
 * The operator's write contract for signup invites — a THIRD interface beside
 * `AccountStore` and `AdminMetadataStore`, for the same reason those two are
 * separate from each other.
 *
 * Minting an invite is an operator action. Nothing a user's own request can do
 * should be able to reach it, and putting these methods on `AccountStore`
 * would leave them one autocomplete away from every auth handler that already
 * holds a store. Redemption is the only user-facing invite operation, and it
 * deliberately lives on `AccountStore` instead — as
 * `redeemInviteAndCreateAccount`, because it has to share a transaction with
 * account creation.
 *
 * WHAT MAY LEAVE THIS INTERFACE. `mint` returns the raw token, exactly once,
 * and it is the only method that ever does. Every read returns
 * `InviteSummary`, which has no `tokenHash` field and no method that could be
 * extended to produce one — a projection, not a habit of remembering not to
 * select a column. See ADR-0001, which states the rule this narrows: a raw
 * invite is an operator-born capability, not a user secret, and it may appear
 * in the response that creates it and nowhere else.
 */

/** One invite as an operator sees it. The digest is absent by construction, and the raw token never existed here. */
export interface InviteSummary {
  id: number;
  /** The operator's own label for who this was for. Never matched against anything. */
  note: string | null;
  createdAt: Date;
  expiresAt: Date;
  /** `null` while the invite is still spendable. */
  redeemedAt: Date | null;
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
  note: string | null;
  expiresAt: Date;
}

export interface InviteStore {
  mint(input: MintInviteInput): Promise<MintedInvite>;
  list(input: { limit: number; offset: number }): Promise<{ invites: InviteSummary[]; total: number }>;
  /** Deletes an UNREDEEMED invite. Returns `false` when there was no such spendable invite — a redeemed one is kept for audit. */
  revoke(inviteId: number): Promise<boolean>;
}
