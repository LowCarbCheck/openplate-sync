/**
 * Opaque-token primitives: minting, hashing, expiry and lifecycle
 * classification. PURE and DB-free by design (the only impurity is
 * `randomBytes`), so every rule below is unit-testable without a database —
 * the DB-touching orchestration lives in `server/auth-handlers.ts` over an
 * injected `AccountStore`.
 *
 * SECURITY MODEL — the reason these are opaque strings and not JWTs:
 *
 *  - A JWT is *stateless*, which is exactly the property this service must
 *    not have. Revocation is the load-bearing feature here: PROTOCOL.md
 *    requires that a passphrase change invalidates every outstanding session
 *    immediately. A stateless token can only be made to
 *    expire, never to stop working, without adding the same server-side
 *    denylist that a database-backed opaque token already is.
 *  - Only the SHA-256 digest of a token is persisted. A dumped
 *    `account_tokens` table therefore yields nothing replayable. SHA-256 with
 *    no stretching is correct here (unlike for passwords): the pre-image is
 *    256 bits of `randomBytes`, so there is no dictionary to run.
 *
 * ACCESS/REFRESH SPLIT (counsel decision, M128 spec 02): the client in a
 * zero-knowledge design must never cache the master passphrase, so it cannot
 * silently re-derive an auth-hash to log in again. A long-lived rotating
 * refresh token is what makes silent re-auth possible at all; the short-lived
 * access token is what limits the damage of one leaking.
 */
import { createHash, randomBytes } from 'node:crypto';

/**
 * Every kind of opaque token this service issues.
 *
 * SESSION TOKENS ARE NOW THE ONLY KIND. Until M181 this union also carried
 * two single-use LINK kinds, minted to be put in a message: one confirmed an
 * address, the other redeemed a mailed recovery link. Both went with the
 * mailer. A service that holds no address cannot send a link, and the mailed
 * link was an account-takeover path that bought no recovery — it restored a
 * LOGIN to data that stays sealed, because the server never held a key that
 * unwraps a DEK. `account_tokens` therefore holds sessions and nothing else.
 */
export type AccountTokenKind = 'access' | 'refresh';

/**
 * The kinds that constitute a logged-in session — exactly what a credential
 * change revokes. Every kind, since the link tokens went; kept as a named
 * list because the revocation rule is about SESSIONS, not about "all rows",
 * and a future non-session kind must not silently join it.
 */
export const SESSION_TOKEN_KINDS: readonly AccountTokenKind[] = ['access', 'refresh'];

/** Short — a leaked access token is useful for minutes, not weeks. */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;
/** Long, but rotating: every use mints a replacement and revokes the presented one (see `server/auth-handlers.ts`). */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export const TOKEN_TTL_MS = {
  access: ACCESS_TOKEN_TTL_MS,
  refresh: REFRESH_TOKEN_TTL_MS,
} satisfies Record<AccountTokenKind, number>;

/** A freshly minted token: `raw` goes to the client, `hash` goes in the DB. Never store `raw`. */
export interface GeneratedToken {
  raw: string;
  hash: string;
}

/** SHA-256 hex digest of a raw token — deterministic, which is the whole point of storing digests. */
export function hashToken(raw: string): string {
  return createHash('sha256').update(raw).digest('hex');
}

/** Mints a 256-bit random token and its digest. Session tokens carry no prefix. */
export function generateToken(): GeneratedToken {
  const raw = randomBytes(32).toString('base64url');
  return { raw, hash: hashToken(raw) };
}

/**
 * How long a mailed password-reset token is worth anything. One hour: long
 * enough to survive a person reading their mail on the train, short enough
 * that a letter forgotten in an inbox is not a live capability tomorrow.
 *
 * Deliberately not in {@link TOKEN_TTL_MS}, which is keyed by
 * {@link AccountTokenKind} — a reset token is not an `account_tokens` row and
 * never becomes a session (`password_resets`).
 */
export const RESET_TOKEN_TTL_MS = 60 * 60 * 1000;

/**
 * The shape a SIGNUP INVITE carries, and nothing else does. Kept beside
 * `generateToken` because the contrast is the point: session tokens stay bare.
 */
export const SIGNUP_INVITE_TOKEN_PREFIX = 'si_';

/** The shape a mailed PASSWORD RESET carries. Distinct from `si_` for the reason below. */
export const PASSWORD_RESET_TOKEN_PREFIX = 'sr_';

/**
 * Mints a signup invite: the same 256 bits, wearing its service's prefix.
 *
 * A signup invite is the one token of this service that is handed to a HUMAN,
 * pasted into a chat, and put in a join link beside a token belonging to a
 * DIFFERENT service (the gateway's `gi_`). The prefix makes the two
 * distinguishable before either is posted anywhere: the client refuses to send
 * the wrong one, and this server refuses to look one up.
 *
 * Session tokens deliberately keep their bare shape. They are never seen by a
 * person, never travel beside another service's token, and prefixing them would
 * only mark a credential in a log as worth stealing.
 */
export function generateSignupInviteToken(): GeneratedToken {
  const raw = `${SIGNUP_INVITE_TOKEN_PREFIX}${randomBytes(32).toString('base64url')}`;
  return { raw, hash: hashToken(raw) };
}

/**
 * Mints a password reset: the same 256 bits, wearing its own prefix.
 *
 * A SECOND HUMAN-FACING TOKEN, and the second prefix is what keeps the two
 * apart. Both arrive in a mail, both open a link in the client, and they mean
 * very different things — one creates an account, one hands over a recovery
 * code. A person forwarding the wrong letter, or a client reading the wrong
 * fragment, is refused by shape rather than by a lookup that would have to
 * decide what a cross-purpose token means.
 */
export function generatePasswordResetToken(): GeneratedToken {
  const raw = `${PASSWORD_RESET_TOKEN_PREFIX}${randomBytes(32).toString('base64url')}`;
  return { raw, hash: hashToken(raw) };
}

/**
 * Whether a presented string could be a signup invite at all.
 *
 * A SHAPE GATE, not a check: it is run BEFORE any lookup and its rejection is
 * the same generic `invite-invalid` a wrong, spent or expired token gets, so it
 * adds no oracle. What it buys is that a token of another kind posted here is
 * refused without ever being hashed against this service's invite rows.
 */
export function isSignupInviteToken(raw: string): boolean {
  return raw.startsWith(SIGNUP_INVITE_TOKEN_PREFIX);
}

/**
 * A refresh-token FAMILY id, carried unchanged across rotations. It is what
 * lets `logout` revoke exactly one device's pair, and what lets a replayed
 * (already-rotated) refresh token revoke that whole lineage rather than just
 * itself — the standard reuse-detection response to a stolen token.
 */
export function generateFamilyId(): string {
  return randomBytes(16).toString('hex');
}

export function computeExpiry(now: Date, ttlMs: number): Date {
  return new Date(now.getTime() + ttlMs);
}

/** The persisted shape a lifecycle decision needs — a structural subset of an `account_tokens` row. */
export interface TokenLifecycle {
  expiresAt: Date;
  revokedAt: Date | null;
}

export type TokenStatus = 'valid' | 'revoked' | 'expired';

/**
 * Classifies a token against `now`. `revoked` wins over `expired` because
 * the two mean very different things to the caller: an expired refresh token
 * is a routine re-login, while a revoked one that is still within its TTL is
 * the reuse signal that triggers family revocation.
 */
export function classifyToken(token: TokenLifecycle, now: Date): TokenStatus {
  if (token.revokedAt !== null) return 'revoked';
  if (token.expiresAt.getTime() <= now.getTime()) return 'expired';
  return 'valid';
}

export function isTokenUsable(token: TokenLifecycle, now: Date): boolean {
  return classifyToken(token, now) === 'valid';
}

/**
 * Extracts the token from an `Authorization: Bearer <token>` header value.
 * Returns `null` for anything that is not exactly that shape — a missing
 * header, a different scheme, or a bearer with no value.
 */
export function parseBearerHeader(headerValue: string | undefined): string | null {
  if (headerValue === undefined) return null;
  const match = /^Bearer[ ]+(\S+)$/i.exec(headerValue.trim());
  return match ? (match[1] ?? null) : null;
}
