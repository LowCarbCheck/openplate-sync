/**
 * Account handler cores — the `/v1/auth/*` policy, written against injected
 * dependencies (`AuthContext`) rather than a database, a clock, or a mailer.
 *
 * Same discipline as the sync handler cores (`server/push-handler.ts` and
 * friends), for the same reason: everything interesting about authentication
 * is a decision, and decisions should be testable without standing up
 * Postgres. The Express glue lives in `register-auth-routes.ts`; the Drizzle
 * `AccountStore` in `db/account-store.ts`.
 *
 * Nothing here throws for an expected outcome. Every path returns a typed
 * `AuthOutcome`, which the glue maps 1:1 onto a status code.
 *
 * THE PROPERTY THAT MUST NOT BE BROKEN: nothing in this file ever sees, or
 * can derive, a value that decrypts a blob. The client's auth-hash is one
 * HKDF branch; the passphrase-KEK is another, with a different `info` label.
 * `wrappedDek` bytes pass through as opaque input to the store.
 */
import type { AccountRecord, AccountStore, KeyRecordSubmission, NewTokenInput } from './account-store.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';
import { deriveDummyKdfDescriptor } from '../lib/kdf-descriptor.js';
import { computeVerifier, verifierMatches } from '../lib/verifier.js';
import {
  classifyToken,
  computeExpiry,
  hashToken,
  TOKEN_TTL_MS,
  type AccountTokenKind,
  type GeneratedToken,
} from '../lib/tokens.js';
import { buildResetEmail, buildVerificationEmail } from '../mail/messages.js';
import type { MailMessage, MailResult } from '../mail/transport.js';
import type { Logger } from '../logger.js';
import {
  asFields,
  parseAuthHashField,
  parseDisplayName,
  parseEmail,
  parseKdfDescriptorField,
  parseKeyRecordSubmissions,
  parseTokenField,
} from './auth-input.js';
import type { JsonObject, JsonValue } from '../lib/json.js';

/** Everything the handlers need from the outside world. All of it injected — none of it imported. */
export interface AuthContext {
  store: AccountStore;
  /** `HMAC` key for verifiers, derived from `SERVER_SECRET` (`lib/server-secrets.ts`). */
  pepper: string;
  /** `HMAC` key behind deterministic dummy KDF descriptors. */
  enumerationSecret: string;
  signupsOpen: boolean;
  requireEmailVerification: boolean;
  clientBaseUrl: string;
  sendMail(message: MailMessage): Promise<MailResult>;
  now(): Date;
  mintToken(): GeneratedToken;
  mintFamilyId(): string;
  logger: Logger;
}

export interface SessionTokens {
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export interface AccountSummary {
  id: number;
  email: string;
  displayName: string | null;
  emailVerified: boolean;
}

export interface SessionResponse {
  account: AccountSummary;
  /** `null` when `REQUIRE_EMAIL_VERIFICATION` is on and the address is still unconfirmed — verify, then log in. */
  tokens: SessionTokens | null;
}

/**
 * Every outcome an auth handler can produce, in HTTP-shaped terms so the glue
 * needs no policy of its own. `reason` strings are diagnostic; clients branch
 * on the status.
 */
export type AuthOutcome<T> =
  | { status: 'ok'; body: T }
  | { status: 'created'; body: T }
  /** `202` — the request was taken, and whether anything happened is deliberately not disclosed. */
  | { status: 'accepted' }
  | { status: 'no-content' }
  | { status: 'invalid'; reason: string }
  | { status: 'unauthorized'; reason: string }
  | { status: 'forbidden'; reason: string }
  | { status: 'conflict'; reason: string };

/**
 * Compared against when no account exists, so an unknown email costs the same
 * constant-time comparison as a wrong auth-hash. 64 hex characters — the exact
 * width of a real verifier, because `verifierMatches` short-circuits on a
 * length mismatch.
 */
const ABSENT_ACCOUNT_VERIFIER = '0'.repeat(64);

/** A single generic message for every login failure — never "no such account" vs "wrong passphrase". */
const LOGIN_REJECTED = 'invalid email or passphrase';

function summarize(account: AccountRecord): AccountSummary {
  return {
    id: account.id,
    email: account.email,
    displayName: account.displayName,
    emailVerified: account.emailVerifiedAt !== null,
  };
}

function invalid<T>(reason: string): AuthOutcome<T> {
  return { status: 'invalid', reason };
}

interface MintedSession {
  tokens: SessionTokens;
  rows: NewTokenInput[];
}

/**
 * Mints one access/refresh pair sharing a family id. Returns both the raw
 * tokens (for the response) and the rows to persist (digests only) — the
 * caller decides whether they are inserted standalone or inside a rotation
 * transaction.
 */
function mintSession(ctx: AuthContext, input: { accountId: number; familyId: string }): MintedSession {
  const now = ctx.now();
  const access = ctx.mintToken();
  const refresh = ctx.mintToken();
  const accessExpiresAt = computeExpiry(now, TOKEN_TTL_MS.access);
  const refreshExpiresAt = computeExpiry(now, TOKEN_TTL_MS.refresh);

  return {
    tokens: {
      accessToken: access.raw,
      accessTokenExpiresAt: accessExpiresAt.toISOString(),
      refreshToken: refresh.raw,
      refreshTokenExpiresAt: refreshExpiresAt.toISOString(),
    },
    rows: [
      {
        accountId: input.accountId,
        kind: 'access',
        tokenHash: access.hash,
        familyId: input.familyId,
        expiresAt: accessExpiresAt,
      },
      {
        accountId: input.accountId,
        kind: 'refresh',
        tokenHash: refresh.hash,
        familyId: input.familyId,
        expiresAt: refreshExpiresAt,
      },
    ],
  };
}

/** Mints, persists and returns a single-use link token (`email-verification` or `auth-reset`). */
async function issueLinkToken(ctx: AuthContext, input: { accountId: number; kind: AccountTokenKind }): Promise<string> {
  const token = ctx.mintToken();
  await ctx.store.insertTokens([
    {
      accountId: input.accountId,
      kind: input.kind,
      tokenHash: token.hash,
      familyId: null,
      expiresAt: computeExpiry(ctx.now(), TOKEN_TTL_MS[input.kind]),
    },
  ]);
  return token.raw;
}

/** Fail-soft send: a dead relay must never turn a committed signup into a 500. */
async function sendOrLog(ctx: AuthContext, message: MailMessage, purpose: string): Promise<void> {
  const result = await ctx.sendMail(message);
  if (!result.success) {
    ctx.logger.error('Failed to send account email', { purpose, error: result.error ?? 'unknown' });
  }
}

// ---------------------------------------------------------------------------
// Pre-login: KDF descriptor
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/kdf` — the salt and cost parameters a new device needs BEFORE
 * it can authenticate.
 *
 * POST rather than GET, for a read: a GET would put the email in the request
 * line, and from there into access logs, proxy logs, `Referer` headers and
 * browser history. An endpoint whose entire purpose is not disclosing who has
 * an account should not scatter the address it was asked about.
 *
 * Unknown emails get a deterministic dummy (`lib/kdf-descriptor.ts`), produced
 * on this same code path with this same response shape.
 *
 * BOTH BRANCHES DO IDENTICAL WORK, and that is deliberate. The dummy is
 * derived unconditionally — including for accounts that exist and will never
 * use it — so that a real lookup and a miss cost the same one query plus the
 * same one HMAC. Computing it lazily (`account?.kdfDescriptor ?? derive(...)`)
 * left a measurable timing delta: the *response* said nothing, but how long it
 * took to produce did. An oracle that answers in nanoseconds is still an
 * oracle. The wasted HMAC is a rounding error next to the database round-trip.
 *
 * Rate-limiting is the second half of this defence and lives in the route
 * (`register-auth-routes.ts`): a timing signal this small needs many samples
 * per address to rise above network noise, and the per-IP throttle is what
 * denies an attacker those samples.
 */
export async function handleGetKdfDescriptor(
  input: { email: JsonValue | undefined },
  ctx: AuthContext,
): Promise<AuthOutcome<{ kdfDescriptor: KdfDescriptor }>> {
  const email = parseEmail(input.email);
  if (!email.ok) return invalid(email.reason);

  const account = await ctx.store.findAccountByEmail(email.value);
  // Computed before the branch, never inside it — see the header.
  const dummy = deriveDummyKdfDescriptor({ email: email.value, enumerationSecret: ctx.enumerationSecret });
  const kdfDescriptor = account === null ? dummy : account.kdfDescriptor;

  return { status: 'ok', body: { kdfDescriptor } };
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

export async function handleSignup(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  if (!ctx.signupsOpen) {
    return { status: 'forbidden', reason: 'this instance is not accepting new accounts' };
  }

  const fields = asFields(body);
  const email = parseEmail(fields.email);
  if (!email.ok) return invalid(email.reason);
  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return invalid(authHash.reason);
  const kdfDescriptor = parseKdfDescriptorField(fields.kdfDescriptor);
  if (!kdfDescriptor.ok) return invalid(kdfDescriptor.reason);
  const displayName = parseDisplayName(fields.displayName);
  if (!displayName.ok) return invalid(displayName.reason);

  const created = await ctx.store.createAccount({
    email: email.value,
    displayName: displayName.value,
    verifier: computeVerifier({ authHash: authHash.value, pepper: ctx.pepper }),
    kdfDescriptor: kdfDescriptor.value,
  });
  if (!created.ok) {
    // ACCEPTED ENUMERATION ORACLE, not an oversight. This 409 tells the caller
    // the address is registered — the one place in this service that does.
    // It is unavoidable in the mail-free configuration (with
    // REQUIRE_EMAIL_VERIFICATION off, a duplicate signup MUST fail loudly
    // rather than silently not create the account the user asked for), it
    // matches Bitwarden's behaviour, and it is bounded by the per-IP signup
    // throttle in `register-auth-routes.ts`. Every OTHER path — kdf, login,
    // request-reset — stays indistinguishable.
    // Full reasoning: docs/adr/002-signup-enumeration-tradeoff.md
    return { status: 'conflict', reason: 'an account already exists for this email' };
  }

  const account = created.account;
  const verificationToken = await issueLinkToken(ctx, { accountId: account.id, kind: 'email-verification' });
  await sendOrLog(
    ctx,
    buildVerificationEmail({ to: account.email, clientBaseUrl: ctx.clientBaseUrl, token: verificationToken }),
    'email-verification',
  );

  // With verification required, an unconfirmed account gets no session at all
  // — otherwise the requirement would be trivially bypassed by never leaving
  // the tab open after signup.
  if (ctx.requireEmailVerification) {
    return { status: 'created', body: { account: summarize(account), tokens: null } };
  }

  const session = mintSession(ctx, { accountId: account.id, familyId: ctx.mintFamilyId() });
  await ctx.store.insertTokens(session.rows);
  ctx.logger.info('Account created', { accountId: account.id });
  return { status: 'created', body: { account: summarize(account), tokens: session.tokens } };
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

export async function handleLogin(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const fields = asFields(body);
  const email = parseEmail(fields.email);
  if (!email.ok) return invalid(email.reason);
  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return invalid(authHash.reason);

  const account = await ctx.store.findAccountByEmail(email.value);
  // Computed and compared unconditionally: an unknown email must not return
  // faster than a wrong passphrase.
  const candidate = computeVerifier({ authHash: authHash.value, pepper: ctx.pepper });
  const matches = verifierMatches({ candidate, stored: account?.verifier ?? ABSENT_ACCOUNT_VERIFIER });

  if (account === null || !matches) {
    return { status: 'unauthorized', reason: LOGIN_REJECTED };
  }
  if (ctx.requireEmailVerification && account.emailVerifiedAt === null) {
    return { status: 'forbidden', reason: 'email address is not verified' };
  }

  const session = mintSession(ctx, { accountId: account.id, familyId: ctx.mintFamilyId() });
  await ctx.store.insertTokens(session.rows);
  return { status: 'ok', body: { account: summarize(account), tokens: session.tokens } };
}

// ---------------------------------------------------------------------------
// Token lifecycle
// ---------------------------------------------------------------------------

/** What the bearer middleware gets back for a valid access token. */
export interface ResolvedSession {
  accountId: number;
  tokenId: number;
  familyId: string | null;
}

/**
 * Resolves an `Authorization: Bearer` access token. `null` for absent,
 * unknown, expired or revoked — the caller turns all four into one `401`,
 * because distinguishing them tells an attacker which guesses were close.
 */
export async function resolveAccessToken(rawToken: string, ctx: AuthContext): Promise<ResolvedSession | null> {
  const stored = await ctx.store.findToken({ kind: 'access', tokenHash: hashToken(rawToken) });
  if (stored === null) return null;
  if (classifyToken(stored, ctx.now()) !== 'valid') return null;
  return { accountId: stored.accountId, tokenId: stored.id, familyId: stored.familyId };
}

/**
 * `POST /v1/auth/refresh` — rotation, with reuse detection.
 *
 * A VALID refresh token is consumed (revoked) and replaced by a fresh pair
 * carrying the same family id. A token that is present but ALREADY REVOKED is
 * the interesting case: the legitimate client rotated it, so whoever is
 * presenting it now has a copy they should not have. The whole family is
 * revoked, which logs out both the attacker and the real user — the correct
 * response, because the alternative is leaving a thief with a working
 * session.
 *
 * Access tokens minted by earlier rotations are deliberately left alone; they
 * expire on their own within minutes, and revoking them here would break a
 * request that is legitimately in flight during the rotation.
 */
export async function handleRefresh(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<{ tokens: SessionTokens }>> {
  const fields = asFields(body);
  const refreshToken = parseTokenField(fields.refreshToken, 'refreshToken');
  if (!refreshToken.ok) return invalid(refreshToken.reason);

  const stored = await ctx.store.findToken({ kind: 'refresh', tokenHash: hashToken(refreshToken.value) });
  if (stored === null) return { status: 'unauthorized', reason: 'invalid refresh token' };

  const now = ctx.now();
  const state = classifyToken(stored, now);
  if (state === 'revoked') {
    if (stored.familyId !== null) {
      await ctx.store.revokeFamily({ accountId: stored.accountId, familyId: stored.familyId, revokedAt: now });
    }
    ctx.logger.warn('Refresh token reuse detected; family revoked', { accountId: stored.accountId });
    return { status: 'unauthorized', reason: 'invalid refresh token' };
  }
  if (state === 'expired') {
    return { status: 'unauthorized', reason: 'refresh token has expired' };
  }

  await ctx.store.revokeToken({ tokenId: stored.id, revokedAt: now });
  const session = mintSession(ctx, {
    accountId: stored.accountId,
    familyId: stored.familyId ?? ctx.mintFamilyId(),
  });
  await ctx.store.insertTokens(session.rows);
  return { status: 'ok', body: { tokens: session.tokens } };
}

/** `POST /v1/auth/logout` — revokes the caller's whole family (this device), not just the presented access token. */
export async function handleLogout(session: ResolvedSession, ctx: AuthContext): Promise<AuthOutcome<never>> {
  const now = ctx.now();
  if (session.familyId === null) {
    await ctx.store.revokeToken({ tokenId: session.tokenId, revokedAt: now });
    return { status: 'no-content' };
  }
  await ctx.store.revokeFamily({ accountId: session.accountId, familyId: session.familyId, revokedAt: now });
  return { status: 'no-content' };
}

// ---------------------------------------------------------------------------
// Email verification
// ---------------------------------------------------------------------------

export async function handleVerifyEmail(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<{ verified: true }>> {
  const fields = asFields(body);
  const token = parseTokenField(fields.token);
  if (!token.ok) return invalid(token.reason);

  const stored = await ctx.store.findToken({ kind: 'email-verification', tokenHash: hashToken(token.value) });
  const now = ctx.now();
  if (stored === null || classifyToken(stored, now) !== 'valid') {
    return { status: 'invalid', reason: 'this verification link is invalid or has expired' };
  }

  await ctx.store.markEmailVerified({ accountId: stored.accountId, verifiedAt: now });
  // Consume it: a verification link is single-use.
  await ctx.store.revokeToken({ tokenId: stored.id, revokedAt: now });
  return { status: 'ok', body: { verified: true } };
}

// ---------------------------------------------------------------------------
// Reset (login recovery) and change-passphrase
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/request-reset` — always `202`, whether or not the address
 * has an account. The email is the only channel that reveals anything, and it
 * only reveals it to whoever controls the inbox.
 *
 * Any previously issued, still-live reset token is revoked first, so
 * requesting a second link cancels the first.
 */
export async function handleRequestReset(body: JsonValue | undefined, ctx: AuthContext): Promise<AuthOutcome<never>> {
  const fields = asFields(body);
  const email = parseEmail(fields.email);
  if (!email.ok) return invalid(email.reason);

  const account = await ctx.store.findAccountByEmail(email.value);
  if (account === null) return { status: 'accepted' };

  const now = ctx.now();
  await ctx.store.revokeTokensOfKind({ accountId: account.id, kind: 'auth-reset', revokedAt: now });
  const resetToken = await issueLinkToken(ctx, { accountId: account.id, kind: 'auth-reset' });
  await sendOrLog(
    ctx,
    buildResetEmail({ to: account.email, clientBaseUrl: ctx.clientBaseUrl, token: resetToken }),
    'auth-reset',
  );
  return { status: 'accepted' };
}

interface RotationFields {
  authHash: string;
  kdfDescriptor: KdfDescriptor;
  keyRecords: KeyRecordSubmission[];
}

/** The three fields every credential rotation carries, parsed once for both the reset and the change path. */
function parseRotationFields(fields: JsonObject, authHashField: string): ParseRotationResult {
  const authHash = parseAuthHashField(fields[authHashField], authHashField);
  if (!authHash.ok) return { ok: false, reason: authHash.reason };
  const kdfDescriptor = parseKdfDescriptorField(fields.kdfDescriptor);
  if (!kdfDescriptor.ok) return { ok: false, reason: kdfDescriptor.reason };
  const keyRecords = parseKeyRecordSubmissions(fields.keyRecords);
  if (!keyRecords.ok) return { ok: false, reason: keyRecords.reason };
  return {
    ok: true,
    value: { authHash: authHash.value, kdfDescriptor: kdfDescriptor.value, keyRecords: keyRecords.value },
  };
}

type ParseRotationResult = { ok: true; value: RotationFields } | { ok: false; reason: string };

/**
 * `POST /v1/auth/reset` — redeems a reset link into a NEW verifier, and, if
 * the client still had its recovery code, the re-wrapped DEK that keeps the
 * data readable.
 *
 * Reset restores LOGIN. It cannot restore DATA: the server never held a key.
 * A client that submits `keyRecords: []` gets a working account whose blob is
 * permanently undecryptable — which is why the email says so in those words
 * before the user clicks (`mail/messages.ts`).
 *
 * Everything — token consumption, verifier swap, key-record upsert, and
 * revocation of every outstanding session — happens in ONE transaction inside
 * the store. A partial application here would be silent data loss.
 */
export async function handleResetCredential(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<{ tokens: SessionTokens }>> {
  const fields = asFields(body);
  const token = parseTokenField(fields.token);
  if (!token.ok) return invalid(token.reason);
  const rotation = parseRotationFields(fields, 'authHash');
  if (!rotation.ok) return invalid(rotation.reason);

  const stored = await ctx.store.findToken({ kind: 'auth-reset', tokenHash: hashToken(token.value) });
  const now = ctx.now();
  if (stored === null || classifyToken(stored, now) !== 'valid') {
    return { status: 'invalid', reason: 'this reset link is invalid or has expired' };
  }

  const familyId = ctx.mintFamilyId();
  const session = mintSession(ctx, { accountId: stored.accountId, familyId });
  await ctx.store.rotateCredential({
    accountId: stored.accountId,
    verifier: computeVerifier({ authHash: rotation.value.authHash, pepper: ctx.pepper }),
    kdfDescriptor: rotation.value.kdfDescriptor,
    keyRecords: rotation.value.keyRecords,
    issue: session.rows,
    revokedAt: now,
    consumeTokenId: stored.id,
  });

  ctx.logger.info('Credential reset completed', {
    accountId: stored.accountId,
    keyRecordsSubmitted: rotation.value.keyRecords.length,
  });
  return { status: 'ok', body: { tokens: session.tokens } };
}

/**
 * `POST /v1/auth/change-passphrase` — the authenticated sibling of reset, for
 * a user who still knows their current passphrase.
 *
 * It exists in v0.1.0 rather than "later" on purpose: bolting it on after the
 * protocol ships would be a breaking change, because the atomic
 * verifier + re-wrapped-DEK submission below is exactly the shape the reset
 * path already has, and adding it late would mean two incompatible shapes.
 *
 * Like reset, it revokes every outstanding session for the account and hands
 * back a fresh pair for the caller — a passphrase change should log out the
 * other devices, which is precisely what a user changing it under suspicion
 * expects.
 */
export async function handleChangePassphrase(
  input: { accountId: number; body: JsonValue | undefined },
  ctx: AuthContext,
): Promise<AuthOutcome<{ tokens: SessionTokens }>> {
  const fields = asFields(input.body);
  const currentAuthHash = parseAuthHashField(fields.currentAuthHash, 'currentAuthHash');
  if (!currentAuthHash.ok) return invalid(currentAuthHash.reason);
  const rotation = parseRotationFields(fields, 'newAuthHash');
  if (!rotation.ok) return invalid(rotation.reason);

  const account = await ctx.store.findAccountById(input.accountId);
  if (account === null) return { status: 'unauthorized', reason: 'account no longer exists' };

  const candidate = computeVerifier({ authHash: currentAuthHash.value, pepper: ctx.pepper });
  if (!verifierMatches({ candidate, stored: account.verifier })) {
    return { status: 'unauthorized', reason: 'current passphrase is incorrect' };
  }

  const now = ctx.now();
  const session = mintSession(ctx, { accountId: account.id, familyId: ctx.mintFamilyId() });
  await ctx.store.rotateCredential({
    accountId: account.id,
    verifier: computeVerifier({ authHash: rotation.value.authHash, pepper: ctx.pepper }),
    kdfDescriptor: rotation.value.kdfDescriptor,
    keyRecords: rotation.value.keyRecords,
    issue: session.rows,
    revokedAt: now,
    consumeTokenId: null,
  });

  ctx.logger.info('Passphrase changed', { accountId: account.id });
  return { status: 'ok', body: { tokens: session.tokens } };
}

// ---------------------------------------------------------------------------
// Account read
// ---------------------------------------------------------------------------

/**
 * `GET /v1/auth/account` — the caller's own summary. The client needs it to
 * know whether the address is verified without inferring it from a login
 * failure.
 *
 * `unauthorized` rather than `not-found` when the row is gone: the token
 * outlived the account (deleted from another device), and "log in again" is
 * the honest instruction.
 */
export async function handleGetAccount(
  input: { accountId: number },
  ctx: AuthContext,
): Promise<AuthOutcome<{ account: AccountSummary }>> {
  const account = await ctx.store.findAccountById(input.accountId);
  if (account === null) return { status: 'unauthorized', reason: 'account no longer exists' };
  return { status: 'ok', body: { account: summarize(account) } };
}

// ---------------------------------------------------------------------------
// Account deletion (self-serve DSAR)
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/delete` — removes the account and, by foreign-key cascade,
 * every blob and key record it owns. This is the self-serve erasure path that
 * closed the M118 privacy blocker: no support ticket, no cleanup job, no
 * window in which orphaned ciphertext outlives its owner.
 *
 * Re-authentication is required even though the caller already holds a valid
 * access token: a token left behind on a shared device must not be enough to
 * destroy someone's data irreversibly.
 */
export async function handleDeleteAccount(
  input: { accountId: number; body: JsonValue | undefined },
  ctx: AuthContext,
): Promise<AuthOutcome<never>> {
  const fields = asFields(input.body);
  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return invalid(authHash.reason);

  const account = await ctx.store.findAccountById(input.accountId);
  if (account === null) return { status: 'unauthorized', reason: 'account no longer exists' };

  const candidate = computeVerifier({ authHash: authHash.value, pepper: ctx.pepper });
  if (!verifierMatches({ candidate, stored: account.verifier })) {
    return { status: 'unauthorized', reason: 'passphrase is incorrect' };
  }

  await ctx.store.deleteAccount(account.id);
  ctx.logger.info('Account deleted with all sync data', { accountId: account.id });
  return { status: 'no-content' };
}
