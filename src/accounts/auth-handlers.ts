/**
 * Account handler cores — the `/v1/auth/*` policy, written against injected
 * dependencies (`AuthContext`) rather than a database, a clock or a mailer.
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
 *
 * WHAT M192 CHANGED ABOUT THAT SENTENCE, AND WHAT IT DID NOT. This file now
 * seals and opens the RECOVERY CODE (`lib/escrow.ts`, ADR-0005). A recovery
 * code is not a key: it becomes one only after the client runs HKDF over it,
 * and nothing on this server ever does. The operator's power is real and is
 * written down in ADR-0005 rather than hidden behind that distinction — but
 * the code path is unchanged, and no function here has ever held a DEK.
 */
import type {
  AccountRecord,
  AccountStore,
  KeyRecordSubmission,
  NewTokenInput,
  RedeemInviteResult,
} from './account-store.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';
import { deriveDummyKdfDescriptor } from '../lib/kdf-descriptor.js';
import { computeVerifier, verifierMatches } from '../lib/verifier.js';
import { openRecoveryCode, sealRecoveryCode } from '../lib/escrow.js';
import { utcDayKey } from '../lib/utc-day.js';
import {
  classifyToken,
  computeExpiry,
  isSignupInviteToken,
  hashToken,
  RESET_TOKEN_TTL_MS,
  TOKEN_TTL_MS,
  type GeneratedToken,
} from '../lib/tokens.js';
import type { Logger } from '../logger.js';
import type { Mailer } from '../mail/mailer.js';
import {
  asFields,
  parseAuthHashField,
  parseDisplayName,
  parseEmail,
  parseKdfDescriptorField,
  parseKeyRecordSubmissions,
  parseOptionalRecoveryAuthHash,
  parseRecoveryCode,
  parseTokenField,
} from './auth-input.js';
import type { JsonObject, JsonValue } from '../lib/json.js';
import type { AccountView } from '../protocol.js';

/** Everything the handlers need from the outside world. All of it injected — none of it imported. */
export interface AuthContext {
  store: AccountStore;
  /** `HMAC` key for verifiers, derived from `SERVER_SECRET` (`lib/server-secrets.ts`). */
  pepper: string;
  /** `HMAC` key behind deterministic dummy KDF descriptors. */
  enumerationSecret: string;
  /**
   * The 32-byte AES-256-GCM key that seals `accounts.recovery_code_escrow`,
   * derived from `SERVER_SECRET` under its own frozen label. It is the one
   * value in this context that DECRYPTS something; see `lib/escrow.ts`.
   */
  escrowKey: Buffer;
  /** The two letters this service sends. A no-op implementation on an instance with no mail configured. */
  mailer: Mailer;
  now(): Date;
  mintToken(): GeneratedToken;
  /**
   * Mints a password-reset token (`sr_`). SEPARATE from {@link AuthContext.mintToken}
   * because the prefix binds the token to one endpoint: a session token posted
   * to `/reset/open`, or a reset token sent as a bearer, is refused by shape
   * before anything is looked up.
   */
  mintResetToken(): GeneratedToken;
  mintFamilyId(): string;
  logger: Logger;
}

export interface SessionTokens {
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
}

export interface SessionResponse {
  account: AccountView;
  tokens: SessionTokens;
}

/** `POST /v1/auth/invite-lookup` — what a person is shown before they choose a passphrase. */
export interface InviteLookupResponse {
  email: string;
  displayName: string | null;
  expiresAt: string;
}

/** `POST /v1/auth/reset/open` — the escrowed code, handed over once. */
export interface ResetOpenResponse {
  email: string;
  recoveryCode: string;
}

/**
 * Every outcome an auth handler can produce, in HTTP-shaped terms so the glue
 * needs no policy of its own. `reason` strings are diagnostic; clients branch
 * on the status. The three machine-shaped reasons (`invite-invalid`,
 * `reset-invalid`, `account-suspended`) are the exception the contract fixes,
 * and they are constants below rather than literals at a call site.
 */
export type AuthOutcome<T> =
  | { status: 'ok'; body: T }
  | { status: 'created'; body: T }
  | { status: 'accepted'; body: T }
  | { status: 'no-content' }
  | { status: 'invalid'; reason: string }
  | { status: 'unauthorized'; reason: string }
  | { status: 'forbidden'; reason: string }
  | { status: 'not-found'; reason: string }
  | { status: 'conflict'; reason: string };

/**
 * Compared against when no account exists, so an unknown address costs the same
 * constant-time comparison as a wrong auth-hash. 64 hex characters — the exact
 * width of a real verifier, because `verifierMatches` short-circuits on a
 * length mismatch.
 */
const ABSENT_ACCOUNT_VERIFIER = '0'.repeat(64);

/** A single generic message for every login failure — never "no such account" vs "wrong passphrase". */
const LOGIN_REJECTED = 'invalid email or passphrase';

/**
 * The ONE failure the recovery endpoints ever report. An unknown address, an
 * account that never set a recovery code, a wrong code, and a rotation that
 * lost a race all come back as this exact string with this exact status —
 * see `handleRecover` for why the list has to be that long.
 */
const RECOVERY_REJECTED = 'invalid email or recovery code';

/**
 * The contract's fixed reason for a suspended account, on every surface:
 * login, refresh, every bearer route, the recovery paths and the admin tree.
 * A machine-shaped string rather than a sentence, because a client renders its
 * own copy for this one and must be able to recognise it.
 */
export const ACCOUNT_SUSPENDED = 'account-suspended';

/**
 * The ONE failure every invite path reports — unknown, malformed, wrong
 * service, expired, revoked and already redeemed alike. Telling them apart
 * would let a caller probe which tokens exist and learn that a token had once
 * been real.
 */
export const INVITE_INVALID = 'invite-invalid';

/** The ONE failure `POST /v1/auth/reset/open` reports: unknown, spent and expired share it. */
export const RESET_INVALID = 'reset-invalid';

function invalid<T>(reason: string): AuthOutcome<T> {
  return { status: 'invalid', reason };
}

function suspended<T>(): AuthOutcome<T> {
  return { status: 'forbidden', reason: ACCOUNT_SUSPENDED };
}

/**
 * The ONE function that turns an account row into a response body, and it
 * names every field it emits.
 *
 * It is `async` because `aiUsedToday` is a second read, and that cost is
 * deliberate: a client that shows "3 of 200 used today" on the account screen
 * would otherwise need a second endpoint, and a second endpoint would drift
 * from this one about which day "today" is.
 */
async function toAccountView(account: AccountRecord, ctx: AuthContext): Promise<AccountView> {
  const aiUsedToday = await ctx.store.aiUsageOn({ accountId: account.id, day: utcDayKey(ctx.now()) });
  return {
    id: account.id,
    email: account.email,
    displayName: account.displayName,
    role: account.role,
    dailyAiLimit: account.dailyAiLimit,
    aiUsedToday,
    suspendedAt: account.suspendedAt?.toISOString() ?? null,
    createdAt: account.createdAt.toISOString(),
  };
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

/** Signs the caller in: mints a pair, persists the digests, and builds the body. */
async function issueSession(account: AccountRecord, ctx: AuthContext): Promise<SessionResponse> {
  const session = mintSession(ctx, { accountId: account.id, familyId: ctx.mintFamilyId() });
  await ctx.store.insertTokens(session.rows);
  return { account: await toAccountView(account, ctx), tokens: session.tokens };
}

// ---------------------------------------------------------------------------
// Pre-login: KDF descriptor
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/kdf` — the salt and cost parameters a new device needs BEFORE
 * it can authenticate.
 *
 * POST rather than GET, for a read: a GET would put the address in the request
 * line, and from there into access logs, proxy logs, `Referer` headers and
 * browser history. An endpoint whose entire purpose is not disclosing who has
 * an account should not scatter the identifier it was asked about. That
 * argument was already true for a handle; with an address back on the wire it
 * is the difference between a leak and a mailing list.
 *
 * Unknown addresses get a deterministic dummy (`lib/kdf-descriptor.ts`),
 * produced on this same code path with this same response shape, derived over
 * the CANONICAL email.
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
  // Computed before the branch, never inside it — see the header. Derived over
  // the CANONICAL address, so two spellings of one unknown address cannot be
  // told apart by their descriptors.
  const dummy = deriveDummyKdfDescriptor({ identifier: email.value, enumerationSecret: ctx.enumerationSecret });
  const kdfDescriptor = account === null ? dummy : account.kdfDescriptor;

  return { status: 'ok', body: { kdfDescriptor } };
}

// ---------------------------------------------------------------------------
// Invite lookup
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/invite-lookup` — who this invitation is for.
 *
 * The client calls it when a person opens the link in their mail, so the
 * signup form can show the address the letter went to instead of asking them
 * to type it. That is the whole point of an ADDRESSED invite: the person never
 * enters their own email, so they cannot mistype it into an account nobody can
 * reach.
 *
 * IT IS NOT AN ORACLE, and the shape of this function is why. Unknown, spent,
 * revoked, expired and wrong-service tokens all answer one `404` with one
 * message, and every one of them costs the same work: the token is hashed and
 * the table is queried on both branches. Returning early on a malformed token
 * would make the response time the thing that says which tokens are real.
 *
 * Throttled per IP in `register-auth-routes.ts`, which is what denies an
 * attacker the volume a residual timing signal would need.
 */
export async function handleInviteLookup(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<InviteLookupResponse>> {
  const fields = asFields(body);
  const inviteToken = parseTokenField(fields.inviteToken, 'inviteToken');
  // A missing or malformed token is hashed anyway — as the empty string — so
  // the query runs on every branch and the answer costs the same.
  const raw = inviteToken.ok ? inviteToken.value : '';
  const addressing = await ctx.store.findInviteAddressing({
    inviteTokenHash: hashToken(raw),
    now: ctx.now(),
  });

  // The shape gate is applied to the RESULT rather than before the lookup, for
  // the same reason: a `gi_` token from the retired gateway, or a session
  // token pasted here, must cost exactly what a wrong `si_` token costs.
  if (addressing === null || !isSignupInviteToken(raw)) {
    return { status: 'not-found', reason: INVITE_INVALID };
  }

  return {
    status: 'ok',
    body: {
      email: addressing.email,
      displayName: addressing.displayName,
      expiresAt: addressing.expiresAt.toISOString(),
    },
  };
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

/** Everything a signup body carries, once every field has been decoded. */
interface SignupSubmission {
  inviteToken: string;
  authHash: string;
  kdfDescriptor: KdfDescriptor;
  displayName: string | null;
  recoveryAuthHash: string;
  recoveryCode: string;
  keyRecords: KeyRecordSubmission[];
}

type ParseSignupResult = { ok: true; value: SignupSubmission } | { ok: false; outcome: AuthOutcome<never> };

/**
 * Decodes a signup body, or says which status it fails with.
 *
 * THE INVITE IS PARSED FIRST AND ITS FAILURE IS A `403`, NOT A `400`. A caller
 * must not be able to learn what a well-formed invite looks like by watching
 * the status code change, so a missing, malformed or wrong-service token reads
 * exactly as a wrong one does. Every other field is an ordinary `400`.
 */
function parseSignup(fields: JsonObject): ParseSignupResult {
  const inviteToken = parseTokenField(fields.inviteToken, 'inviteToken');
  // THE SHAPE GATE, and it runs before anything else: a token minted by the
  // retired gateway (`gi_`) is refused here without ever being hashed against
  // this service's invite rows. Its answer is the SAME `invite-invalid` a
  // wrong, spent, revoked or expired token gets.
  if (!inviteToken.ok || !isSignupInviteToken(inviteToken.value)) {
    return { ok: false, outcome: { status: 'forbidden', reason: INVITE_INVALID } };
  }

  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return { ok: false, outcome: invalid(authHash.reason) };
  const kdfDescriptor = parseKdfDescriptorField(fields.kdfDescriptor);
  if (!kdfDescriptor.ok) return { ok: false, outcome: invalid(kdfDescriptor.reason) };
  const displayName = parseDisplayName(fields.displayName);
  if (!displayName.ok) return { ok: false, outcome: invalid(displayName.reason) };

  // REQUIRED SINCE M192, both of them. The client no longer SHOWS the recovery
  // code to the person, so an account created without one is an account whose
  // lost passphrase is terminal and whose owner was never warned. `null` used
  // to be a legitimate "this account has no second authenticator"; it is now a
  // `400`.
  const recoveryAuthHash = parseAuthHashField(fields.recoveryAuthHash, 'recoveryAuthHash');
  if (!recoveryAuthHash.ok) return { ok: false, outcome: invalid(recoveryAuthHash.reason) };
  const recoveryCode = parseRecoveryCode(fields.recoveryCode);
  if (!recoveryCode.ok) return { ok: false, outcome: invalid(recoveryCode.reason) };

  const keyRecords = parseKeyRecordSubmissions(fields.keyRecords);
  if (!keyRecords.ok) return { ok: false, outcome: invalid(keyRecords.reason) };
  const kinds = new Set(keyRecords.value.map((record) => record.kind));
  // BOTH RECORDS OR NEITHER ACCOUNT. A signup without the `passphrase` record
  // creates a login that decrypts nothing; one without the `recovery` record
  // creates an escrowed code that unwraps nothing, which is a mailed reset
  // that fails on the day it is needed.
  if (!kinds.has('passphrase') || !kinds.has('recovery')) {
    return {
      ok: false,
      outcome: invalid('keyRecords must contain exactly one passphrase record and one recovery record'),
    };
  }

  return {
    ok: true,
    value: {
      inviteToken: inviteToken.value,
      authHash: authHash.value,
      kdfDescriptor: kdfDescriptor.value,
      displayName: displayName.value,
      recoveryAuthHash: recoveryAuthHash.value,
      recoveryCode: recoveryCode.value,
      keyRecords: keyRecords.value,
    },
  };
}

/**
 * `POST /v1/auth/signup` — redeem an addressed invite and become an account.
 *
 * THE EMAIL COMES FROM THE INVITE, NEVER FROM THE BODY, and that single fact
 * is what makes the invitation the address verification. A person who received
 * the letter at `anna@example.org` cannot sign up as `boss@example.org`, and
 * nobody has to click a second confirmation link to prove a mailbox they have
 * already demonstrably read.
 *
 * ONE TRANSACTION, FIVE WRITES: the invite redemption, the account, the sealed
 * recovery code, and both key records. See
 * `AccountStore.redeemInviteAndCreateAccount` for why a half-application of
 * any of them is a distinct disaster.
 */
export async function handleSignup(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const parsed = parseSignup(asFields(body));
  if (!parsed.ok) return parsed.outcome;
  const submission = parsed.value;

  const created: RedeemInviteResult = await ctx.store.redeemInviteAndCreateAccount({
    inviteTokenHash: hashToken(submission.inviteToken),
    now: ctx.now(),
    account: {
      displayName: submission.displayName,
      verifier: computeVerifier({ authHash: submission.authHash, pepper: ctx.pepper }),
      recoveryVerifier: computeVerifier({ authHash: submission.recoveryAuthHash, pepper: ctx.pepper }),
      kdfDescriptor: submission.kdfDescriptor,
      // The raw code exists in this function and inside `sealRecoveryCode`,
      // and nowhere else. It is never logged and never returned.
      recoveryCodeEscrow: sealRecoveryCode({ code: submission.recoveryCode, escrowKey: ctx.escrowKey }),
      keyRecords: submission.keyRecords,
    },
  });

  if (!created.ok && created.reason === 'invite-invalid') {
    // ONE message for unknown, expired, revoked and already-spent.
    return { status: 'forbidden', reason: INVITE_INVALID };
  }
  if (!created.ok) {
    // A DUPLICATE ADDRESS, AND THE ORACLE IS NOW ALMOST GONE. This 409 is
    // reachable only by somebody holding a live invite that was ADDRESSED to
    // the very address it reports as taken, so it confirms nothing the caller
    // did not already know: the operator wrote that address on the letter.
    // Before M192 an invite holder could probe arbitrary handles here; they
    // cannot now, because the address is not theirs to choose.
    //
    // It does NOT consume the invite (see
    // `AccountStore.redeemInviteAndCreateAccount`), so an operator who invited
    // somebody twice by mistake has not destroyed the live invitation.
    return { status: 'conflict', reason: 'an account already exists for this email' };
  }

  const session = await issueSession(created.account, ctx);
  ctx.logger.info('Account created', { accountId: created.account.id });
  return { status: 'created', body: session };
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
  // Computed and compared unconditionally: an unknown address must not return
  // faster than a wrong passphrase.
  const candidate = computeVerifier({ authHash: authHash.value, pepper: ctx.pepper });
  const matches = verifierMatches({ candidate, stored: account?.verifier ?? ABSENT_ACCOUNT_VERIFIER });

  if (account === null || !matches) {
    return { status: 'unauthorized', reason: LOGIN_REJECTED };
  }
  // AFTER the credential check, deliberately. A suspended account answers
  // differently from a live one, which is a disclosure — but only to somebody
  // who has just proved they own the account, and they are exactly the person
  // who needs to be told why they cannot get in.
  if (account.suspendedAt !== null) return suspended();

  // One of the two writers of `accounts.last_seen_at`, the other being the AI
  // proxy. Both are deliberate acts a person took, which is what makes the
  // column mean what an operator reads it as; a refresh or a sync poll is the
  // client's timer and is not recorded.
  await ctx.store.touchLastSeen({ accountId: account.id, seenAt: ctx.now() });
  return { status: 'ok', body: await issueSession(account, ctx) };
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
 * The three answers an access token can get.
 *
 * `suspended` IS ITS OWN MEMBER rather than folded into `invalid`, because the
 * two produce different status codes: an unusable token is a `401` that means
 * "sign in again", and a suspended account is a `403` that means "signing in
 * again will not help". A client that could not tell them apart would loop on
 * the refresh endpoint forever.
 */
export type AccessTokenResolution =
  { status: 'valid'; session: ResolvedSession } | { status: 'invalid' } | { status: 'suspended' };

/**
 * Resolves an `Authorization: Bearer` access token. `invalid` covers absent,
 * unknown, expired and revoked — the caller turns all four into one `401`,
 * because distinguishing them tells an attacker which guesses were close.
 *
 * IT READS THE ACCOUNT ROW, which is a second query on every authenticated
 * request. That cost buys the suspension guarantee: without it, an operator
 * who suspends somebody at 09:00 leaves their phone syncing until its access
 * token expires, and "suspended" would mean "in a quarter of an hour".
 */
export async function resolveAccessToken(rawToken: string, ctx: AuthContext): Promise<AccessTokenResolution> {
  const stored = await ctx.store.findToken({ kind: 'access', tokenHash: hashToken(rawToken) });
  if (stored === null) return { status: 'invalid' };
  if (classifyToken(stored, ctx.now()) !== 'valid') return { status: 'invalid' };

  const account = await ctx.store.findAccountById(stored.accountId);
  // The account was deleted from another device while this token lived. Not
  // `suspended`: there is nothing to reactivate, and "sign in again" is the
  // honest instruction.
  if (account === null) return { status: 'invalid' };
  if (account.suspendedAt !== null) return { status: 'suspended' };

  return {
    status: 'valid',
    session: { accountId: stored.accountId, tokenId: stored.id, familyId: stored.familyId },
  };
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

  const account = await ctx.store.findAccountById(stored.accountId);
  if (account === null) return { status: 'unauthorized', reason: 'invalid refresh token' };
  // A suspended account gets a `403` here rather than a `401`, so a client
  // sitting in a refresh loop learns that re-authenticating will not help.
  // The presented token is deliberately NOT spent: the suspension may be
  // lifted, and burning the refresh token would log the person out of a device
  // they will get back.
  if (account.suspendedAt !== null) return suspended();

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
// Change-passphrase
// ---------------------------------------------------------------------------

interface RotationFields {
  authHash: string;
  kdfDescriptor: KdfDescriptor;
  keyRecords: KeyRecordSubmission[];
}

type ParseRotationResult = { ok: true; value: RotationFields } | { ok: false; reason: string };

/** The three fields every credential rotation carries. */
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

/**
 * `POST /v1/auth/change-passphrase` — rotation for a user who still knows
 * their current passphrase.
 *
 * The atomic verifier + re-wrapped-DEK submission below is the shape every
 * rotation on this service uses, which is why it shipped in v0.1.0 rather than
 * "later": adding it after the protocol froze would have meant two
 * incompatible shapes.
 *
 * It revokes every outstanding session for the account and hands
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
  });

  ctx.logger.info('Passphrase changed', { accountId: account.id });
  return { status: 'ok', body: { tokens: session.tokens } };
}

// ---------------------------------------------------------------------------
// Recovery-code authentication
// ---------------------------------------------------------------------------

/**
 * Checks a recovery proof against an account, in constant time whatever the
 * account's state.
 *
 * THREE DIFFERENT "NO" ANSWERS COLLAPSE INTO ONE `null`, and all three cost
 * the same work: the address is unknown, the account exists but has no
 * recovery verifier, or the code is wrong. Each is compared against a
 * full-width stand-in, so the branch that returns is chosen after the HMAC
 * rather than instead of it — the same shape `handleLogin` and
 * `handleGetKdfDescriptor` use, and for the same reason (M128 security
 * review: a response that says nothing can still be an oracle in its timing).
 *
 * The returned `recoveryVerifier` is what the store then compare-and-swaps
 * on, so the value this function matched is the value the transaction
 * requires to still be there.
 */
async function authenticateRecoveryCode(
  input: { email: string; recoveryAuthHash: string },
  ctx: AuthContext,
): Promise<{ account: AccountRecord; recoveryVerifier: string } | null> {
  const account = await ctx.store.findAccountByEmail(input.email);
  const candidate = computeVerifier({ authHash: input.recoveryAuthHash, pepper: ctx.pepper });
  const matches = verifierMatches({ candidate, stored: account?.recoveryVerifier ?? ABSENT_ACCOUNT_VERIFIER });

  if (account === null || account.recoveryVerifier === null || !matches) return null;
  return { account, recoveryVerifier: account.recoveryVerifier };
}

/**
 * `POST /v1/auth/recover` — log in with the recovery code instead of the
 * passphrase.
 *
 * The recovery code is the SECOND authenticator, and since M192 it is also
 * what a mailed reset delivers (`handleResetOpen`). Its properties are
 * unchanged: unlike a mailed link, the code both authenticates AND unwraps,
 * because the client derives `KEK_r` from it. What changed is who else holds a
 * copy — the operator does, in escrow, and ADR-0005 says so plainly.
 *
 * What comes back is an ordinary session. It is deliberately NOT a
 * lesser one: the holder of the recovery code is the account owner by
 * construction, and a restricted "recovery mode" token would only add a
 * second authorization surface with no property the code does not already
 * carry.
 *
 * Throttled per IP and email in `register-auth-routes.ts`. That throttle is
 * not decoration: this endpoint accepts a guess at the ONE authenticator left
 * to a user who has lost their passphrase.
 */
export async function handleRecover(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const fields = asFields(body);
  const email = parseEmail(fields.email);
  if (!email.ok) return invalid(email.reason);
  const recoveryAuthHash = parseAuthHashField(fields.recoveryAuthHash, 'recoveryAuthHash');
  if (!recoveryAuthHash.ok) return invalid(recoveryAuthHash.reason);

  const proof = await authenticateRecoveryCode({ email: email.value, recoveryAuthHash: recoveryAuthHash.value }, ctx);
  if (proof === null) return { status: 'unauthorized', reason: RECOVERY_REJECTED };
  // After the proof, for the reason `handleLogin` gives: only somebody who has
  // demonstrated ownership is told why the door is shut.
  if (proof.account.suspendedAt !== null) return suspended();

  const session = await issueSession(proof.account, ctx);
  ctx.logger.info('Account recovered with a recovery code', { accountId: proof.account.id });
  return { status: 'ok', body: session };
}

/**
 * `POST /v1/auth/recover-rotate` — prove the recovery code, then set a new
 * passphrase.
 *
 * THE PROOF TRAVELS IN THIS REQUEST rather than in a session token minted by
 * `handleRecover`, so the code is checked in the same call that writes. A
 * two-step flow would let a session outlive the moment the user held the
 * code, and would make the store's compare-and-swap guard a check against
 * something read minutes ago.
 *
 * A `passphrase` KEY RECORD IS REQUIRED, unlike `handleChangePassphrase`
 * where an empty array is a legitimate "I am changing nothing". Here the
 * passphrase-KEK necessarily changed, so the DEK MUST be re-wrapped under the
 * new one. Accepting the rotation without it would mint an account that logs
 * in perfectly and decrypts nothing, with no way for the user to notice until
 * they open their diary — the brick `server/rotate-dek-handler.ts` refuses to
 * build, refused here too.
 *
 * ROTATING THE RECOVERY CODE IS ALL-OR-NOTHING, and since M192 it is a THREE
 * way all-or-nothing: the new recovery verifier, the re-wrapped `recovery` key
 * record, AND the re-sealed escrow. A new verifier without the record leaves a
 * code that authenticates and unwraps nothing; a record without the verifier
 * leaves a code that unwraps and cannot log in; and an escrow left holding the
 * OLD code turns the next mailed reset into a letter carrying a credential the
 * account no longer accepts. `recoveryCode` is therefore REQUIRED whenever
 * `newRecoveryAuthHash` is present, and forbidden-by-irrelevance when it is
 * not.
 */
export async function handleRecoverRotate(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const fields = asFields(body);
  const email = parseEmail(fields.email);
  if (!email.ok) return invalid(email.reason);
  const recoveryAuthHash = parseAuthHashField(fields.recoveryAuthHash, 'recoveryAuthHash');
  if (!recoveryAuthHash.ok) return invalid(recoveryAuthHash.reason);
  const rotation = parseRotationFields(fields, 'newAuthHash');
  if (!rotation.ok) return invalid(rotation.reason);
  const newRecoveryAuthHash = parseOptionalRecoveryAuthHash(fields.newRecoveryAuthHash, 'newRecoveryAuthHash');
  if (!newRecoveryAuthHash.ok) return invalid(newRecoveryAuthHash.reason);

  const submittedKinds = new Set(rotation.value.keyRecords.map((record) => record.kind));
  if (!submittedKinds.has('passphrase')) {
    return invalid('a passphrase key record is required: the new passphrase-KEK must re-wrap the DEK');
  }
  if ((newRecoveryAuthHash.value !== null) !== submittedKinds.has('recovery')) {
    return invalid('rotating the recovery code requires both newRecoveryAuthHash and a recovery key record');
  }

  // The third half of the same rule. Parsed here rather than in a shared
  // helper so the two branches stay visible: no new code when the recovery
  // code is not moving, and no rotation at all when it is moving without one.
  let newRecoveryCodeEscrow: Buffer | null = null;
  if (newRecoveryAuthHash.value !== null) {
    const recoveryCode = parseRecoveryCode(fields.recoveryCode);
    if (!recoveryCode.ok) {
      return invalid('rotating the recovery code requires recoveryCode, so the escrow can be replaced with it');
    }
    newRecoveryCodeEscrow = sealRecoveryCode({ code: recoveryCode.value, escrowKey: ctx.escrowKey });
  }

  const proof = await authenticateRecoveryCode({ email: email.value, recoveryAuthHash: recoveryAuthHash.value }, ctx);
  if (proof === null) return { status: 'unauthorized', reason: RECOVERY_REJECTED };
  if (proof.account.suspendedAt !== null) return suspended();

  const now = ctx.now();
  const session = mintSession(ctx, { accountId: proof.account.id, familyId: ctx.mintFamilyId() });
  // ONE call, because every piece below has to move together. The transaction
  // is the store's — see `AccountStore.recoverAndRotatePassphrase` for what
  // each half-state costs. No transaction appears in this file.
  const rotated = await ctx.store.recoverAndRotatePassphrase({
    accountId: proof.account.id,
    expectedRecoveryVerifier: proof.recoveryVerifier,
    verifier: computeVerifier({ authHash: rotation.value.authHash, pepper: ctx.pepper }),
    kdfDescriptor: rotation.value.kdfDescriptor,
    newRecoveryVerifier:
      newRecoveryAuthHash.value === null
        ? null
        : computeVerifier({ authHash: newRecoveryAuthHash.value, pepper: ctx.pepper }),
    newRecoveryCodeEscrow,
    keyRecords: rotation.value.keyRecords,
    issue: session.rows,
    revokedAt: now,
  });

  if (!rotated.ok) {
    // A lost race reports the SAME failure a wrong code does. It is a rare
    // outcome, and letting it be distinguishable would hand an attacker a
    // signal that a concurrent recovery just succeeded.
    return { status: 'unauthorized', reason: RECOVERY_REJECTED };
  }

  ctx.logger.info('Passphrase reset with a recovery code', { accountId: proof.account.id });
  return {
    status: 'ok',
    body: { account: await toAccountView(proof.account, ctx), tokens: session.tokens },
  };
}

// ---------------------------------------------------------------------------
// Mailed password reset
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/reset/request` — "I forgot my password".
 *
 * `202` ALWAYS, AFTER THE SAME WORK. A known address and an unknown one both
 * mint a token, both hash it, and both take the same path out; only the store
 * write and the send are skipped on the unknown branch. That symmetry is the
 * whole anti-enumeration argument here, and it is the one PROTOCOL.md used to
 * record as MISSING (§5.13, before M181 deleted the endpoint): the old
 * `request-reset` did the expensive work only for addresses that existed, so
 * its timing said what its body did not.
 *
 * The residual asymmetry — one INSERT and one HTTP send on the known branch —
 * is bounded by the per (IP, email) throttle in `register-auth-routes.ts`,
 * which is never cleared on success. A person forgets their password once;
 * a caller measuring this endpoint does it thousands of times.
 *
 * WHAT THE LETTER CARRIES IS NOT A NEW AUTHORITY. It carries a link to
 * `handleResetOpen`, which hands back the recovery code the operator already
 * holds in escrow. Nothing on this path writes to the account.
 */
export async function handleResetRequest(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<Record<string, never>>> {
  const fields = asFields(body);
  const email = parseEmail(fields.email);
  // Even a malformed address is a `202`. A `400` here would be a free oracle
  // for the SHAPE of addresses this instance holds, and there is nothing a
  // caller could usefully do with the distinction anyway.
  if (!email.ok) return { status: 'accepted', body: {} };

  const account = await ctx.store.findAccountByEmail(email.value);
  const now = ctx.now();
  // Minted and digested on BOTH branches — see the header. The unknown branch
  // throws the token away, having paid for it.
  const token = ctx.mintResetToken();
  const expiresAt = computeExpiry(now, RESET_TOKEN_TTL_MS);

  if (account === null) return { status: 'accepted', body: {} };
  // A suspended account is not told anything different, deliberately: this
  // endpoint answers `202` to everybody, and a suspended person who resets
  // their password still meets the `403` at the door.
  await ctx.store.createPasswordReset({
    accountId: account.id,
    tokenHash: token.hash,
    expiresAt,
    now,
  });
  // The mailer never throws (see `mail/mailer.ts`): a send failure must not be
  // able to turn this `202` into a `500` and make the status code the oracle.
  await ctx.mailer.sendReset({
    email: account.email,
    resetToken: token.raw,
    expiresAt: expiresAt.toISOString(),
  });
  // The account id, never the address and never the token.
  ctx.logger.info('Password reset requested', { accountId: account.id });
  return { status: 'accepted', body: {} };
}

/**
 * `POST /v1/auth/reset/open` — spend the mailed token and be told the account's
 * recovery code, once.
 *
 * THE TOKEN IS CONSUMED IN THE SAME STATEMENT THAT READS IT
 * (`AccountStore.consumePasswordReset`), so two requests carrying one token
 * cannot both be answered. A read-then-write would make the single use a
 * matter of timing.
 *
 * WHAT THE CALLER DOES NEXT is the ordinary recovery ceremony: derive
 * `recoveryAuthHash` and `KEK_r` from the code, unwrap the DEK from the
 * `recovery` key record, and POST `/v1/auth/recover-rotate` with a new
 * passphrase, a re-wrapped `passphrase` record, a new code and its re-sealed
 * escrow. This endpoint writes nothing to the account and grants nothing on
 * its own; without the key records it hands over a string.
 *
 * Unknown, spent and expired share one `404` after identical work: the token
 * is hashed and the statement runs on every branch.
 */
export async function handleResetOpen(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<ResetOpenResponse>> {
  const fields = asFields(body);
  const resetToken = parseTokenField(fields.resetToken, 'resetToken');
  const raw = resetToken.ok ? resetToken.value : '';

  const consumed = await ctx.store.consumePasswordReset({ tokenHash: hashToken(raw), now: ctx.now() });
  if (consumed === null) return { status: 'not-found', reason: RESET_INVALID };

  // A throw here is a `500`, and correctly so: the bytes are ours, sealed with
  // our own key, so a tag failure means `SERVER_SECRET` was rotated (which has
  // already broken every verifier on the instance) rather than anything the
  // caller did. See `lib/escrow.ts`.
  const recoveryCode = openRecoveryCode({ sealed: consumed.recoveryCodeEscrow, escrowKey: ctx.escrowKey });
  // No account id, no address, and above all no code.
  ctx.logger.info('Password reset opened');
  return { status: 'ok', body: { email: consumed.email, recoveryCode } };
}

// ---------------------------------------------------------------------------
// Account read and edit
// ---------------------------------------------------------------------------

/**
 * `GET /v1/auth/account` — the caller's own view of itself. The client needs
 * it to show which account a device is signed in as, and what its AI allowance
 * has left today.
 *
 * `unauthorized` rather than `not-found` when the row is gone: the token
 * outlived the account (deleted from another device), and "log in again" is
 * the honest instruction.
 */
export async function handleGetAccount(
  input: { accountId: number },
  ctx: AuthContext,
): Promise<AuthOutcome<{ account: AccountView }>> {
  const account = await ctx.store.findAccountById(input.accountId);
  if (account === null) return { status: 'unauthorized', reason: 'account no longer exists' };
  return { status: 'ok', body: { account: await toAccountView(account, ctx) } };
}

/**
 * `PATCH /v1/auth/account` — the one thing an account owner may change about
 * themselves without a rotation.
 *
 * `displayName` MUST BE PRESENT, even as `null`. An absent key is a `400`, the
 * same rule `keyRecords` and `expectedUpdatedAt` follow: silence must never be
 * read as consent, and a PATCH that quietly did nothing because a field name
 * was misspelled is a change the client believes it made.
 *
 * There is deliberately nothing else here. `email` is the identity and moves
 * only through an operator; `role` and `dailyAiLimit` are standing an account
 * must not be able to raise for itself; everything authentication-shaped moves
 * through a rotation.
 */
export async function handleUpdateAccount(
  input: { accountId: number; body: JsonValue | undefined },
  ctx: AuthContext,
): Promise<AuthOutcome<{ account: AccountView }>> {
  const fields = asFields(input.body);
  if (fields.displayName === undefined) {
    return invalid('displayName is required (send null to clear it)');
  }
  const displayName = parseDisplayName(fields.displayName);
  if (!displayName.ok) return invalid(displayName.reason);

  const updated = await ctx.store.updateDisplayName({
    accountId: input.accountId,
    displayName: displayName.value,
  });
  if (updated === null) return { status: 'unauthorized', reason: 'account no longer exists' };
  return { status: 'ok', body: { account: await toAccountView(updated, ctx) } };
}

// ---------------------------------------------------------------------------
// Account deletion (self-serve DSAR)
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/delete` — removes the account and, by foreign-key cascade,
 * every blob, key record, reset token and usage row it owns. This is the
 * self-serve erasure path that closed the M118 privacy blocker: no support
 * ticket, no cleanup job, no window in which orphaned ciphertext outlives its
 * owner.
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
