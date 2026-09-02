/**
 * Account handler cores — the `/v1/auth/*` policy, written against injected
 * dependencies (`AuthContext`) rather than a database or a clock.
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
import type {
  AccountRecord,
  AccountStore,
  CreateAccountInput,
  KeyRecordSubmission,
  NewTokenInput,
  RedeemInviteResult,
} from './account-store.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';
import { deriveDummyKdfDescriptor } from '../lib/kdf-descriptor.js';
import { computeVerifier, verifierMatches } from '../lib/verifier.js';
import { classifyToken, computeExpiry, hashToken, TOKEN_TTL_MS, type GeneratedToken } from '../lib/tokens.js';
import type { Logger } from '../logger.js';
import {
  asFields,
  parseAuthHashField,
  parseDisplayName,
  parseHandle,
  parseKdfDescriptorField,
  parseKeyRecordSubmissions,
  parseOptionalRecoveryAuthHash,
  parseTokenField,
} from './auth-input.js';
import type { JsonObject, JsonValue } from '../lib/json.js';
import type { SignupMode } from '../protocol.js';

/** Everything the handlers need from the outside world. All of it injected — none of it imported. */
export interface AuthContext {
  store: AccountStore;
  /** `HMAC` key for verifiers, derived from `SERVER_SECRET` (`lib/server-secrets.ts`). */
  pepper: string;
  /** `HMAC` key behind deterministic dummy KDF descriptors. */
  enumerationSecret: string;
  /** How this instance treats new accounts. `'invite'` requires a token minted by the operator. */
  signupMode: SignupMode;
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
  handle: string;
  displayName: string | null;
}

export interface SessionResponse {
  account: AccountSummary;
  tokens: SessionTokens;
}

/**
 * Every outcome an auth handler can produce, in HTTP-shaped terms so the glue
 * needs no policy of its own. `reason` strings are diagnostic; clients branch
 * on the status.
 */
export type AuthOutcome<T> =
  | { status: 'ok'; body: T }
  | { status: 'created'; body: T }
  | { status: 'no-content' }
  | { status: 'invalid'; reason: string }
  | { status: 'unauthorized'; reason: string }
  | { status: 'forbidden'; reason: string }
  | { status: 'conflict'; reason: string };

/**
 * Compared against when no account exists, so an unknown handle costs the same
 * constant-time comparison as a wrong auth-hash. 64 hex characters — the exact
 * width of a real verifier, because `verifierMatches` short-circuits on a
 * length mismatch.
 */
const ABSENT_ACCOUNT_VERIFIER = '0'.repeat(64);

/** A single generic message for every login failure — never "no such account" vs "wrong passphrase". */
const LOGIN_REJECTED = 'invalid handle or passphrase';

/**
 * The ONE failure the recovery endpoints ever report. An unknown handle, an
 * account that never set a recovery code, a wrong code, and a rotation that
 * lost a race all come back as this exact string with this exact status —
 * see `handleRecover` for why the list has to be that long.
 */
const RECOVERY_REJECTED = 'invalid handle or recovery code';

function summarize(account: AccountRecord): AccountSummary {
  return {
    id: account.id,
    handle: account.handle,
    displayName: account.displayName,
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

// ---------------------------------------------------------------------------
// Pre-login: KDF descriptor
// ---------------------------------------------------------------------------

/**
 * `POST /v1/auth/kdf` — the salt and cost parameters a new device needs BEFORE
 * it can authenticate.
 *
 * POST rather than GET, for a read: a GET would put the handle in the request
 * line, and from there into access logs, proxy logs, `Referer` headers and
 * browser history. An endpoint whose entire purpose is not disclosing who has
 * an account should not scatter the identifier it was asked about.
 *
 * Unknown handles get a deterministic dummy (`lib/kdf-descriptor.ts`),
 * produced on this same code path with this same response shape. The move from
 * addresses to handles changed nothing here: the derivation is over an opaque
 * string, and a handle is one.
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
  input: { handle: JsonValue | undefined },
  ctx: AuthContext,
): Promise<AuthOutcome<{ kdfDescriptor: KdfDescriptor }>> {
  const handle = parseHandle(input.handle);
  if (!handle.ok) return invalid(handle.reason);

  const account = await ctx.store.findAccountByHandle(handle.value);
  // Computed before the branch, never inside it — see the header. Derived over
  // the CANONICAL handle, so two spellings of one unknown handle cannot be told
  // apart by their descriptors.
  const dummy = deriveDummyKdfDescriptor({ handle: handle.value, enumerationSecret: ctx.enumerationSecret });
  const kdfDescriptor = account === null ? dummy : account.kdfDescriptor;

  return { status: 'ok', body: { kdfDescriptor } };
}

// ---------------------------------------------------------------------------
// Signup
// ---------------------------------------------------------------------------

/**
 * Creates the account the way this instance's {@link SignupMode} demands.
 *
 * `'closed'` never reaches here — `handleSignup` refuses before parsing. The
 * split exists so the invite rules live in one place instead of being threaded
 * through the success path as conditionals.
 */
async function createAccountForMode(
  ctx: AuthContext,
  fields: Readonly<Record<string, JsonValue | undefined>>,
  account: CreateAccountInput,
): Promise<RedeemInviteResult> {
  if (ctx.signupMode !== 'invite') {
    const created = await ctx.store.createAccount(account);
    return created.ok ? created : { ok: false, reason: 'handle-taken' };
  }

  const inviteToken = parseTokenField(fields.inviteToken);
  // A missing or malformed token is reported as `invite-invalid`, NOT as a
  // `400`. A caller must not be able to learn what a well-formed invite looks
  // like by watching the status code change.
  if (!inviteToken.ok) return { ok: false, reason: 'invite-invalid' };

  return await ctx.store.redeemInviteAndCreateAccount({
    inviteTokenHash: hashToken(inviteToken.value),
    now: ctx.now(),
    account,
  });
}

export async function handleSignup(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  // Mode is checked BEFORE any field is parsed, and the order is deliberate: a
  // closed instance must answer the same `403` to a well-formed body and a
  // malformed one. Parsing first would leak, through the difference between a
  // `400` and a `403`, which submissions were structurally valid.
  if (ctx.signupMode === 'closed') {
    return { status: 'forbidden', reason: 'this instance is not accepting new accounts' };
  }

  const fields = asFields(body);
  const handle = parseHandle(fields.handle);
  if (!handle.ok) return invalid(handle.reason);
  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return invalid(authHash.reason);
  const kdfDescriptor = parseKdfDescriptorField(fields.kdfDescriptor);
  if (!kdfDescriptor.ok) return invalid(kdfDescriptor.reason);
  const displayName = parseDisplayName(fields.displayName);
  if (!displayName.ok) return invalid(displayName.reason);
  // The second authenticator, set at signup or never. The client shows the
  // handle and the recovery code together as one saved account card, so this
  // is the moment the user is holding both; a device that skips it creates an
  // account whose lost passphrase is terminal.
  const recoveryAuthHash = parseOptionalRecoveryAuthHash(fields.recoveryAuthHash);
  if (!recoveryAuthHash.ok) return invalid(recoveryAuthHash.reason);

  const accountInput = {
    handle: handle.value,
    displayName: displayName.value,
    verifier: computeVerifier({ authHash: authHash.value, pepper: ctx.pepper }),
    recoveryVerifier:
      recoveryAuthHash.value === null
        ? null
        : computeVerifier({ authHash: recoveryAuthHash.value, pepper: ctx.pepper }),
    kdfDescriptor: kdfDescriptor.value,
  };

  // Two paths to one result. In invite mode the account and the invite must be
  // written together, so the store owns the transaction (see
  // `redeemInviteAndCreateAccount`); this handler stays free of one, which is
  // what keeps every outcome here testable without a database.
  const created = await createAccountForMode(ctx, fields, accountInput);
  if (created.ok === false && created.reason === 'invite-invalid') {
    // ONE message for unknown, expired, already-spent and missing. Telling
    // them apart would turn a mistyped token into a probe for which tokens
    // exist, and would let a spent invite be distinguished from a fictional
    // one.
    return { status: 'forbidden', reason: 'a valid invite is required to create an account here' };
  }
  if (!created.ok) {
    // ACCEPTED ENUMERATION ORACLE, not an oversight. This 409 tells the caller
    // the handle is registered — the one place in this service that does. It
    // is unavoidable: a duplicate signup MUST fail loudly rather than silently
    // not create the account the user asked for, and with no address to write
    // to there is no channel that could carry the news instead. It matches
    // Bitwarden's behaviour, and it is bounded by the per-IP signup throttle in
    // `register-auth-routes.ts`. Every OTHER path — kdf, login — stays
    // indistinguishable.
    //
    // M181 made this leak STRICTLY LESS. What it discloses is now an opaque
    // per-server handle rather than a person's email address, so a confirmed
    // hit no longer hands anybody a way to contact, correlate or phish the
    // account holder.
    //
    // In INVITE mode this 409 is reachable only by someone holding a valid
    // invite, and it does NOT consume it (see
    // `AccountStore.redeemInviteAndCreateAccount`) — so one invite holder can
    // probe many handles. That widening is accepted and bounded by the same
    // per-IP throttle; invite mode still exposes the oracle to strictly fewer
    // people than open mode does.
    //
    // Full reasoning: SECURITY.md and PROTOCOL.md §5.8.
    return { status: 'conflict', reason: 'an account already exists for this handle' };
  }

  const account = created.account;
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
  const handle = parseHandle(fields.handle);
  if (!handle.ok) return invalid(handle.reason);
  const authHash = parseAuthHashField(fields.authHash);
  if (!authHash.ok) return invalid(authHash.reason);

  const account = await ctx.store.findAccountByHandle(handle.value);
  // Computed and compared unconditionally: an unknown handle must not return
  // faster than a wrong passphrase.
  const candidate = computeVerifier({ authHash: authHash.value, pepper: ctx.pepper });
  const matches = verifierMatches({ candidate, stored: account?.verifier ?? ABSENT_ACCOUNT_VERIFIER });

  if (account === null || !matches) {
    return { status: 'unauthorized', reason: LOGIN_REJECTED };
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
// Change-passphrase
// ---------------------------------------------------------------------------

/**
 * WHAT USED TO BE HERE, AND WHY IT IS NOT (M181).
 *
 * `handleVerifyEmail`, `handleRequestReset` and `handleResetCredential` stood
 * between `handleLogout` and the rotation below. All three are gone with the
 * mailer, and the reset flow is the one worth explaining: it mailed a link
 * whose holder could replace the account's verifier. On a zero-knowledge
 * service that is an account-TAKEOVER path that returns no recovery — the DEK
 * is wrapped under a passphrase-KEK and a recovery-KEK the server never sees,
 * so whoever redeemed the link got a login to a diary they still could not
 * read, and could destroy the real owner's access on the way.
 *
 * The recovery code, which the user already holds and the server never sees,
 * becomes the second authenticator instead (M181 spec 02). It joins at
 * `rotateCredential` below: the shape is already "prove something, then move
 * the verifier and the key records together in one transaction", and only the
 * proof differs.
 */

interface RotationFields {
  authHash: string;
  kdfDescriptor: KdfDescriptor;
  keyRecords: KeyRecordSubmission[];
}

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

type ParseRotationResult = { ok: true; value: RotationFields } | { ok: false; reason: string };

/**
 * `POST /v1/auth/change-passphrase` — rotation for a user who still knows
 * their current passphrase, and since M181 the only rotation this service has
 * until the recovery-code path lands (spec 02).
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
// Recovery-code authentication (M181 spec 02)
// ---------------------------------------------------------------------------

/**
 * Checks a recovery proof against an account, in constant time whatever the
 * account's state.
 *
 * THREE DIFFERENT "NO" ANSWERS COLLAPSE INTO ONE `null`, and all three cost
 * the same work: the handle is unknown, the account exists but never set a
 * recovery code, or the code is wrong. Each is compared against a
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
  input: { handle: string; recoveryAuthHash: string },
  ctx: AuthContext,
): Promise<{ account: AccountRecord; recoveryVerifier: string } | null> {
  const account = await ctx.store.findAccountByHandle(input.handle);
  const candidate = computeVerifier({ authHash: input.recoveryAuthHash, pepper: ctx.pepper });
  const matches = verifierMatches({ candidate, stored: account?.recoveryVerifier ?? ABSENT_ACCOUNT_VERIFIER });

  if (account === null || account.recoveryVerifier === null || !matches) return null;
  return { account, recoveryVerifier: account.recoveryVerifier };
}

/**
 * `POST /v1/auth/recover` — log in with the recovery code instead of the
 * passphrase.
 *
 * The recovery code is the SECOND authenticator, and it is the only one left
 * once a passphrase is lost. It replaced a mailed reset link, which on a
 * zero-knowledge service was an account-TAKEOVER path that returned no
 * recovery: the link holder got a login to a diary they still could not read,
 * and could lock the real owner out on the way. The code, unlike the link, is
 * held by the user and never by the server — so it both authenticates AND
 * unwraps, which is the whole difference.
 *
 * What comes back is an ordinary session. It is deliberately NOT a
 * lesser one: the holder of the recovery code is the account owner by
 * construction, and a restricted "recovery mode" token would only add a
 * second authorization surface with no property the code does not already
 * carry.
 *
 * Throttled per IP and handle in `register-auth-routes.ts`. That throttle is
 * not decoration: this endpoint accepts a guess at a value the user has
 * written on paper.
 */
export async function handleRecover(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const fields = asFields(body);
  const handle = parseHandle(fields.handle);
  if (!handle.ok) return invalid(handle.reason);
  const recoveryAuthHash = parseAuthHashField(fields.recoveryAuthHash, 'recoveryAuthHash');
  if (!recoveryAuthHash.ok) return invalid(recoveryAuthHash.reason);

  const proof = await authenticateRecoveryCode({ handle: handle.value, recoveryAuthHash: recoveryAuthHash.value }, ctx);
  if (proof === null) return { status: 'unauthorized', reason: RECOVERY_REJECTED };

  const session = mintSession(ctx, { accountId: proof.account.id, familyId: ctx.mintFamilyId() });
  await ctx.store.insertTokens(session.rows);
  ctx.logger.info('Account recovered with a recovery code', { accountId: proof.account.id });
  return { status: 'ok', body: { account: summarize(proof.account), tokens: session.tokens } };
}

/**
 * `POST /v1/auth/recover-rotate` — prove the recovery code, then set a new
 * passphrase.
 *
 * THE PROOF TRAVELS IN THIS REQUEST rather than in a session token minted by
 * `handleRecover`, so the code is checked in the same call that writes. A
 * two-step flow would let a session outlive the moment the user held the
 * card, and would make the store's compare-and-swap guard a check against
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
 * ROTATING THE RECOVERY CODE IS ALL-OR-NOTHING for the same reason: a new
 * recovery verifier without a re-wrapped `recovery` record leaves a code that
 * authenticates and then unwraps nothing, and a re-wrapped `recovery` record
 * without the new verifier leaves a code that unwraps and can no longer log
 * in. Both halves, or neither.
 */
export async function handleRecoverRotate(
  body: JsonValue | undefined,
  ctx: AuthContext,
): Promise<AuthOutcome<SessionResponse>> {
  const fields = asFields(body);
  const handle = parseHandle(fields.handle);
  if (!handle.ok) return invalid(handle.reason);
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

  const proof = await authenticateRecoveryCode({ handle: handle.value, recoveryAuthHash: recoveryAuthHash.value }, ctx);
  if (proof === null) return { status: 'unauthorized', reason: RECOVERY_REJECTED };

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
  return { status: 'ok', body: { account: summarize(proof.account), tokens: session.tokens } };
}

// ---------------------------------------------------------------------------
// Account read
// ---------------------------------------------------------------------------

/**
 * `GET /v1/auth/account` — the caller's own summary. The client needs it to
 * show which account a device is signed in as without asking the user.
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
