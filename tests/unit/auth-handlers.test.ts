/**
 * Behaviour tests for the account handler cores. Every security property this
 * service claims is asserted here, DB-free, against `fake-account-store.ts`:
 *
 *  - unknown emails get a stable, real-shaped KDF descriptor (no enumeration
 *    oracle on the one endpoint that must answer before authentication)
 *  - login rejects unknown accounts and wrong hashes identically
 *  - refresh rotates, and REUSING a rotated refresh token kills the family
 *  - both credential-rotation paths revoke every outstanding session
 *  - deletion requires re-authentication and takes the sync data with it
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleChangePassphrase,
  handleDeleteAccount,
  handleGetKdfDescriptor,
  handleLogin,
  handleLogout,
  handleRefresh,
  handleRequestReset,
  handleResetCredential,
  handleSignup,
  handleVerifyEmail,
  resolveAccessToken,
  type SessionResponse,
  type SessionTokens,
} from '../../src/accounts/auth-handlers.js';
import { REFRESH_TOKEN_TTL_MS, ACCESS_TOKEN_TTL_MS, AUTH_RESET_TTL_MS } from '../../src/lib/tokens.js';
import type { JsonObject } from '../../src/lib/json.js';
import {
  createAuthFixture,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleWrappedDek,
  type AuthFixture,
} from './auth-context-fixture.js';

const EMAIL = 'person@example.test';
const AUTH_HASH = sampleAuthHash(11);
const OTHER_AUTH_HASH = sampleAuthHash(22);

function signupBody(overrides: JsonObject = {}) {
  return {
    email: EMAIL,
    authHash: AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(),
    displayName: 'A Person',
    ...overrides,
  };
}

/** Signs up and returns the created session, failing the test loudly if signup did not succeed. */
async function signUp(fixture: AuthFixture): Promise<SessionResponse> {
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'created');
  if (outcome.status !== 'created') throw new Error('unreachable');
  return outcome.body;
}

function requireTokens(session: SessionResponse): SessionTokens {
  assert.notEqual(session.tokens, null);
  if (session.tokens === null) throw new Error('unreachable');
  return session.tokens;
}

// ── KDF descriptor / enumeration ───────────────────────────────────────────

test('kdf descriptor for an unknown email is stable across calls', async () => {
  const fixture = createAuthFixture();
  const first = await handleGetKdfDescriptor({ email: 'nobody@example.test' }, fixture.ctx);
  const second = await handleGetKdfDescriptor({ email: 'NOBODY@Example.test' }, fixture.ctx);

  assert.equal(first.status, 'ok');
  assert.equal(second.status, 'ok');
  if (first.status !== 'ok' || second.status !== 'ok') throw new Error('unreachable');
  // Stability is the property: a random dummy would be distinguishable from a
  // real descriptor by simply asking twice. Case-insensitivity matters for the
  // same reason.
  assert.deepEqual(first.body.kdfDescriptor, second.body.kdfDescriptor);
});

test('dummy and real kdf descriptors are structurally indistinguishable', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const real = await handleGetKdfDescriptor({ email: EMAIL }, fixture.ctx);
  const dummy = await handleGetKdfDescriptor({ email: 'nobody@example.test' }, fixture.ctx);
  assert.equal(real.status, 'ok');
  assert.equal(dummy.status, 'ok');
  if (real.status !== 'ok' || dummy.status !== 'ok') throw new Error('unreachable');

  assert.deepEqual(Object.keys(real.body.kdfDescriptor).toSorted(), Object.keys(dummy.body.kdfDescriptor).toSorted());
  assert.equal(
    Buffer.from(real.body.kdfDescriptor.salt, 'base64').byteLength,
    Buffer.from(dummy.body.kdfDescriptor.salt, 'base64').byteLength,
  );
});

test('a different enumeration secret yields a different dummy for the same email', async () => {
  const a = createAuthFixture();
  const b = createAuthFixture();
  b.ctx.enumerationSecret = 'a completely different secret';

  const fromA = await handleGetKdfDescriptor({ email: 'nobody@example.test' }, a.ctx);
  const fromB = await handleGetKdfDescriptor({ email: 'nobody@example.test' }, b.ctx);
  if (fromA.status !== 'ok' || fromB.status !== 'ok') throw new Error('unreachable');
  assert.notEqual(fromA.body.kdfDescriptor.salt, fromB.body.kdfDescriptor.salt);
});

test('a malformed email is a 400, not a dummy descriptor', async () => {
  const fixture = createAuthFixture();
  const outcome = await handleGetKdfDescriptor({ email: 'not-an-email' }, fixture.ctx);
  assert.equal(outcome.status, 'invalid');
});

// ── Signup ─────────────────────────────────────────────────────────────────

test('signup creates an account, sends verification mail and returns a session', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);

  assert.equal(session.account.email, EMAIL);
  assert.equal(session.account.emailVerified, false);
  assert.equal(fixture.sentMail.length, 1);
  assert.match(fixture.sentMail[0]?.text ?? '', /https:\/\/app\.example\.test\/verify-email\?token=/);
  requireTokens(session);
});

test('signup is refused when SIGNUPS_OPEN is off', async () => {
  const fixture = createAuthFixture({ signupsOpen: false });
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
});

test('signup withholds the session when email verification is required', async () => {
  const fixture = createAuthFixture({ requireEmailVerification: true });
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'created');
  if (outcome.status !== 'created') throw new Error('unreachable');
  // Otherwise the requirement would be bypassed by never leaving the tab.
  assert.equal(outcome.body.tokens, null);
});

test('a duplicate signup is a conflict', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'conflict');
});

test('signup succeeds even when the verification mail fails to send', async () => {
  const fixture = createAuthFixture();
  fixture.failNextMail();
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  // Fail-soft: a dead relay must not turn a committed account into a 500.
  assert.equal(outcome.status, 'created');
});

test('signup rejects a short auth hash', async () => {
  const fixture = createAuthFixture();
  const outcome = await handleSignup(signupBody({ authHash: Buffer.alloc(8, 1).toString('base64') }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
});

test('signup rejects a descriptor with a wrong-length salt', async () => {
  const fixture = createAuthFixture();
  const outcome = await handleSignup(
    signupBody({
      kdfDescriptor: {
        salt: Buffer.alloc(4, 1).toString('base64'),
        params: { memorySizeKib: 1, iterations: 1, parallelism: 1 },
      },
    }),
    fixture.ctx,
  );
  assert.equal(outcome.status, 'invalid');
});

// ── Login ──────────────────────────────────────────────────────────────────

test('login succeeds with the right auth hash', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  const outcome = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
});

test('login rejects an unknown account and a wrong hash with the same response', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const unknown = await handleLogin({ email: 'nobody@example.test', authHash: AUTH_HASH }, fixture.ctx);
  const wrong = await handleLogin({ email: EMAIL, authHash: OTHER_AUTH_HASH }, fixture.ctx);

  assert.equal(unknown.status, 'unauthorized');
  assert.equal(wrong.status, 'unauthorized');
  if (unknown.status !== 'unauthorized' || wrong.status !== 'unauthorized') throw new Error('unreachable');
  // Identical text: the message must not be the thing that says which one it was.
  assert.equal(unknown.reason, wrong.reason);
});

test('login is refused for an unverified account when verification is required', async () => {
  const fixture = createAuthFixture({ requireEmailVerification: true });
  await handleSignup(signupBody(), fixture.ctx);
  const outcome = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
});

test('verifying the emailed token unblocks login', async () => {
  const fixture = createAuthFixture({ requireEmailVerification: true });
  await handleSignup(signupBody(), fixture.ctx);

  const link = fixture.sentMail[0]?.text ?? '';
  const token = /token=([^\s]+)/.exec(link)?.[1];
  assert.ok(token);

  assert.equal((await handleVerifyEmail({ token }, fixture.ctx)).status, 'ok');
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
  // Single use.
  assert.equal((await handleVerifyEmail({ token }, fixture.ctx)).status, 'invalid');
});

// ── Tokens ─────────────────────────────────────────────────────────────────

test('an access token resolves to its account, and stops after expiry', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);
  const tokens = requireTokens(session);

  assert.notEqual(await resolveAccessToken(tokens.accessToken, fixture.ctx), null);
  fixture.advance(ACCESS_TOKEN_TTL_MS + 1000);
  assert.equal(await resolveAccessToken(tokens.accessToken, fixture.ctx), null);
});

test('refresh rotates the pair and invalidates the presented token', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);
  const first = requireTokens(session);

  const rotated = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  assert.equal(rotated.status, 'ok');
  if (rotated.status !== 'ok') throw new Error('unreachable');
  assert.notEqual(rotated.body.tokens.refreshToken, first.refreshToken);
  assert.notEqual(await resolveAccessToken(rotated.body.tokens.accessToken, fixture.ctx), null);
});

test('reusing an already-rotated refresh token revokes the whole family', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);
  const first = requireTokens(session);

  const rotated = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  if (rotated.status !== 'ok') throw new Error('unreachable');

  // A thief replays the token the real client already spent.
  const replay = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  assert.equal(replay.status, 'unauthorized');

  // Both parties are logged out — the correct response, because the
  // alternative leaves the thief with a working session.
  assert.equal(await resolveAccessToken(rotated.body.tokens.accessToken, fixture.ctx), null);
  assert.equal(
    (await handleRefresh({ refreshToken: rotated.body.tokens.refreshToken }, fixture.ctx)).status,
    'unauthorized',
  );
});

test('an expired refresh token is rejected without revoking anything', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);
  const tokens = requireTokens(session);

  fixture.advance(REFRESH_TOKEN_TTL_MS + 1000);
  const outcome = await handleRefresh({ refreshToken: tokens.refreshToken }, fixture.ctx);
  assert.equal(outcome.status, 'unauthorized');
  if (outcome.status !== 'unauthorized') throw new Error('unreachable');
  assert.match(outcome.reason, /expired/);
});

test('logout revokes the caller family, leaving other devices signed in', async () => {
  const fixture = createAuthFixture();
  const deviceOne = requireTokens(await signUp(fixture));
  const loginTwo = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  if (loginTwo.status !== 'ok') throw new Error('unreachable');
  const deviceTwo = requireTokens(loginTwo.body);

  const session = await resolveAccessToken(deviceOne.accessToken, fixture.ctx);
  assert.ok(session);
  assert.equal((await handleLogout(session, fixture.ctx)).status, 'no-content');

  assert.equal(await resolveAccessToken(deviceOne.accessToken, fixture.ctx), null);
  assert.notEqual(await resolveAccessToken(deviceTwo.accessToken, fixture.ctx), null);
});

// ── Change passphrase ──────────────────────────────────────────────────────

test('change-passphrase swaps the verifier, stores the re-wrapped DEK and logs other devices out', async () => {
  const fixture = createAuthFixture();
  const first = requireTokens(await signUp(fixture));
  const secondLogin = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  if (secondLogin.status !== 'ok') throw new Error('unreachable');
  const otherDevice = requireTokens(secondLogin.body);

  const session = await resolveAccessToken(first.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleChangePassphrase(
    {
      accountId: session.accountId,
      body: {
        currentAuthHash: AUTH_HASH,
        newAuthHash: OTHER_AUTH_HASH,
        kdfDescriptor: sampleKdfDescriptor(2),
        keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek() }],
      },
    },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');

  // Old credential dead, new credential live.
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'unauthorized');
  assert.equal((await handleLogin({ email: EMAIL, authHash: OTHER_AUTH_HASH }, fixture.ctx)).status, 'ok');

  // Every prior session gone; the caller's fresh pair works.
  assert.equal(await resolveAccessToken(otherDevice.accessToken, fixture.ctx), null);
  assert.equal(await resolveAccessToken(first.accessToken, fixture.ctx), null);
  assert.notEqual(await resolveAccessToken(outcome.body.tokens.accessToken, fixture.ctx), null);

  assert.equal(fixture.store.keyRecordsFor(session.accountId).get('passphrase')?.kind, 'passphrase');
});

test('change-passphrase rejects a wrong current passphrase and changes nothing', async () => {
  const fixture = createAuthFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolveAccessToken(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleChangePassphrase(
    {
      accountId: session.accountId,
      body: {
        currentAuthHash: OTHER_AUTH_HASH,
        newAuthHash: sampleAuthHash(33),
        kdfDescriptor: sampleKdfDescriptor(3),
        keyRecords: [],
      },
    },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'unauthorized');
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('a rotation with an absent keyRecords field is a 400, never an implicit empty list', async () => {
  const fixture = createAuthFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolveAccessToken(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleChangePassphrase(
    {
      accountId: session.accountId,
      body: { currentAuthHash: AUTH_HASH, newAuthHash: OTHER_AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(4) },
    },
    fixture.ctx,
  );
  // Silence must never read as consent on a path that can strand data.
  assert.equal(outcome.status, 'invalid');
});

// ── Reset ──────────────────────────────────────────────────────────────────

test('request-reset answers 202 for a known and an unknown address alike', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  fixture.sentMail.length = 0;

  assert.equal((await handleRequestReset({ email: EMAIL }, fixture.ctx)).status, 'accepted');
  assert.equal((await handleRequestReset({ email: 'nobody@example.test' }, fixture.ctx)).status, 'accepted');
  // Only the known address produced mail — and only the inbox owner sees that.
  assert.equal(fixture.sentMail.length, 1);
});

test('the reset email states the data-loss consequence before the user clicks', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  fixture.sentMail.length = 0;
  await handleRequestReset({ email: EMAIL }, fixture.ctx);

  const body = fixture.sentMail[0]?.text ?? '';
  assert.match(body, /recovery code/i);
  assert.match(body, /permanently unreadable/i);
});

test('reset restores login, revokes every session and is single-use', async () => {
  const fixture = createAuthFixture();
  const original = requireTokens(await signUp(fixture));
  fixture.sentMail.length = 0;
  await handleRequestReset({ email: EMAIL }, fixture.ctx);
  const token = /token=([^\s]+)/.exec(fixture.sentMail[0]?.text ?? '')?.[1];
  assert.ok(token);

  const outcome = await handleResetCredential(
    {
      token,
      authHash: OTHER_AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(5),
      keyRecords: [{ kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(3) }],
    },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');

  assert.equal(await resolveAccessToken(original.accessToken, fixture.ctx), null);
  assert.notEqual(await resolveAccessToken(outcome.body.tokens.accessToken, fixture.ctx), null);
  assert.equal((await handleLogin({ email: EMAIL, authHash: OTHER_AUTH_HASH }, fixture.ctx)).status, 'ok');

  const replay = await handleResetCredential(
    { token, authHash: sampleAuthHash(44), kdfDescriptor: sampleKdfDescriptor(6), keyRecords: [] },
    fixture.ctx,
  );
  assert.equal(replay.status, 'invalid');
});

test('an expired reset token is refused', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  fixture.sentMail.length = 0;
  await handleRequestReset({ email: EMAIL }, fixture.ctx);
  const token = /token=([^\s]+)/.exec(fixture.sentMail[0]?.text ?? '')?.[1];
  assert.ok(token);

  fixture.advance(AUTH_RESET_TTL_MS + 1000);
  const outcome = await handleResetCredential(
    { token, authHash: OTHER_AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(7), keyRecords: [] },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'invalid');
});

test('requesting a second reset link cancels the first', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  fixture.sentMail.length = 0;

  await handleRequestReset({ email: EMAIL }, fixture.ctx);
  const firstToken = /token=([^\s]+)/.exec(fixture.sentMail[0]?.text ?? '')?.[1];
  await handleRequestReset({ email: EMAIL }, fixture.ctx);
  const secondToken = /token=([^\s]+)/.exec(fixture.sentMail[1]?.text ?? '')?.[1];
  assert.ok(firstToken);
  assert.ok(secondToken);

  const stale = await handleResetCredential(
    { token: firstToken, authHash: OTHER_AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(8), keyRecords: [] },
    fixture.ctx,
  );
  assert.equal(stale.status, 'invalid');

  const fresh = await handleResetCredential(
    { token: secondToken, authHash: OTHER_AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(8), keyRecords: [] },
    fixture.ctx,
  );
  assert.equal(fresh.status, 'ok');
});

// ── Deletion ───────────────────────────────────────────────────────────────

test('deletion requires re-authentication', async () => {
  const fixture = createAuthFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolveAccessToken(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const refused = await handleDeleteAccount(
    { accountId: session.accountId, body: { authHash: OTHER_AUTH_HASH } },
    fixture.ctx,
  );
  assert.equal(refused.status, 'unauthorized');
  assert.equal(fixture.store.hasAccount(session.accountId), true);
});

test('deletion removes the account and its sync data', async () => {
  const fixture = createAuthFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolveAccessToken(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleDeleteAccount(
    { accountId: session.accountId, body: { authHash: AUTH_HASH } },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'no-content');
  assert.equal(fixture.store.hasAccount(session.accountId), false);
  assert.equal(fixture.store.keyRecordsFor(session.accountId).size, 0);
  assert.equal(await resolveAccessToken(tokens.accessToken, fixture.ctx), null);
});
