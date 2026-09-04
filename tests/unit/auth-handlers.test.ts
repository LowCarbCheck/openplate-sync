/**
 * Behaviour tests for the account handler cores. Every security property this
 * service claims is asserted here, DB-free, against `fake-account-store.ts`:
 *
 *  - unknown addresses get a stable, real-shaped KDF descriptor (no
 *    enumeration oracle on the one endpoint that must answer before
 *    authentication)
 *  - login rejects unknown accounts and wrong hashes identically
 *  - refresh rotates, and REUSING a rotated refresh token kills the family
 *  - both credential-rotation paths revoke every outstanding session
 *  - deletion requires re-authentication and takes the sync data with it
 *  - the recovery code authenticates, and an unknown address, a wrong code and
 *    a lost race are one indistinguishable failure
 *  - a suspended account is refused everywhere, with one machine-shaped reason
 *
 * `signup-with-invite.test.ts` and `password-reset.test.ts` carry the two
 * flows M192 added; this file keeps the properties that predate them.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleChangePassphrase,
  handleDeleteAccount,
  handleGetAccount,
  handleGetKdfDescriptor,
  handleLogin,
  handleLogout,
  handleRecover,
  handleRecoverRotate,
  handleRefresh,
  handleSignup,
  handleUpdateAccount,
  resolveAccessToken,
  type AuthContext,
  type ResolvedSession,
  type SessionResponse,
  type SessionTokens,
} from '../../src/accounts/auth-handlers.js';
import { REFRESH_TOKEN_TTL_MS, ACCESS_TOKEN_TTL_MS, hashToken } from '../../src/lib/tokens.js';
import type { JsonObject } from '../../src/lib/json.js';
import {
  createAuthFixture,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  type AuthFixture,
} from './auth-context-fixture.js';

const EMAIL = 'anna@example.org';
const OTHER_EMAIL = 'boris@example.org';
const AUTH_HASH = sampleAuthHash(11);
const OTHER_AUTH_HASH = sampleAuthHash(22);
const RECOVERY_AUTH_HASH = sampleAuthHash(33);
const NEW_RECOVERY_AUTH_HASH = sampleAuthHash(44);
const INVITE_TOKEN = 'si_invite-token-for-tests';

/** Both key records, which every signup must now carry. */
function bothKeyRecords() {
  return [
    { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
    { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
  ];
}

function signupBody(overrides: JsonObject = {}) {
  return {
    inviteToken: INVITE_TOKEN,
    authHash: AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(),
    displayName: 'A Person',
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    recoveryCode: sampleRecoveryCode(),
    keyRecords: bothKeyRecords(),
    ...overrides,
  };
}

/** The body `POST /v1/auth/recover-rotate` takes, minus whatever a test is testing the absence of. */
function recoverRotateBody(overrides: JsonObject = {}) {
  return {
    email: EMAIL,
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    newAuthHash: OTHER_AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(2),
    keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(21) }],
    ...overrides,
  };
}

/**
 * A fixture with one live invite already minted, because there is no other
 * door onto the service.
 */
function inviteFixture(options: { expiresInMs?: number; email?: string; token?: string } = {}): AuthFixture {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(options.token ?? INVITE_TOKEN),
    email: options.email ?? EMAIL,
    expiresAt: new Date(fixture.now().getTime() + (options.expiresInMs ?? 7 * 24 * 60 * 60 * 1000)),
  });
  return fixture;
}

/** Signs up and returns the created session, failing the test loudly if signup did not succeed. */
async function signUp(fixture: AuthFixture): Promise<SessionResponse> {
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'created', `signup failed: ${JSON.stringify(outcome)}`);
  if (outcome.status !== 'created') throw new Error('unreachable');
  return outcome.body;
}

function requireTokens(session: SessionResponse): SessionTokens {
  return session.tokens;
}

/** The resolved session, or `null` — the shape the tests below assert against. */
async function resolvedSession(rawToken: string, ctx: AuthContext): Promise<ResolvedSession | null> {
  const resolution = await resolveAccessToken(rawToken, ctx);
  return resolution.status === 'valid' ? resolution.session : null;
}

// ── KDF descriptor / enumeration ───────────────────────────────────────────

test('kdf descriptor for an unknown address is stable across calls', async () => {
  const fixture = createAuthFixture();
  const first = await handleGetKdfDescriptor({ email: 'nobody@example.org' }, fixture.ctx);
  const second = await handleGetKdfDescriptor({ email: '  NOBODY@Example.ORG ' }, fixture.ctx);

  assert.equal(first.status, 'ok');
  assert.equal(second.status, 'ok');
  if (first.status !== 'ok' || second.status !== 'ok') throw new Error('unreachable');
  // Stability is the property: a random dummy would be distinguishable from a
  // real descriptor by simply asking twice. Canonicalisation matters for the
  // same reason — the dummy is derived over the NORMALIZED address, so casing
  // and stray whitespace cannot become an oracle of their own.
  assert.deepEqual(first.body.kdfDescriptor, second.body.kdfDescriptor);
});

test('dummy and real kdf descriptors are structurally indistinguishable', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const real = await handleGetKdfDescriptor({ email: EMAIL }, fixture.ctx);
  const dummy = await handleGetKdfDescriptor({ email: 'nobody@example.org' }, fixture.ctx);
  assert.equal(real.status, 'ok');
  assert.equal(dummy.status, 'ok');
  if (real.status !== 'ok' || dummy.status !== 'ok') throw new Error('unreachable');

  assert.deepEqual(Object.keys(real.body.kdfDescriptor).toSorted(), Object.keys(dummy.body.kdfDescriptor).toSorted());
  assert.equal(
    Buffer.from(real.body.kdfDescriptor.salt, 'base64').byteLength,
    Buffer.from(dummy.body.kdfDescriptor.salt, 'base64').byteLength,
  );
});

test('a different enumeration secret yields a different dummy for the same address', async () => {
  const a = createAuthFixture();
  const b = createAuthFixture();
  b.ctx.enumerationSecret = 'a completely different secret';

  const fromA = await handleGetKdfDescriptor({ email: 'nobody@example.org' }, a.ctx);
  const fromB = await handleGetKdfDescriptor({ email: 'nobody@example.org' }, b.ctx);
  if (fromA.status !== 'ok' || fromB.status !== 'ok') throw new Error('unreachable');
  assert.notEqual(fromA.body.kdfDescriptor.salt, fromB.body.kdfDescriptor.salt);
});

test('a malformed address is a 400, not a dummy descriptor', async () => {
  const fixture = createAuthFixture();
  assert.equal((await handleGetKdfDescriptor({ email: '' }, fixture.ctx)).status, 'invalid');
  assert.equal((await handleGetKdfDescriptor({ email: 42 }, fixture.ctx)).status, 'invalid');
  // The `@`-rejection of M181 is INVERTED: an address is now the identity, and
  // a string with no `@` is what gets refused.
  assert.equal((await handleGetKdfDescriptor({ email: 'bright-otter-42' }, fixture.ctx)).status, 'invalid');
});

// ── Signup ─────────────────────────────────────────────────────────────────

test('signup creates an account and returns a session immediately', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);

  // The address came from the INVITE, and the body never named one.
  assert.equal(session.account.email, EMAIL);
  assert.equal(session.account.role, 'member');
  assert.equal(session.account.dailyAiLimit, 0);
  assert.equal(session.account.aiUsedToday, 0);
  assert.equal(session.account.suspendedAt, null);
  requireTokens(session);
});

test('the account takes its email, role and allowance from the invite, never from the body', async () => {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(INVITE_TOKEN),
    email: 'invited@example.org',
    role: 'admin',
    dailyAiLimit: 200,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });

  // The body claims a different address, a different role and a bigger
  // allowance. All three are ignored: the invite is what grants standing.
  const outcome = await handleSignup(
    signupBody({ email: 'attacker@example.org', role: 'admin', dailyAiLimit: 9999 }),
    fixture.ctx,
  );
  assert.equal(outcome.status, 'created');
  if (outcome.status !== 'created') throw new Error('unreachable');
  assert.equal(outcome.body.account.email, 'invited@example.org');
  assert.equal(outcome.body.account.role, 'admin');
  assert.equal(outcome.body.account.dailyAiLimit, 200);
});

test('an address is canonicalised, so casing and Unicode form cannot fork an account', async () => {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(INVITE_TOKEN),
    email: EMAIL,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });
  await signUp(fixture);

  // NFKC folds the fullwidth Latin letters; lowercasing folds the casing; the
  // trim folds the pasted whitespace. All three must reach the SAME account.
  assert.equal((await handleLogin({ email: 'ａnna@example.org', authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.equal((await handleLogin({ email: '  ANNA@Example.ORG ', authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('signup is refused without a valid invite, and every bad invite reads alike', async () => {
  // A caller who can tell these apart can probe which tokens exist, and can
  // learn that a token WAS real before it was spent. `gi_…` is a token from the
  // retired gateway: it is stopped by the shape gate before any lookup, and the
  // whole point of this case is that the caller cannot tell that happened.
  const reasons = new Set<string>();
  for (const inviteToken of [undefined, '', 'never-minted', 'gi_a-gateway-invite-posted-here', 12345]) {
    const fixture = inviteFixture({ expiresInMs: 1000 });
    fixture.advance(2000);
    const body = inviteToken === undefined ? signupBody({ inviteToken: undefined }) : signupBody({ inviteToken });
    const outcome = await handleSignup(body, fixture.ctx);
    assert.equal(outcome.status, 'forbidden', `invite ${String(inviteToken)}`);
    if (outcome.status !== 'forbidden') throw new Error('unreachable');
    reasons.add(outcome.reason);
  }
  assert.equal(reasons.size, 1, `expected one shared rejection, got: ${[...reasons].join(' | ')}`);
  assert.equal([...reasons][0], 'invite-invalid');
});

test('a revoked invite is refused, and reads exactly as an expired one', async () => {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(INVITE_TOKEN),
    email: EMAIL,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
    revokedAt: fixture.now(),
  });
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
  if (outcome.status !== 'forbidden') throw new Error('unreachable');
  assert.equal(outcome.reason, 'invite-invalid');
});

test('one invite cannot create a second account', async () => {
  const fixture = inviteFixture();
  const first = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(first.status, 'created');

  const second = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(second.status, 'forbidden');
});

test('a signup for an address that already has an account leaves the invite redeemable', async () => {
  const fixture = inviteFixture();
  // Burn the address first, using a SECOND invite for the same person.
  fixture.store.seedInvite({
    tokenHash: hashToken('si_first-invite'),
    email: EMAIL,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });
  const first = await handleSignup(signupBody({ inviteToken: 'si_first-invite' }), fixture.ctx);
  assert.equal(first.status, 'created');

  const duplicate = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(duplicate.status, 'conflict');
  // The 409 must cost the holder nothing.
  assert.equal(fixture.store.inviteIsRedeemable(hashToken(INVITE_TOKEN)), true);
});

test('signup requires a recovery code AND both key records', async () => {
  // The client no longer SHOWS the code, so an account created without an
  // escrow is one no mailed reset can ever restore, and its owner was never
  // warned. Each of these used to be legitimate; none is now.
  for (const overrides of [
    { recoveryAuthHash: null },
    { recoveryCode: undefined },
    { recoveryCode: 'not-base32-and-too-short' },
    { keyRecords: [] },
    { keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() }] },
    { keyRecords: [{ kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) }] },
  ]) {
    const fixture = inviteFixture();
    const outcome = await handleSignup(signupBody(overrides), fixture.ctx);
    assert.equal(outcome.status, 'invalid', `expected a 400 for ${JSON.stringify(overrides)}`);
  }
});

test('the sealed escrow is never the plaintext code, and both key records land', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);

  const sealed = fixture.store.escrowFor(session.account.id);
  assert.ok(sealed !== null, 'signup must write an escrow');
  const canonical = sampleRecoveryCode().replaceAll('-', '');
  assert.ok(!sealed.toString('utf8').includes(canonical), 'the stored bytes must not contain the code');
  assert.ok(!sealed.toString('base64').includes(canonical), 'nor in any encoding of them');

  const records = fixture.store.keyRecordsFor(session.account.id);
  assert.equal(records.get('passphrase')?.kind, 'passphrase');
  assert.equal(records.get('recovery')?.kind, 'recovery');
});

test('signup rejects a short auth hash', async () => {
  const fixture = inviteFixture();
  const outcome = await handleSignup(signupBody({ authHash: Buffer.alloc(8, 1).toString('base64') }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
});

test('signup rejects a descriptor with a wrong-length salt', async () => {
  const fixture = inviteFixture();
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
  const fixture = inviteFixture();
  await signUp(fixture);
  const outcome = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
});

test('login rejects an unknown account and a wrong hash with the same response', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const unknown = await handleLogin({ email: 'nobody@example.org', authHash: AUTH_HASH }, fixture.ctx);
  const wrong = await handleLogin({ email: EMAIL, authHash: OTHER_AUTH_HASH }, fixture.ctx);

  assert.equal(unknown.status, 'unauthorized');
  assert.equal(wrong.status, 'unauthorized');
  if (unknown.status !== 'unauthorized' || wrong.status !== 'unauthorized') throw new Error('unreachable');
  // Identical text: the message must not be the thing that says which one it was.
  assert.equal(unknown.reason, wrong.reason);
});

// ── Suspension ─────────────────────────────────────────────────────────────

test('a suspended account is refused at login, at refresh, at the bearer gate and at recovery', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const tokens = requireTokens(session);

  await fixture.store.suspendAccount({ accountId: session.account.id, suspendedAt: fixture.now() });

  const login = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  assert.equal(login.status, 'forbidden');
  if (login.status !== 'forbidden') throw new Error('unreachable');
  assert.equal(login.reason, 'account-suspended');

  // Suspending revoked the sessions, so this token resolves as INVALID rather
  // than as suspended. That is the store's guarantee, and it is why a
  // suspension means "now" rather than "in a quarter of an hour".
  assert.equal(await resolvedSession(tokens.accessToken, fixture.ctx), null);

  // A fresh session on the suspended account resolves as suspended, which is
  // what makes the bearer gate answer 403 rather than 401.
  await fixture.store.insertTokens([
    {
      accountId: session.account.id,
      kind: 'access',
      tokenHash: hashToken('a-live-token'),
      familyId: 'family-x',
      expiresAt: new Date(fixture.now().getTime() + 60_000),
    },
  ]);
  assert.equal((await resolveAccessToken('a-live-token', fixture.ctx)).status, 'suspended');

  const recovered = await handleRecover({ email: EMAIL, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx);
  assert.equal(recovered.status, 'forbidden');
  if (recovered.status !== 'forbidden') throw new Error('unreachable');
  assert.equal(recovered.reason, 'account-suspended');
});

test('a refresh on a suspended account is 403 and does NOT spend the token', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);

  await fixture.store.suspendAccount({ accountId: session.account.id, suspendedAt: fixture.now() });
  // Suspending revoked every session, so the refresh path's OWN check needs a
  // token that is live and belongs to a suspended account. That combination is
  // reachable in production — an operator suspends between the mint and the
  // presentation — and it is the defence in depth this assertion pins.
  await fixture.store.insertTokens([
    {
      accountId: session.account.id,
      kind: 'refresh',
      tokenHash: hashToken('a-live-refresh-token'),
      familyId: 'family-x',
      expiresAt: new Date(fixture.now().getTime() + REFRESH_TOKEN_TTL_MS),
    },
  ]);

  const refused = await handleRefresh({ refreshToken: 'a-live-refresh-token' }, fixture.ctx);
  assert.equal(refused.status, 'forbidden');
  if (refused.status !== 'forbidden') throw new Error('unreachable');
  assert.equal(refused.reason, 'account-suspended');

  // The token was NOT spent: a suspension may be lifted, and burning it would
  // have logged the person out of a device they are getting back.
  await fixture.store.reactivateAccount(session.account.id);
  assert.equal((await handleRefresh({ refreshToken: 'a-live-refresh-token' }, fixture.ctx)).status, 'ok');
});

// ── Tokens ─────────────────────────────────────────────────────────────────

test('an access token resolves to its account, and stops after expiry', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const tokens = requireTokens(session);

  assert.notEqual(await resolvedSession(tokens.accessToken, fixture.ctx), null);
  fixture.advance(ACCESS_TOKEN_TTL_MS + 1000);
  assert.equal(await resolvedSession(tokens.accessToken, fixture.ctx), null);
});

test('refresh rotates the pair and invalidates the presented token', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const first = requireTokens(session);

  const rotated = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  assert.equal(rotated.status, 'ok');
  if (rotated.status !== 'ok') throw new Error('unreachable');
  assert.notEqual(rotated.body.tokens.refreshToken, first.refreshToken);
  assert.notEqual(await resolvedSession(rotated.body.tokens.accessToken, fixture.ctx), null);
});

test('reusing an already-rotated refresh token revokes the whole family', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const first = requireTokens(session);

  const rotated = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  if (rotated.status !== 'ok') throw new Error('unreachable');

  // A thief replays the token the real client already spent.
  const replay = await handleRefresh({ refreshToken: first.refreshToken }, fixture.ctx);
  assert.equal(replay.status, 'unauthorized');

  // Both parties are logged out — the correct response, because the
  // alternative leaves the thief with a working session.
  assert.equal(await resolvedSession(rotated.body.tokens.accessToken, fixture.ctx), null);
  assert.equal(
    (await handleRefresh({ refreshToken: rotated.body.tokens.refreshToken }, fixture.ctx)).status,
    'unauthorized',
  );
});

test('an expired refresh token is rejected without revoking anything', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const tokens = requireTokens(session);

  fixture.advance(REFRESH_TOKEN_TTL_MS + 1000);
  const outcome = await handleRefresh({ refreshToken: tokens.refreshToken }, fixture.ctx);
  assert.equal(outcome.status, 'unauthorized');
  if (outcome.status !== 'unauthorized') throw new Error('unreachable');
  assert.match(outcome.reason, /expired/);
});

test('logout revokes the caller family, leaving other devices signed in', async () => {
  const fixture = inviteFixture();
  const deviceOne = requireTokens(await signUp(fixture));
  const loginTwo = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  if (loginTwo.status !== 'ok') throw new Error('unreachable');
  const deviceTwo = requireTokens(loginTwo.body);

  const session = await resolvedSession(deviceOne.accessToken, fixture.ctx);
  assert.ok(session);
  assert.equal((await handleLogout(session, fixture.ctx)).status, 'no-content');

  assert.equal(await resolvedSession(deviceOne.accessToken, fixture.ctx), null);
  assert.notEqual(await resolvedSession(deviceTwo.accessToken, fixture.ctx), null);
});

// ── Change passphrase ──────────────────────────────────────────────────────

test('change-passphrase swaps the verifier, stores the re-wrapped DEK and logs other devices out', async () => {
  const fixture = inviteFixture();
  const first = requireTokens(await signUp(fixture));
  const secondLogin = await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx);
  if (secondLogin.status !== 'ok') throw new Error('unreachable');
  const otherDevice = requireTokens(secondLogin.body);

  const session = await resolvedSession(first.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleChangePassphrase(
    {
      accountId: session.accountId,
      body: {
        currentAuthHash: AUTH_HASH,
        newAuthHash: OTHER_AUTH_HASH,
        kdfDescriptor: sampleKdfDescriptor(2),
        keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(51) }],
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
  assert.equal(await resolvedSession(otherDevice.accessToken, fixture.ctx), null);
  assert.equal(await resolvedSession(first.accessToken, fixture.ctx), null);
  assert.notEqual(await resolvedSession(outcome.body.tokens.accessToken, fixture.ctx), null);

  assert.equal(
    Buffer.from(
      fixture.store.keyRecordsFor(session.accountId).get('passphrase')?.wrappedDek ?? new Uint8Array(),
    ).toString('base64'),
    sampleWrappedDek(51),
  );
});

test('change-passphrase rejects a wrong current passphrase and changes nothing', async () => {
  const fixture = inviteFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolvedSession(tokens.accessToken, fixture.ctx);
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
  const fixture = inviteFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolvedSession(tokens.accessToken, fixture.ctx);
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

// ── Account read and edit ──────────────────────────────────────────────────

test('GET /account reports the whole AccountView, including today’s AI spend', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  fixture.store.seedAiUsage({ accountId: session.account.id, day: '2026-08-04', count: 3 });

  const outcome = await handleGetAccount({ accountId: session.account.id }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');
  assert.deepEqual(Object.keys(outcome.body.account).toSorted(), [
    'aiUsedToday',
    'createdAt',
    'dailyAiLimit',
    'displayName',
    'email',
    'id',
    'role',
    'suspendedAt',
  ]);
  assert.equal(outcome.body.account.aiUsedToday, 3);
});

test('PATCH /account sets and clears the display name, and refuses a missing key', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);

  const renamed = await handleUpdateAccount(
    { accountId: session.account.id, body: { displayName: '  Anna S.  ' } },
    fixture.ctx,
  );
  assert.equal(renamed.status, 'ok');
  if (renamed.status !== 'ok') throw new Error('unreachable');
  assert.equal(renamed.body.account.displayName, 'Anna S.');

  const cleared = await handleUpdateAccount(
    { accountId: session.account.id, body: { displayName: null } },
    fixture.ctx,
  );
  if (cleared.status !== 'ok') throw new Error('unreachable');
  assert.equal(cleared.body.account.displayName, null);

  // An absent key is a 400: a PATCH that quietly did nothing because a field
  // name was misspelled is a change the client believes it made.
  assert.equal((await handleUpdateAccount({ accountId: session.account.id, body: {} }, fixture.ctx)).status, 'invalid');
});

test('PATCH /account cannot raise a role or an allowance', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);

  const outcome = await handleUpdateAccount(
    { accountId: session.account.id, body: { displayName: 'Anna', role: 'admin', dailyAiLimit: 9999 } },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');
  // Standing is granted by an operator, never asked for by the account.
  assert.equal(outcome.body.account.role, 'member');
  assert.equal(outcome.body.account.dailyAiLimit, 0);
});

// ── Deletion ───────────────────────────────────────────────────────────────

test('deletion requires re-authentication', async () => {
  const fixture = inviteFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolvedSession(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const refused = await handleDeleteAccount(
    { accountId: session.accountId, body: { authHash: OTHER_AUTH_HASH } },
    fixture.ctx,
  );
  assert.equal(refused.status, 'unauthorized');
  assert.equal(fixture.store.hasAccount(session.accountId), true);
});

test('deletion removes the account and its sync data', async () => {
  const fixture = inviteFixture();
  const tokens = requireTokens(await signUp(fixture));
  const session = await resolvedSession(tokens.accessToken, fixture.ctx);
  assert.ok(session);

  const outcome = await handleDeleteAccount(
    { accountId: session.accountId, body: { authHash: AUTH_HASH } },
    fixture.ctx,
  );
  assert.equal(outcome.status, 'no-content');
  assert.equal(fixture.store.hasAccount(session.accountId), false);
  assert.equal(fixture.store.keyRecordsFor(session.accountId).size, 0);
  assert.equal(await resolvedSession(tokens.accessToken, fixture.ctx), null);
});

// ── Recovery-code authentication ───────────────────────────────────────────

test('the recovery code logs an account in without the passphrase', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const outcome = await handleRecover({ email: EMAIL, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');
  assert.equal(outcome.body.account.email, EMAIL);

  const session = await resolvedSession(outcome.body.tokens.accessToken, fixture.ctx);
  assert.ok(session, 'a recovery must hand back a usable session');
});

test('the recovery code is not the passphrase, and neither stands in for the other', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  // The passphrase auth-hash presented as a recovery proof, and vice versa.
  assert.equal(
    (await handleRecover({ email: EMAIL, recoveryAuthHash: AUTH_HASH }, fixture.ctx)).status,
    'unauthorized',
  );
  assert.equal((await handleLogin({ email: EMAIL, authHash: RECOVERY_AUTH_HASH }, fixture.ctx)).status, 'unauthorized');
});

test('an unknown address and a wrong code are ONE failure', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const outcomes = await Promise.all([
    handleRecover({ email: 'nobody@example.org', recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx),
    handleRecover({ email: OTHER_EMAIL, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx),
    handleRecover({ email: EMAIL, recoveryAuthHash: OTHER_AUTH_HASH }, fixture.ctx),
  ]);

  const answers = new Set(outcomes.map((outcome) => JSON.stringify(outcome)));
  assert.equal(answers.size, 1, `every recovery failure must read identically, got ${[...answers].join(' | ')}`);
});

test('recover-rotate sets a new passphrase, re-wraps the DEK and logs every device out', async () => {
  const fixture = inviteFixture();
  const original = requireTokens(await signUp(fixture));

  const outcome = await handleRecoverRotate(recoverRotateBody(), fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');

  // The point of the whole flow: the new passphrase works and the old is dead.
  assert.equal((await handleLogin({ email: EMAIL, authHash: OTHER_AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'unauthorized');

  // The re-wrapped DEK landed, so the new passphrase can actually decrypt.
  const records = fixture.store.keyRecordsFor(outcome.body.account.id);
  assert.equal(
    Buffer.from(records.get('passphrase')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(21),
  );

  // Every session that existed before the reset is gone.
  assert.equal(await resolvedSession(original.accessToken, fixture.ctx), null);
  assert.ok(await resolvedSession(outcome.body.tokens.accessToken, fixture.ctx));
});

test('recover-rotate refuses without a passphrase key record, rather than minting an account that decrypts nothing', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const outcome = await handleRecoverRotate(recoverRotateBody({ keyRecords: [] }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
  // And nothing moved: the old passphrase still works.
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('rotating the recovery code needs BOTH its verifier and its key record, in either direction', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const verifierOnly = await handleRecoverRotate(
    recoverRotateBody({ newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH, recoveryCode: sampleRecoveryCode(3) }),
    fixture.ctx,
  );
  assert.equal(verifierOnly.status, 'invalid');

  const recordOnly = await handleRecoverRotate(
    recoverRotateBody({
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(21) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(31) },
      ],
    }),
    fixture.ctx,
  );
  assert.equal(recordOnly.status, 'invalid');
});

test('rotating the recovery code without a new recoveryCode is a 400, so no escrow goes stale', async () => {
  // The third half of the all-or-nothing rule. An escrow still holding the OLD
  // code after a rotation is a mailed reset that hands somebody a credential
  // the account no longer accepts, discovered on the day they need it.
  const fixture = inviteFixture();
  await signUp(fixture);

  const outcome = await handleRecoverRotate(
    recoverRotateBody({
      newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(21) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(31) },
      ],
    }),
    fixture.ctx,
  );
  assert.equal(outcome.status, 'invalid');
  if (outcome.status !== 'invalid') throw new Error('unreachable');
  assert.match(outcome.reason, /recoveryCode/);
});

test('rotating the recovery code moves its verifier, its key record and its escrow together', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const escrowBefore = fixture.store.escrowFor(session.account.id);

  const outcome = await handleRecoverRotate(
    recoverRotateBody({
      newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
      recoveryCode: sampleRecoveryCode(3),
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(21) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(31) },
      ],
    }),
    fixture.ctx,
  );
  assert.equal(outcome.status, 'ok');

  // The new code authenticates, the old one does not.
  assert.equal(
    (await handleRecover({ email: EMAIL, recoveryAuthHash: NEW_RECOVERY_AUTH_HASH }, fixture.ctx)).status,
    'ok',
  );
  assert.equal(
    (await handleRecover({ email: EMAIL, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx)).status,
    'unauthorized',
  );
  // And the record the new code unwraps moved with it.
  const records = fixture.store.keyRecordsFor(session.account.id);
  assert.equal(
    Buffer.from(records.get('recovery')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(31),
  );
  // …and so did the escrow.
  const escrowAfter = fixture.store.escrowFor(session.account.id);
  assert.ok(escrowAfter !== null);
  assert.notDeepEqual(escrowAfter, escrowBefore, 'the escrow must be re-sealed with the new code');
});

test('a rotation that keeps the recovery code leaves the escrow untouched', async () => {
  const fixture = inviteFixture();
  const session = await signUp(fixture);
  const escrowBefore = fixture.store.escrowFor(session.account.id);

  const outcome = await handleRecoverRotate(recoverRotateBody(), fixture.ctx);
  assert.equal(outcome.status, 'ok');
  assert.deepEqual(fixture.store.escrowFor(session.account.id), escrowBefore);
});

test('a wrong recovery code changes nothing, and reads the same as an unknown address', async () => {
  const fixture = inviteFixture();
  await signUp(fixture);

  const wrongCode = await handleRecoverRotate(recoverRotateBody({ recoveryAuthHash: OTHER_AUTH_HASH }), fixture.ctx);
  const unknownEmail = await handleRecoverRotate(recoverRotateBody({ email: 'nobody@example.org' }), fixture.ctx);
  assert.deepEqual(wrongCode, unknownEmail);
  assert.equal(wrongCode.status, 'unauthorized');

  // The old passphrase still works and no key record was written.
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});
