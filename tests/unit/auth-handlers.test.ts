/**
 * Behaviour tests for the account handler cores. Every security property this
 * service claims is asserted here, DB-free, against `fake-account-store.ts`:
 *
 *  - unknown handles get a stable, real-shaped KDF descriptor (no enumeration
 *    oracle on the one endpoint that must answer before authentication)
 *  - login rejects unknown accounts and wrong hashes identically
 *  - refresh rotates, and REUSING a rotated refresh token kills the family
 *  - both credential-rotation paths revoke every outstanding session
 *  - deletion requires re-authentication and takes the sync data with it
 *  - the recovery code authenticates, and an unknown handle, an account with
 *    no recovery code and a wrong code are one indistinguishable failure
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleChangePassphrase,
  handleDeleteAccount,
  handleGetKdfDescriptor,
  handleLogin,
  handleLogout,
  handleRecover,
  handleRecoverRotate,
  handleRefresh,
  handleSignup,
  resolveAccessToken,
  type SessionResponse,
  type SessionTokens,
} from '../../src/accounts/auth-handlers.js';
import { REFRESH_TOKEN_TTL_MS, ACCESS_TOKEN_TTL_MS, hashToken } from '../../src/lib/tokens.js';
import type { JsonObject } from '../../src/lib/json.js';
import {
  createAuthFixture,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleWrappedDek,
  type AuthFixture,
} from './auth-context-fixture.js';

const HANDLE = 'bright-otter-42';
const AUTH_HASH = sampleAuthHash(11);
const OTHER_AUTH_HASH = sampleAuthHash(22);
const RECOVERY_AUTH_HASH = sampleAuthHash(33);
const NEW_RECOVERY_AUTH_HASH = sampleAuthHash(44);

function signupBody(overrides: JsonObject = {}) {
  return {
    handle: HANDLE,
    authHash: AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(),
    displayName: 'A Person',
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    ...overrides,
  };
}

/** The body `POST /v1/auth/recover-rotate` takes, minus whatever a test is testing the absence of. */
function recoverRotateBody(overrides: JsonObject = {}) {
  return {
    handle: HANDLE,
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    newAuthHash: OTHER_AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(2),
    keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(21) }],
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
  return session.tokens;
}

// ── KDF descriptor / enumeration ───────────────────────────────────────────

test('kdf descriptor for an unknown handle is stable across calls', async () => {
  const fixture = createAuthFixture();
  const first = await handleGetKdfDescriptor({ handle: 'nobody-at-all' }, fixture.ctx);
  const second = await handleGetKdfDescriptor({ handle: '  NOBODY-At-All ' }, fixture.ctx);

  assert.equal(first.status, 'ok');
  assert.equal(second.status, 'ok');
  if (first.status !== 'ok' || second.status !== 'ok') throw new Error('unreachable');
  // Stability is the property: a random dummy would be distinguishable from a
  // real descriptor by simply asking twice. Canonicalisation matters for the
  // same reason — the dummy is derived over the NORMALIZED handle, so casing
  // and stray whitespace cannot become an oracle of their own.
  assert.deepEqual(first.body.kdfDescriptor, second.body.kdfDescriptor);
});

test('dummy and real kdf descriptors are structurally indistinguishable', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const real = await handleGetKdfDescriptor({ handle: HANDLE }, fixture.ctx);
  const dummy = await handleGetKdfDescriptor({ handle: 'nobody-at-all' }, fixture.ctx);
  assert.equal(real.status, 'ok');
  assert.equal(dummy.status, 'ok');
  if (real.status !== 'ok' || dummy.status !== 'ok') throw new Error('unreachable');

  assert.deepEqual(Object.keys(real.body.kdfDescriptor).toSorted(), Object.keys(dummy.body.kdfDescriptor).toSorted());
  assert.equal(
    Buffer.from(real.body.kdfDescriptor.salt, 'base64').byteLength,
    Buffer.from(dummy.body.kdfDescriptor.salt, 'base64').byteLength,
  );
});

test('a different enumeration secret yields a different dummy for the same handle', async () => {
  const a = createAuthFixture();
  const b = createAuthFixture();
  b.ctx.enumerationSecret = 'a completely different secret';

  const fromA = await handleGetKdfDescriptor({ handle: 'nobody-at-all' }, a.ctx);
  const fromB = await handleGetKdfDescriptor({ handle: 'nobody-at-all' }, b.ctx);
  if (fromA.status !== 'ok' || fromB.status !== 'ok') throw new Error('unreachable');
  assert.notEqual(fromA.body.kdfDescriptor.salt, fromB.body.kdfDescriptor.salt);
});

test('a malformed handle is a 400, not a dummy descriptor', async () => {
  const fixture = createAuthFixture();
  assert.equal((await handleGetKdfDescriptor({ handle: '' }, fixture.ctx)).status, 'invalid');
  assert.equal((await handleGetKdfDescriptor({ handle: 42 }, fixture.ctx)).status, 'invalid');
});

test("the kdf endpoint refuses an '@' rather than answering about an address", async () => {
  // The rejection is what stops this endpoint being asked about mailboxes at
  // all. It is structural, identical for every caller, and therefore not an
  // oracle: nothing containing an '@' can ever be an account here.
  const fixture = createAuthFixture();
  const outcome = await handleGetKdfDescriptor({ handle: 'person@example.test' }, fixture.ctx);
  assert.equal(outcome.status, 'invalid');
  if (outcome.status !== 'invalid') throw new Error('unreachable');
  assert.match(outcome.reason, /@/);
});

// ── Signup ─────────────────────────────────────────────────────────────────

test('signup creates an account and returns a session immediately', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);

  assert.equal(session.account.handle, HANDLE);
  // No withheld session any more: there is no address to confirm, so there is
  // no state in which an account exists but cannot be used.
  requireTokens(session);
});

test("signup refuses a handle containing '@', and the reason names the rule", async () => {
  // THE LOAD-BEARING REJECTION. Without it the handle column drifts back into
  // being an address register, one user at a time, and M181 is undone.
  const fixture = createAuthFixture();
  const outcome = await handleSignup(signupBody({ handle: 'person@example.test' }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
  if (outcome.status !== 'invalid') throw new Error('unreachable');
  assert.match(outcome.reason, /@/);
});

test('a handle is canonicalised, so casing and Unicode form cannot fork an account', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  // NFKC folds the fullwidth Latin letters; lowercasing folds the casing; the
  // trim folds the pasted whitespace. All three must reach the SAME account.
  const fullwidth = 'ｂright-otter-42';
  const duplicate = await handleSignup(signupBody({ handle: '  BRIGHT-Otter-42 ' }), fixture.ctx);
  assert.equal(duplicate.status, 'conflict');

  assert.equal((await handleLogin({ handle: fullwidth, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.equal((await handleLogin({ handle: '  BRIGHT-Otter-42 ', authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('an over-long handle is refused', async () => {
  const fixture = createAuthFixture();
  const outcome = await handleSignup(signupBody({ handle: 'x'.repeat(65) }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
});

test('signup is refused when the instance is closed', async () => {
  const fixture = createAuthFixture({ signupMode: 'closed' });
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
});

// ---------------------------------------------------------------------------
// Invite-only signup (M166)
// ---------------------------------------------------------------------------

const INVITE_TOKEN = 'si_invite-token-for-tests';

/** A fixture in invite mode with one live invite already minted. */
function inviteFixture(options: { expiresInMs?: number } = {}) {
  const fixture = createAuthFixture({ signupMode: 'invite' });
  fixture.store.seedInvite({
    tokenHash: hashToken(INVITE_TOKEN),
    expiresAt: new Date(fixture.now().getTime() + (options.expiresInMs ?? 7 * 24 * 60 * 60 * 1000)),
  });
  return fixture;
}

test('an invited signup succeeds and spends the invite', async () => {
  const fixture = inviteFixture();
  const outcome = await handleSignup(signupBody({ inviteToken: INVITE_TOKEN }), fixture.ctx);
  assert.equal(outcome.status, 'created');
  assert.equal(fixture.store.inviteIsRedeemable(hashToken(INVITE_TOKEN)), false);
});

test('one invite cannot create a second account', async () => {
  const fixture = inviteFixture();
  const first = await handleSignup(signupBody({ inviteToken: INVITE_TOKEN }), fixture.ctx);
  assert.equal(first.status, 'created');

  const second = await handleSignup(signupBody({ handle: 'someone-else', inviteToken: INVITE_TOKEN }), fixture.ctx);
  assert.equal(second.status, 'forbidden');
});

test('a signup that hits a taken handle leaves the invite redeemable', async () => {
  const fixture = inviteFixture();
  // Burn the handle first, using a SECOND invite, so the handle exists.
  fixture.store.seedInvite({
    tokenHash: hashToken('si_first-invite'),
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });
  const first = await handleSignup(signupBody({ inviteToken: 'si_first-invite' }), fixture.ctx);
  assert.equal(first.status, 'created');

  const duplicate = await handleSignup(signupBody({ inviteToken: INVITE_TOKEN }), fixture.ctx);
  assert.equal(duplicate.status, 'conflict');
  // The 409 must cost the holder nothing.
  assert.equal(fixture.store.inviteIsRedeemable(hashToken(INVITE_TOKEN)), true);
});

test('an expired invite is refused, and is refused as invalid rather than as expired', async () => {
  const fixture = inviteFixture({ expiresInMs: 1000 });
  fixture.advance(2000);
  const outcome = await handleSignup(signupBody({ inviteToken: INVITE_TOKEN }), fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
  if (outcome.status !== 'forbidden') throw new Error('unreachable');
  // Same words as an unknown token — see the next test for why.
  assert.match(outcome.reason, /valid invite is required/i);
});

test('unknown, missing, wrong-service and expired invites are indistinguishable', async () => {
  // A caller who can tell these apart can probe which tokens exist, and can
  // learn that a token WAS real before it was spent. `gi_…` is a GATEWAY
  // invite: it is stopped by the shape gate before any lookup, and the whole
  // point of this case is that the caller cannot tell that happened.
  const reasons = new Set<string>();
  for (const inviteToken of [undefined, '', 'never-minted', 'gi_a-gateway-invite-posted-here', 12345]) {
    const fixture = inviteFixture({ expiresInMs: 1000 });
    fixture.advance(2000);
    const body = inviteToken === undefined ? signupBody() : signupBody({ inviteToken });
    const outcome = await handleSignup(body, fixture.ctx);
    assert.equal(outcome.status, 'forbidden');
    if (outcome.status !== 'forbidden') throw new Error('unreachable');
    reasons.add(outcome.reason);
  }
  assert.equal(reasons.size, 1, `expected one shared rejection, got: ${[...reasons].join(' | ')}`);
});

test('a closed instance refuses before parsing, so a malformed body still gets 403', async () => {
  // Ordering guard. If the mode check moved below field parsing, this would be
  // a 400 and the status code would disclose which bodies were well formed.
  const fixture = createAuthFixture({ signupMode: 'closed' });
  const outcome = await handleSignup({ handle: 42 }, fixture.ctx);
  assert.equal(outcome.status, 'forbidden');
});

test('invite mode is not consulted when the instance is open', async () => {
  const fixture = createAuthFixture({ signupMode: 'open' });
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'created');
});

test('a duplicate signup is a conflict', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'conflict');
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
  const outcome = await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
});

test('login rejects an unknown account and a wrong hash with the same response', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const unknown = await handleLogin({ handle: 'nobody-at-all', authHash: AUTH_HASH }, fixture.ctx);
  const wrong = await handleLogin({ handle: HANDLE, authHash: OTHER_AUTH_HASH }, fixture.ctx);

  assert.equal(unknown.status, 'unauthorized');
  assert.equal(wrong.status, 'unauthorized');
  if (unknown.status !== 'unauthorized' || wrong.status !== 'unauthorized') throw new Error('unreachable');
  // Identical text: the message must not be the thing that says which one it was.
  assert.equal(unknown.reason, wrong.reason);
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
  const loginTwo = await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx);
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
  const secondLogin = await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx);
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
  assert.equal((await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx)).status, 'unauthorized');
  assert.equal((await handleLogin({ handle: HANDLE, authHash: OTHER_AUTH_HASH }, fixture.ctx)).status, 'ok');

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
  assert.equal((await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
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

// ── Recovery-code authentication (M181 spec 02) ────────────────────────────

test('the recovery code logs an account in without the passphrase', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const outcome = await handleRecover({ handle: HANDLE, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');
  assert.equal(outcome.body.account.handle, HANDLE);

  const session = await resolveAccessToken(outcome.body.tokens.accessToken, fixture.ctx);
  assert.ok(session, 'a recovery must hand back a usable session');
});

test('the recovery code is not the passphrase, and neither stands in for the other', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  // The passphrase auth-hash presented as a recovery proof, and vice versa.
  assert.equal(
    (await handleRecover({ handle: HANDLE, recoveryAuthHash: AUTH_HASH }, fixture.ctx)).status,
    'unauthorized',
  );
  assert.equal(
    (await handleLogin({ handle: HANDLE, authHash: RECOVERY_AUTH_HASH }, fixture.ctx)).status,
    'unauthorized',
  );
});

test('an unknown handle, an account with no recovery code and a wrong code are ONE failure', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);
  // A second account created WITHOUT a recovery code — the third of the three
  // cases that must not be distinguishable.
  const withoutCode = await handleSignup(signupBody({ handle: 'no-code-here', recoveryAuthHash: null }), fixture.ctx);
  assert.equal(withoutCode.status, 'created');

  const outcomes = await Promise.all([
    handleRecover({ handle: 'nobody-at-all', recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx),
    handleRecover({ handle: 'no-code-here', recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx),
    handleRecover({ handle: HANDLE, recoveryAuthHash: OTHER_AUTH_HASH }, fixture.ctx),
  ]);

  const answers = new Set(outcomes.map((outcome) => JSON.stringify(outcome)));
  assert.equal(answers.size, 1, `every recovery failure must read identically, got ${[...answers].join(' | ')}`);
});

test('recover-rotate sets a new passphrase, re-wraps the DEK and logs every device out', async () => {
  const fixture = createAuthFixture();
  const original = requireTokens(await signUp(fixture));

  const outcome = await handleRecoverRotate(recoverRotateBody(), fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');

  // The point of the whole flow: the new passphrase works and the old is dead.
  assert.equal((await handleLogin({ handle: HANDLE, authHash: OTHER_AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.equal((await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx)).status, 'unauthorized');

  // The re-wrapped DEK landed, so the new passphrase can actually decrypt.
  const records = fixture.store.keyRecordsFor(outcome.body.account.id);
  assert.equal(
    Buffer.from(records.get('passphrase')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(21),
  );

  // Every session that existed before the reset is gone.
  assert.equal(await resolveAccessToken(original.accessToken, fixture.ctx), null);
  assert.ok(await resolveAccessToken(outcome.body.tokens.accessToken, fixture.ctx));
});

test('recover-rotate refuses without a passphrase key record, rather than minting an account that decrypts nothing', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const outcome = await handleRecoverRotate(recoverRotateBody({ keyRecords: [] }), fixture.ctx);
  assert.equal(outcome.status, 'invalid');
  // And nothing moved: the old passphrase still works.
  assert.equal((await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('rotating the recovery code needs BOTH its verifier and its key record, in either direction', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const verifierOnly = await handleRecoverRotate(
    recoverRotateBody({ newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH }),
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

test('rotating the recovery code moves its verifier and its key record together', async () => {
  const fixture = createAuthFixture();
  const session = await signUp(fixture);

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
  assert.equal(outcome.status, 'ok');

  // The new code authenticates, the old one does not.
  assert.equal(
    (await handleRecover({ handle: HANDLE, recoveryAuthHash: NEW_RECOVERY_AUTH_HASH }, fixture.ctx)).status,
    'ok',
  );
  assert.equal(
    (await handleRecover({ handle: HANDLE, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx)).status,
    'unauthorized',
  );
  // And the record the new code unwraps moved with it.
  const records = fixture.store.keyRecordsFor(session.account.id);
  assert.equal(
    Buffer.from(records.get('recovery')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(31),
  );
});

test('a wrong recovery code changes nothing, and reads the same as an unknown handle', async () => {
  const fixture = createAuthFixture();
  await signUp(fixture);

  const wrongCode = await handleRecoverRotate(recoverRotateBody({ recoveryAuthHash: OTHER_AUTH_HASH }), fixture.ctx);
  const unknownHandle = await handleRecoverRotate(recoverRotateBody({ handle: 'nobody-at-all' }), fixture.ctx);
  assert.deepEqual(wrongCode, unknownHandle);
  assert.equal(wrongCode.status, 'unauthorized');

  // The old passphrase still works and no key record was written.
  assert.equal((await handleLogin({ handle: HANDLE, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});
