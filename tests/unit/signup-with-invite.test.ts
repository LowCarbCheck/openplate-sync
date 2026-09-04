/**
 * `POST /v1/auth/signup` — the only door onto this service, and what it
 * commits.
 *
 * THE FIVE WRITES ARE ONE ACT: the invite redemption, the account (with the
 * INVITE's address, role and allowance), the sealed recovery code, and both
 * key records. `auth-handlers.test.ts` covers the refusals; this file covers
 * what a success actually leaves behind, and the two rules that make the
 * invite a capability rather than a suggestion — one redemption per invite,
 * and a `409` that costs the holder nothing.
 *
 * The ATOMICITY of those five writes is a property of Postgres and is asserted
 * in `tests/integration/signup-invites.test.ts`. What is asserted here is that
 * the handler asks for all five in one call, which is what makes the
 * transaction possible at all.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleInviteLookup, handleLogin, handleSignup } from '../../src/accounts/auth-handlers.js';
import { openRecoveryCode } from '../../src/lib/escrow.js';
import { hashToken } from '../../src/lib/tokens.js';
import type { JsonObject } from '../../src/lib/json.js';
import {
  createAuthFixture,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  TEST_ESCROW_KEY,
  type AuthFixture,
} from './auth-context-fixture.js';

const INVITE_TOKEN = 'si_an-invite-token-for-this-suite';
const EMAIL = 'anna@example.org';
const AUTH_HASH = sampleAuthHash(11);
const RECOVERY_AUTH_HASH = sampleAuthHash(33);
const RECOVERY_CODE = sampleRecoveryCode();

function signupBody(overrides: JsonObject = {}) {
  return {
    inviteToken: INVITE_TOKEN,
    authHash: AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(),
    displayName: 'Anna',
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    recoveryCode: RECOVERY_CODE,
    keyRecords: [
      { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
      { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
    ],
    ...overrides,
  };
}

interface InviteOptions {
  token?: string;
  email?: string;
  displayName?: string | null;
  role?: 'admin' | 'member';
  dailyAiLimit?: number;
  expiresInMs?: number;
  revoked?: boolean;
}

function withInvite(options: InviteOptions = {}): AuthFixture {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(options.token ?? INVITE_TOKEN),
    email: options.email ?? EMAIL,
    displayName: options.displayName ?? null,
    role: options.role ?? 'member',
    dailyAiLimit: options.dailyAiLimit ?? 0,
    expiresAt: new Date(fixture.now().getTime() + (options.expiresInMs ?? 7 * 24 * 60 * 60 * 1000)),
    revokedAt: options.revoked === true ? fixture.now() : null,
  });
  return fixture;
}

// ── What a success leaves behind ───────────────────────────────────────────

test('a signup commits the account, both key records and the escrow, and spends the invite', async () => {
  const fixture = withInvite({ displayName: 'Anna Schmidt', role: 'admin', dailyAiLimit: 200 });

  const outcome = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(outcome.status, 'created');
  if (outcome.status !== 'created') throw new Error('unreachable');
  const account = outcome.body.account;

  // (1) the account, standing and all, from the invite.
  assert.equal(account.email, EMAIL);
  assert.equal(account.role, 'admin');
  assert.equal(account.dailyAiLimit, 200);
  // The DISPLAY NAME comes from the body, not from the invite: the operator's
  // guess is a suggestion, and the person is the one who knows their name.
  assert.equal(account.displayName, 'Anna');

  // (2) and (3) both key records.
  const records = fixture.store.keyRecordsFor(account.id);
  assert.equal(records.size, 2);
  assert.equal(
    Buffer.from(records.get('passphrase')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(),
  );
  assert.equal(
    Buffer.from(records.get('recovery')?.wrappedDek ?? new Uint8Array()).toString('base64'),
    sampleWrappedDek(41),
  );

  // (4) the escrow, and it really is the code the client sent.
  const sealed = fixture.store.escrowFor(account.id);
  assert.ok(sealed !== null, 'signup must write an escrow');
  assert.equal(
    openRecoveryCode({ sealed, escrowKey: TEST_ESCROW_KEY }),
    // Canonicalised: the client sent it in groups of five, and one code must
    // have one sealed form or a re-escrow after a rotation is not comparable.
    RECOVERY_CODE.replaceAll('-', ''),
  );

  // (5) the invite is spent.
  assert.equal(fixture.store.inviteIsRedeemable(hashToken(INVITE_TOKEN)), false);

  // And the session works, so this was a signup and not a write followed by a
  // rejection.
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
});

test('the escrowed code is canonicalised, so spacing cannot fork one code into two', async () => {
  const spaced = sampleRecoveryCode().replaceAll('-', ' ').toLowerCase();
  const fixture = withInvite();

  const outcome = await handleSignup(signupBody({ recoveryCode: spaced }), fixture.ctx);
  assert.equal(outcome.status, 'created');
  if (outcome.status !== 'created') throw new Error('unreachable');

  const sealed = fixture.store.escrowFor(outcome.body.account.id);
  assert.ok(sealed !== null);
  assert.equal(openRecoveryCode({ sealed, escrowKey: TEST_ESCROW_KEY }), RECOVERY_CODE.replaceAll('-', ''));
});

// ── The invite as a capability ─────────────────────────────────────────────

test('a 409 for an address that already has an account leaves the invite spendable', async () => {
  const fixture = withInvite();
  // A second invite for the same address, so the address can be burned first.
  fixture.store.seedInvite({
    tokenHash: hashToken('si_the-first-invite'),
    email: EMAIL,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });

  assert.equal((await handleSignup(signupBody({ inviteToken: 'si_the-first-invite' }), fixture.ctx)).status, 'created');

  const duplicate = await handleSignup(signupBody(), fixture.ctx);
  assert.equal(duplicate.status, 'conflict');
  // THE RULE THIS TEST EXISTS FOR. An operator who invited somebody twice by
  // mistake has not destroyed the live invitation.
  assert.equal(fixture.store.inviteIsRedeemable(hashToken(INVITE_TOKEN)), true);
});

test('an invite is single use, and the second attempt is indistinguishable from a fictional token', async () => {
  const fixture = withInvite();
  assert.equal((await handleSignup(signupBody(), fixture.ctx)).status, 'created');

  const second = await handleSignup(signupBody(), fixture.ctx);
  const fictional = await handleSignup(signupBody({ inviteToken: 'si_never-minted-at-all' }), fixture.ctx);
  assert.deepEqual(second, fictional);
  assert.equal(second.status, 'forbidden');
});

test('an expired and a revoked invite are refused with the same words as an unknown one', async () => {
  const expired = withInvite({ expiresInMs: 1000 });
  expired.advance(2000);
  const expiredOutcome = await handleSignup(signupBody(), expired.ctx);

  const revoked = withInvite({ revoked: true });
  const revokedOutcome = await handleSignup(signupBody(), revoked.ctx);

  const unknown = createAuthFixture();
  const unknownOutcome = await handleSignup(signupBody(), unknown.ctx);

  assert.deepEqual(expiredOutcome, revokedOutcome);
  assert.deepEqual(expiredOutcome, unknownOutcome);
  assert.equal(expiredOutcome.status, 'forbidden');
});

// ── Invite lookup ──────────────────────────────────────────────────────────

test('invite-lookup shows who the invitation is for, and nothing else', async () => {
  const fixture = withInvite({ displayName: 'Anna Schmidt', role: 'admin', dailyAiLimit: 200 });

  const outcome = await handleInviteLookup({ inviteToken: INVITE_TOKEN }, fixture.ctx);
  assert.equal(outcome.status, 'ok');
  if (outcome.status !== 'ok') throw new Error('unreachable');

  // The address and the operator's guess at a name, so the sign-up form can
  // show them instead of asking the person to type their own address.
  assert.equal(outcome.body.email, EMAIL);
  assert.equal(outcome.body.displayName, 'Anna Schmidt');
  // The standing an invite grants is NOT shown: a person who has not signed up
  // has no business learning that the operator gave them an admin role, and a
  // caller holding a stranger's link has less business still.
  assert.deepEqual(Object.keys(outcome.body).toSorted(), ['displayName', 'email', 'expiresAt']);
});

test('every bad invite gets ONE 404 from the lookup, whatever is wrong with it', async () => {
  const expired = withInvite({ expiresInMs: 1000 });
  expired.advance(2000);

  const revoked = withInvite({ revoked: true });

  const spent = withInvite();
  assert.equal((await handleSignup(signupBody(), spent.ctx)).status, 'created');

  const unknown = createAuthFixture();

  const outcomes = [
    await handleInviteLookup({ inviteToken: INVITE_TOKEN }, expired.ctx),
    await handleInviteLookup({ inviteToken: INVITE_TOKEN }, revoked.ctx),
    await handleInviteLookup({ inviteToken: INVITE_TOKEN }, spent.ctx),
    await handleInviteLookup({ inviteToken: INVITE_TOKEN }, unknown.ctx),
    // A token from the retired gateway, and a session token pasted here.
    await handleInviteLookup({ inviteToken: 'gi_a-gateway-invite' }, unknown.ctx),
    await handleInviteLookup({ inviteToken: 'a-bare-session-token' }, unknown.ctx),
    // No token at all, and a token of the wrong JSON type.
    await handleInviteLookup({}, unknown.ctx),
    await handleInviteLookup({ inviteToken: 42 }, unknown.ctx),
  ];

  const answers = new Set(outcomes.map((outcome) => JSON.stringify(outcome)));
  assert.equal(answers.size, 1, `every lookup failure must read identically, got ${[...answers].join(' | ')}`);
  assert.equal(outcomes[0]?.status, 'not-found');
  if (outcomes[0]?.status !== 'not-found') throw new Error('unreachable');
  assert.equal(outcomes[0].reason, 'invite-invalid');
});

test('a valid invite that has been looked up is still spendable', async () => {
  // The lookup must not consume anything: a person who opens the link twice,
  // or whose client retries, still has an invitation.
  const fixture = withInvite();
  assert.equal((await handleInviteLookup({ inviteToken: INVITE_TOKEN }, fixture.ctx)).status, 'ok');
  assert.equal((await handleInviteLookup({ inviteToken: INVITE_TOKEN }, fixture.ctx)).status, 'ok');
  assert.equal((await handleSignup(signupBody(), fixture.ctx)).status, 'created');
});
