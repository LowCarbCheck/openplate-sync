/**
 * The mailed password reset: `POST /v1/auth/reset/request` and
 * `POST /v1/auth/reset/open`.
 *
 * THE PROPERTY THAT CARRIES THE FILE is that `reset/request` answers `202` to
 * everybody and does the same work on both branches. PROTOCOL.md used to
 * record the OLD `request-reset` as the one endpoint where timing was not
 * equalised: a known address cost a token write and a mail send that an
 * unknown address did not. Only the write and the send are skipped now; the
 * mint and the digest happen either way, and the assertions below pin that by
 * counting the tokens the fixture minted rather than by measuring a clock,
 * which no test can do honestly.
 *
 * THE SECOND PROPERTY is that `reset/open` writes nothing to the account. It
 * hands back the recovery code the operator already holds in escrow, and the
 * client then runs the ordinary `recover-rotate` ceremony with it. That is what
 * makes this a delivery mechanism rather than the account-takeover path
 * ADR-0004 deleted: without the key records, the code is a string.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleLogin,
  handleRecover,
  handleResetOpen,
  handleResetRequest,
  handleSignup,
} from '../../src/accounts/auth-handlers.js';
import { hashToken, PASSWORD_RESET_TOKEN_PREFIX, RESET_TOKEN_TTL_MS } from '../../src/lib/tokens.js';
import {
  createAuthFixture,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  type AuthFixture,
} from './auth-context-fixture.js';

const INVITE_TOKEN = 'si_an-invite-token-for-this-suite';
const EMAIL = 'anna@example.org';
const AUTH_HASH = sampleAuthHash(11);
const RECOVERY_AUTH_HASH = sampleAuthHash(33);
const RECOVERY_CODE = sampleRecoveryCode();
const CANONICAL_CODE = RECOVERY_CODE.replaceAll('-', '');

/** A fixture with one account, created the only way the service can: through an invite. */
async function withAccount(): Promise<AuthFixture> {
  const fixture = createAuthFixture();
  fixture.store.seedInvite({
    tokenHash: hashToken(INVITE_TOKEN),
    email: EMAIL,
    expiresAt: new Date(fixture.now().getTime() + 60_000),
  });
  const created = await handleSignup(
    {
      inviteToken: INVITE_TOKEN,
      authHash: AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(),
      recoveryAuthHash: RECOVERY_AUTH_HASH,
      recoveryCode: RECOVERY_CODE,
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
      ],
    },
    fixture.ctx,
  );
  assert.equal(created.status, 'created', `fixture signup failed: ${JSON.stringify(created)}`);
  return fixture;
}

// ── reset/request ──────────────────────────────────────────────────────────

test('a reset request for a known address is 202, stores a token and asks for a letter', async () => {
  const fixture = await withAccount();

  const outcome = await handleResetRequest({ email: EMAIL }, fixture.ctx);
  assert.equal(outcome.status, 'accepted');
  if (outcome.status !== 'accepted') throw new Error('unreachable');
  assert.deepEqual(outcome.body, {});

  const live = fixture.store.allPasswordResets().filter((row) => row.consumedAt === null);
  assert.equal(live.length, 1);

  assert.equal(fixture.mailer.resets.length, 1);
  assert.equal(fixture.mailer.resets[0]?.email, EMAIL);
  // The letter carries a `sr_` token, not a session token: the prefix is what
  // stops one being posted to the endpoint that wants the other.
  assert.ok(fixture.mailer.resets[0]?.resetToken.startsWith(PASSWORD_RESET_TOKEN_PREFIX));
  // …and the digest of exactly that token is what was stored.
  assert.equal(live[0]?.tokenHash, hashToken(fixture.mailer.resets[0]?.resetToken ?? ''));
});

test('a reset request for an unknown address is the SAME 202, and sends nothing', async () => {
  const fixture = await withAccount();

  const known = await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const unknown = await handleResetRequest({ email: 'nobody@example.org' }, fixture.ctx);
  // Byte-identical outcomes: the response must say nothing about whether the
  // address exists.
  assert.deepEqual(known, unknown);

  // One letter, for the account that exists.
  assert.equal(fixture.mailer.resets.length, 1);
  assert.equal(fixture.store.allPasswordResets().length, 1);
});

test('a malformed address is also a 202, so the status code is not an address-shape oracle', async () => {
  const fixture = await withAccount();

  for (const email of ['', 'not-an-address', 42, undefined]) {
    const outcome = await handleResetRequest({ email }, fixture.ctx);
    assert.equal(outcome.status, 'accepted', `email=${String(email)}`);
  }
  assert.equal(fixture.mailer.resets.length, 0);
});

test('both branches mint and digest a token, so the known one is not the only one that pays', async () => {
  // The timing property, asserted structurally rather than with a stopwatch:
  // the fixture's minter is a counter, so an unknown address that skipped the
  // mint would leave the counter untouched. This is the assertion that would
  // fail if somebody "optimised" the mint into the `account !== null` branch.
  const fixture = await withAccount();

  await handleResetRequest({ email: 'nobody@example.org' }, fixture.ctx);
  await handleResetRequest({ email: 'also-nobody@example.org' }, fixture.ctx);
  await handleResetRequest({ email: EMAIL }, fixture.ctx);

  // Three mints, one of which was stored. The two thrown away were paid for.
  const stored = fixture.store.allPasswordResets();
  assert.equal(stored.length, 1);
  const mailed = fixture.mailer.resets[0]?.resetToken ?? '';
  assert.equal(mailed, 'sr_reset-3', 'the third mint is the one that was kept, so the first two really happened');
});

test('a new request supersedes the older live token', async () => {
  const fixture = await withAccount();

  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const first = fixture.mailer.resets[0]?.resetToken ?? '';
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const second = fixture.mailer.resets[1]?.resetToken ?? '';
  assert.notEqual(first, second);

  // ONE live token per account: two letters in a mailbox, both live, is a
  // second copy of a credential that hands over a recovery code.
  assert.equal(fixture.store.allPasswordResets().filter((row) => row.consumedAt === null).length, 1);

  // And the old letter really is dead, which is what somebody scrolling up in
  // their inbox would otherwise redeem.
  assert.equal((await handleResetOpen({ resetToken: first }, fixture.ctx)).status, 'not-found');
  assert.equal((await handleResetOpen({ resetToken: second }, fixture.ctx)).status, 'ok');
});

// ── reset/open ─────────────────────────────────────────────────────────────

test('opening a reset returns the escrowed code once, and spends the token', async () => {
  const fixture = await withAccount();
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const token = fixture.mailer.resets[0]?.resetToken ?? '';

  const first = await handleResetOpen({ resetToken: token }, fixture.ctx);
  assert.equal(first.status, 'ok');
  if (first.status !== 'ok') throw new Error('unreachable');
  assert.equal(first.body.email, EMAIL);
  // The code the client sealed at signup comes back, canonical.
  assert.equal(first.body.recoveryCode, CANONICAL_CODE);

  // ONCE. A second request with the same token is refused, and refused as the
  // same failure a fictional token gets.
  const second = await handleResetOpen({ resetToken: token }, fixture.ctx);
  assert.equal(second.status, 'not-found');
  if (second.status !== 'not-found') throw new Error('unreachable');
  assert.equal(second.reason, 'reset-invalid');
});

test('opening a reset writes nothing to the account', async () => {
  // THE DIFFERENCE FROM THE MAILED RESET ADR-0004 DELETED. That one replaced
  // the verifier and the key records; this one hands over a code and leaves the
  // account exactly as it was. Whoever redeems it gets no login by doing so.
  const fixture = await withAccount();
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const token = fixture.mailer.resets[0]?.resetToken ?? '';
  const escrowBefore = fixture.store.escrowFor(1);

  assert.equal((await handleResetOpen({ resetToken: token }, fixture.ctx)).status, 'ok');

  // The old passphrase still logs in, the recovery code still authenticates,
  // and the escrow is untouched.
  assert.equal((await handleLogin({ email: EMAIL, authHash: AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.equal((await handleRecover({ email: EMAIL, recoveryAuthHash: RECOVERY_AUTH_HASH }, fixture.ctx)).status, 'ok');
  assert.deepEqual(fixture.store.escrowFor(1), escrowBefore);
  assert.deepEqual(fixture.store.keyRecordsFor(1).size, 2);
});

test('unknown, spent and expired tokens are ONE 404 after the same work', async () => {
  const fixture = await withAccount();
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const spent = fixture.mailer.resets[0]?.resetToken ?? '';
  assert.equal((await handleResetOpen({ resetToken: spent }, fixture.ctx)).status, 'ok');

  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const expiring = fixture.mailer.resets[1]?.resetToken ?? '';
  fixture.advance(RESET_TOKEN_TTL_MS + 1000);

  const outcomes = [
    await handleResetOpen({ resetToken: spent }, fixture.ctx),
    await handleResetOpen({ resetToken: expiring }, fixture.ctx),
    await handleResetOpen({ resetToken: 'sr_never-minted' }, fixture.ctx),
    // A signup invite and a session token pasted into the wrong endpoint.
    await handleResetOpen({ resetToken: INVITE_TOKEN }, fixture.ctx),
    await handleResetOpen({ resetToken: 'token-1' }, fixture.ctx),
    // No token, and a token of the wrong JSON type.
    await handleResetOpen({}, fixture.ctx),
    await handleResetOpen({ resetToken: 42 }, fixture.ctx),
  ];

  const answers = new Set(outcomes.map((outcome) => JSON.stringify(outcome)));
  assert.equal(answers.size, 1, `every reset failure must read identically, got ${[...answers].join(' | ')}`);
});

test('a reset token lives one hour and not a minute more', async () => {
  const fixture = await withAccount();
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const token = fixture.mailer.resets[0]?.resetToken ?? '';

  // A minute before the TTL, it still opens.
  fixture.advance(RESET_TOKEN_TTL_MS - 60_000);
  const early = await handleResetOpen({ resetToken: token }, fixture.ctx);
  assert.equal(early.status, 'ok');

  // A fresh one, and this time past the boundary.
  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const second = fixture.mailer.resets[1]?.resetToken ?? '';
  fixture.advance(RESET_TOKEN_TTL_MS + 1);
  assert.equal((await handleResetOpen({ resetToken: second }, fixture.ctx)).status, 'not-found');
});

test('the recovery code never appears in a log line', async () => {
  // The code opens a diary, and a log line outlives the request by months.
  const lines: string[] = [];
  const fixture = await withAccount();
  fixture.ctx.logger = {
    debug: (message, fields) => lines.push(JSON.stringify({ message, fields })),
    info: (message, fields) => lines.push(JSON.stringify({ message, fields })),
    warn: (message, fields) => lines.push(JSON.stringify({ message, fields })),
    error: (message, fields) => lines.push(JSON.stringify({ message, fields })),
  };

  await handleResetRequest({ email: EMAIL }, fixture.ctx);
  const token = fixture.mailer.resets[0]?.resetToken ?? '';
  assert.equal((await handleResetOpen({ resetToken: token }, fixture.ctx)).status, 'ok');

  const serialized = lines.join('\n');
  // The positive half, so a handler that logged nothing would not pass by
  // silence: both steps ARE recorded.
  assert.ok(serialized.includes('Password reset requested'));
  assert.ok(serialized.includes('Password reset opened'));
  // The absence half.
  assert.ok(!serialized.includes(CANONICAL_CODE), 'the recovery code reached the log');
  assert.ok(!serialized.includes(token), 'the reset token reached the log');
  assert.ok(!serialized.includes(EMAIL), 'the address reached the log');
});
