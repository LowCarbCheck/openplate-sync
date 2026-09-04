/**
 * The mailed password reset against REAL Postgres: `POST /v1/auth/reset/request`,
 * `POST /v1/auth/reset/open`, and the ceremony that follows.
 *
 * WHY THIS SUITE EXISTS RATHER THAN MORE HANDLER UNIT TESTS. Two properties
 * here are properties of the database, not of the handler:
 *
 *  - **A reset token is single-use under concurrency.** The spend is one
 *    `UPDATE … WHERE consumed_at IS NULL AND expires_at > now RETURNING`, and a
 *    read-then-write would let two requests both be told the recovery code. A
 *    JavaScript Map cannot fail that way, so a fake cannot prove it.
 *  - **The round trip actually restores the account.** The code that comes back
 *    out of `accounts.recovery_code_escrow` must be the code the client sealed
 *    at signup, well enough to derive a proof the server accepts. That crosses
 *    the escrow, the column, and the recovery verifier.
 *
 * The suite mints the recovery proof the way a client does, which is why
 * `RECOVERY_AUTH_HASH` is a fixed value rather than derived: this service never
 * sees a recovery code except as an escrow, so the proof and the code are
 * independent inputs from its point of view, and the test asserts that BOTH
 * survive the round trip.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { eq } from 'drizzle-orm';
import { accounts, passwordResets } from '../../src/db/schema.js';
import { RESET_TOKEN_TTL_MS } from '../../src/lib/tokens.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

const EMAIL = 'forgetful@example.org';
const AUTH_HASH = sampleAuthHash(11);
const NEW_AUTH_HASH = sampleAuthHash(12);
const RECOVERY_AUTH_HASH = sampleAuthHash(31);
const NEW_RECOVERY_AUTH_HASH = sampleAuthHash(32);
const RECOVERY_CODE = sampleRecoveryCode(0);
const NEW_RECOVERY_CODE = sampleRecoveryCode(3);
/** The canonical form the server seals and returns: grouping removed, uppercased. */
const CANONICAL_CODE = RECOVERY_CODE.replaceAll('-', '');

let database: TestDatabase;
let service: ServiceHarness;

before(async () => {
  database = await setupTestDatabase();
  service = await startService({ db: database.db });
});

after(async () => {
  await service.close();
  await database.close();
});

beforeEach(async () => {
  await database.reset();
});

async function setUpAccount(): Promise<number> {
  const session = await service.signupThroughInvite({
    email: EMAIL,
    authHash: AUTH_HASH,
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    recoveryCode: RECOVERY_CODE,
  });
  return session.account.id;
}

/** Asks for a reset and returns the token the mailer was handed. */
async function requestReset(email: string): Promise<string | null> {
  const sentSoFar = service.mailer.resets.length;
  const response = await service.request({ method: 'POST', path: '/v1/auth/reset/request', body: { email } });
  assert.equal(response.status, 202, `reset/request for ${email}`);
  return service.mailer.resets.length > sentSoFar ? (service.mailer.resets.at(-1)?.resetToken ?? null) : null;
}

test('the whole way back: forget the passphrase, open the mail, set a new one, and the diary is still there', async () => {
  const accountId = await setUpAccount();

  // The account has a blob before anything, so "the diary is still there" is a
  // claim about bytes rather than about a login.
  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: (
      await service.request<{ tokens: { accessToken: string } }>({
        method: 'POST',
        path: '/v1/auth/login',
        body: { email: EMAIL, authHash: AUTH_HASH },
      })
    ).body.tokens.accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: Buffer.alloc(256, 7).toString('base64') },
  });
  assert.equal(push.status, 200);

  // 1. "Forgot password".
  const token = await requestReset(EMAIL);
  assert.ok(token !== null, 'a known address must be mailed a reset');

  // 2. The link hands back the escrowed code, and the address it belongs to.
  const opened = await service.request<{ email: string; recoveryCode: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken: token },
  });
  assert.equal(opened.status, 200);
  assert.equal(opened.body.email, EMAIL);
  assert.equal(opened.body.recoveryCode, CANONICAL_CODE, 'the code must survive the escrow byte for byte');

  // 3. THE ORDINARY CEREMONY, with the code the mail delivered. Nothing about
  //    this call is reset-specific: it is exactly §5.14.
  const rotated = await service.request<{ tokens: { accessToken: string } }>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: {
      email: EMAIL,
      recoveryAuthHash: RECOVERY_AUTH_HASH,
      newAuthHash: NEW_AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(2),
      newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
      recoveryCode: NEW_RECOVERY_CODE,
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(61) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(62) },
      ],
    },
  });
  assert.equal(rotated.status, 200);

  // 4. The new passphrase works, the old one is dead, and the blob is still
  //    where it was — the whole point of an escrowed code over a mailed link.
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/login', body: { email: EMAIL, authHash: AUTH_HASH } }))
      .status,
    401,
  );
  const pulled = await service.request<{ blobVersion: number }>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: rotated.body.tokens.accessToken,
  });
  assert.equal(pulled.status, 200);
  assert.equal(pulled.body.blobVersion, 1);

  // 5. And the NEXT reset delivers the NEW code, so the escrow moved with the
  //    verifier rather than going stale.
  const second = await requestReset(EMAIL);
  assert.ok(second !== null);
  const reopened = await service.request<{ recoveryCode: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken: second },
  });
  assert.equal(reopened.body.recoveryCode, NEW_RECOVERY_CODE.replaceAll('-', ''));
  assert.equal(await countLiveResets(accountId), 0);
});

/** How many unconsumed, unexpired reset rows the account has. */
async function countLiveResets(accountId: number): Promise<number> {
  const rows = await database.db.select().from(passwordResets).where(eq(passwordResets.accountId, accountId));
  return rows.filter((row) => row.consumedAt === null).length;
}

test('a reset for an unknown address is the same 202, and writes nothing', async () => {
  await setUpAccount();
  const rowsBefore = await database.db.select().from(passwordResets);

  const token = await requestReset('nobody@example.org');
  assert.equal(token, null, 'an unknown address must not be mailed');

  const rowsAfter = await database.db.select().from(passwordResets);
  assert.equal(rowsAfter.length, rowsBefore.length, 'an unknown address must not write a row');
});

test('a reset token is spent exactly once, even under concurrent redemption', async () => {
  await setUpAccount();
  const token = await requestReset(EMAIL);
  assert.ok(token !== null);

  // Fired together, deliberately not awaited in sequence. With a
  // read-then-write both would pass the read and both would be told the code.
  const attempts = await Promise.all(
    [1, 2, 3].map(() =>
      service.request<{ recoveryCode?: string; error?: string }>({
        method: 'POST',
        path: '/v1/auth/reset/open',
        body: { resetToken: token },
      }),
    ),
  );

  const opened = attempts.filter((response) => response.status === 200);
  const refused = attempts.filter((response) => response.status === 404);
  assert.equal(opened.length, 1, `expected exactly one redemption, got ${opened.length}`);
  assert.equal(refused.length, 2);
  for (const response of refused) assert.equal(response.body.error, 'reset-invalid');
});

test('a new request supersedes the older live token in the same transaction', async () => {
  const accountId = await setUpAccount();

  const first = await requestReset(EMAIL);
  const second = await requestReset(EMAIL);
  assert.ok(first !== null && second !== null);
  assert.notEqual(first, second);

  // ONE live row: two letters in a mailbox, both live, is a second copy of a
  // credential that hands over a recovery code.
  assert.equal(await countLiveResets(accountId), 1);
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/reset/open', body: { resetToken: first } })).status,
    404,
  );
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/reset/open', body: { resetToken: second } })).status,
    200,
  );
});

test('an expired token is refused with the same body an unknown one gets', async () => {
  await setUpAccount();
  const token = await requestReset(EMAIL);
  assert.ok(token !== null);

  service.advance(RESET_TOKEN_TTL_MS + 1000);

  const expired = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken: token },
  });
  const unknown = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken: 'sr_never-minted' },
  });
  assert.equal(expired.status, 404);
  assert.deepEqual(expired.body, unknown.body);
});

test('deleting an account takes its reset tokens with it', async () => {
  const accountId = await setUpAccount();
  await requestReset(EMAIL);
  assert.equal((await database.db.select().from(passwordResets)).length, 1);

  await database.db.delete(accounts).where(eq(accounts.id, accountId));

  // The cascade, which is what makes erasure complete without a cleanup job.
  assert.deepEqual(await database.db.select().from(passwordResets), []);
});
