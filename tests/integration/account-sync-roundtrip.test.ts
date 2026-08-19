/**
 * The end-to-end contract, against a real Postgres and the committed
 * migrations: signup → login → key-record PUT → blob push → pull → CAS 409 →
 * account delete, plus the properties that only a real database can prove.
 *
 * What is genuinely NOT testable with the unit fakes, and is therefore the
 * reason this suite exists:
 *   - `ON DELETE CASCADE` actually removing blobs and key records
 *   - the unique-index-backed CAS returning a conflict rather than throwing
 *   - `rotateCredential` committing as ONE transaction
 *   - byte-exact round-tripping of `bytea` (any re-encoding destroys the GCM
 *     tag and with it the user's data)
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { eq } from 'drizzle-orm';
import { accountTokens, accounts, syncBlobs, syncKeyRecords } from '../../src/db/schema.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleCiphertext,
  sampleKdfDescriptor,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

const EMAIL = 'roundtrip@example.test';
const AUTH_HASH = sampleAuthHash(11);
const NEW_AUTH_HASH = sampleAuthHash(22);

interface SessionBody {
  account: { id: number; email: string; emailVerified: boolean };
  tokens: { accessToken: string; refreshToken: string } | null;
}

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

async function signUp(): Promise<{ accountId: number; accessToken: string; refreshToken: string }> {
  const response = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { email: EMAIL, authHash: AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(), displayName: 'Round Trip' },
  });
  assert.equal(response.status, 201);
  assert.ok(response.body.tokens);
  return {
    accountId: response.body.account.id,
    accessToken: response.body.tokens.accessToken,
    refreshToken: response.body.tokens.refreshToken,
  };
}

test('health reports the protocol handshake without authentication', async () => {
  const response = await service.request<{ protocolVersion: number; envelopeVersion: number; serviceVersion: string }>({
    method: 'GET',
    path: '/health',
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.protocolVersion, 1);
  assert.equal(response.body.envelopeVersion, 1);
  assert.notEqual(response.body.serviceVersion.length, 0);
  // Wide-open CORS is what lets any client reach any instance; the bearer
  // model is what makes it safe (see `server/cors.ts`).
  assert.equal(response.headers.get('access-control-allow-origin'), '*');
});

test('the full round trip: signup, login, key record, push, pull, conflict, delete', async () => {
  const { accountId, accessToken } = await signUp();

  // --- login with the same auth hash yields a second, independent session ---
  const login = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/login',
    body: { email: EMAIL, authHash: AUTH_HASH },
  });
  assert.equal(login.status, 200);
  assert.ok(login.body.tokens);

  // --- key record PUT (first-time CAS: expectedUpdatedAt null) ---
  const wrappedDek = sampleWrappedDek(5);
  const put = await service.request<{ kind: string; updatedAt: string }>({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(2), wrappedDek, expectedUpdatedAt: null },
  });
  assert.equal(put.status, 200);
  assert.equal(put.body.kind, 'passphrase');

  // A repeat of the same first-time assertion must conflict, never upsert.
  const putAgain = await service.request<{ currentUpdatedAt: string | null }>({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(2), wrappedDek, expectedUpdatedAt: null },
  });
  assert.equal(putAgain.status, 409);

  const listed = await service.request<{ records: Array<{ kind: string; wrappedDek: string }> }>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken,
  });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.records.length, 1);
  // Byte-exact: any normalization here would destroy the wrapped DEK.
  assert.equal(listed.body.records[0]?.wrappedDek, wrappedDek);

  // --- blob push (CAS from version 0) ---
  const ciphertext = sampleCiphertext(4, 1024);
  const push = await service.request<{ newVersion: number }>({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext },
  });
  assert.equal(push.status, 200);
  assert.equal(push.body.newVersion, 1);

  // --- pull returns exactly what was pushed ---
  const pull = await service.request<{ blobVersion: number; ciphertext: string }>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken,
  });
  assert.equal(pull.status, 200);
  assert.equal(pull.body.blobVersion, 1);
  assert.equal(pull.body.ciphertext, ciphertext);

  // --- a stale baseVersion is a 409 carrying the real current version ---
  const conflict = await service.request<{ currentVersion: number }>({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: sampleCiphertext(6) },
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.currentVersion, 1);

  // --- delete cascades to every row this account owned ---
  const deleted = await service.request<never>({
    method: 'POST',
    path: '/v1/auth/delete',
    accessToken,
    body: { authHash: AUTH_HASH },
  });
  assert.equal(deleted.status, 204);

  assert.equal((await database.db.select().from(accounts).where(eq(accounts.id, accountId))).length, 0);
  assert.equal((await database.db.select().from(syncBlobs).where(eq(syncBlobs.accountId, accountId))).length, 0);
  assert.equal(
    (await database.db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId))).length,
    0,
  );
  assert.equal(
    (await database.db.select().from(accountTokens).where(eq(accountTokens.accountId, accountId))).length,
    0,
  );
});

test('sync endpoints refuse an unauthenticated caller with 401, not 403', async () => {
  await signUp();
  const response = await service.request<{ error: string }>({ method: 'GET', path: '/v1/sync/blob' });
  // 401 means "authenticate"; 403 would mean "you did, and still may not".
  assert.equal(response.status, 401);
  assert.notEqual(response.body.error.length, 0);
});

test('one account can never read another account blob', async () => {
  const first = await signUp();
  await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: first.accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: sampleCiphertext(8) },
  });

  const second = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { email: 'other@example.test', authHash: sampleAuthHash(33), kdfDescriptor: sampleKdfDescriptor(3) },
  });
  assert.equal(second.status, 201);
  assert.ok(second.body.tokens);

  const pull = await service.request<{ error: string }>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: second.body.tokens.accessToken,
  });
  assert.equal(pull.status, 404);
});

test('blob versions are retained to the documented cap and pruned oldest-first', async () => {
  const { accountId, accessToken } = await signUp();

  for (let version = 0; version < 7; version += 1) {
    const response = await service.request<{ newVersion: number }>({
      method: 'POST',
      path: '/v1/sync/blob',
      accessToken,
      body: { baseVersion: version, envelopeVersion: 1, ciphertext: sampleCiphertext(version + 1) },
    });
    assert.equal(response.status, 200);
  }

  const rows = await database.db.select().from(syncBlobs).where(eq(syncBlobs.accountId, accountId));
  assert.equal(rows.length, 5);
  const versions = rows.map((row) => row.blobVersion).toSorted((a, b) => a - b);
  assert.deepEqual(versions, [3, 4, 5, 6, 7]);
});

test('the KDF endpoint answers for an unknown email in the same shape as a real one', async () => {
  await signUp();

  const real = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: EMAIL },
  });
  const dummy = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: 'never-registered@example.test' },
  });
  const dummyAgain = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: 'never-registered@example.test' },
  });

  assert.equal(real.status, 200);
  assert.equal(dummy.status, 200);
  assert.deepEqual(dummy.body, dummyAgain.body);
  assert.deepEqual(Object.keys(real.body.kdfDescriptor).toSorted(), Object.keys(dummy.body.kdfDescriptor).toSorted());
});

test('refresh rotates against the database and the spent token stops working', async () => {
  const { refreshToken } = await signUp();

  const rotated = await service.request<{ tokens: { accessToken: string; refreshToken: string } }>({
    method: 'POST',
    path: '/v1/auth/refresh',
    body: { refreshToken },
  });
  assert.equal(rotated.status, 200);

  const replay = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/refresh',
    body: { refreshToken },
  });
  assert.equal(replay.status, 401);

  // Reuse detection revoked the family, so the rotated token dies too.
  const afterReuse = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/refresh',
    body: { refreshToken: rotated.body.tokens.refreshToken },
  });
  assert.equal(afterReuse.status, 401);
});

test('change-passphrase commits verifier and key record together and revokes other sessions', async () => {
  const { accountId, accessToken } = await signUp();

  // A second device, which must be logged out by the change.
  const otherLogin = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/login',
    body: { email: EMAIL, authHash: AUTH_HASH },
  });
  assert.ok(otherLogin.body.tokens);
  const otherAccessToken = otherLogin.body.tokens.accessToken;

  const rewrapped = sampleWrappedDek(21);
  const changed = await service.request<{ tokens: { accessToken: string } }>({
    method: 'POST',
    path: '/v1/auth/change-passphrase',
    accessToken,
    body: {
      currentAuthHash: AUTH_HASH,
      newAuthHash: NEW_AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(4),
      keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(4), wrappedDek: rewrapped }],
    },
  });
  assert.equal(changed.status, 200);

  // Verifier and key record moved together — the transaction's whole point.
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/login', body: { email: EMAIL, authHash: AUTH_HASH } }))
      .status,
    401,
  );
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/login', body: { email: EMAIL, authHash: NEW_AUTH_HASH } }))
      .status,
    200,
  );
  const [record] = await database.db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId));
  assert.equal(record?.wrappedDek.toString('base64'), rewrapped);

  // Old sessions gone, new one live.
  assert.equal(
    (await service.request({ method: 'GET', path: '/v1/auth/account', accessToken: otherAccessToken })).status,
    401,
  );
  assert.equal((await service.request({ method: 'GET', path: '/v1/auth/account', accessToken })).status, 401);
  assert.equal(
    (await service.request({ method: 'GET', path: '/v1/auth/account', accessToken: changed.body.tokens.accessToken }))
      .status,
    200,
  );
});

test('the reset link restores login and revokes every prior session', async () => {
  const { accessToken } = await signUp();
  service.sentMail.length = 0;

  const requested = await service.request<Record<string, never>>({
    method: 'POST',
    path: '/v1/auth/request-reset',
    body: { email: EMAIL },
  });
  assert.equal(requested.status, 202);

  const token = /token=([^\s]+)/.exec(service.sentMail[0]?.text ?? '')?.[1];
  assert.ok(token);

  const reset = await service.request<{ tokens: { accessToken: string } }>({
    method: 'POST',
    path: '/v1/auth/reset',
    body: {
      token,
      authHash: NEW_AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(5),
      keyRecords: [{ kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(31) }],
    },
  });
  assert.equal(reset.status, 200);

  assert.equal((await service.request({ method: 'GET', path: '/v1/auth/account', accessToken })).status, 401);
  assert.equal(
    (await service.request({ method: 'POST', path: '/v1/auth/login', body: { email: EMAIL, authHash: NEW_AUTH_HASH } }))
      .status,
    200,
  );
});

test('an unknown endpoint returns the documented JSON error shape', async () => {
  const response = await service.request<{ error: string }>({ method: 'GET', path: '/v1/nope' });
  assert.equal(response.status, 404);
  assert.notEqual(response.body.error.length, 0);
});
