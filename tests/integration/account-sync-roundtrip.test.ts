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
import { and, eq } from 'drizzle-orm';
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

const EMAIL = 'roundtrip@example.org';
const AUTH_HASH = sampleAuthHash(11);
const NEW_AUTH_HASH = sampleAuthHash(22);

interface SessionBody {
  account: { id: number; email: string };
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
  // Through an invite, because there is no other door on this service.
  const session = await service.signupThroughInvite({
    email: EMAIL,
    displayName: 'Round Trip',
    authHash: AUTH_HASH,
  });
  return {
    accountId: session.account.id,
    accessToken: session.tokens.accessToken,
    refreshToken: session.tokens.refreshToken,
  };
}

test('health reports the protocol handshake without authentication', async () => {
  const response = await service.request<{ protocolVersion: number; envelopeVersion: number; serviceVersion: string }>({
    method: 'GET',
    path: '/health',
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.protocolVersion, 2);
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

  // --- key record PUT (a rotation: signup already wrote both records) ---
  //
  // THE FIRST-TIME ASSERTION IS NOW THE CONFLICT CASE, and that is a stronger
  // test of the same rule than it used to be. `expectedUpdatedAt: null` says
  // "no record of this kind exists yet"; since M192 signup writes both, so the
  // claim is false and the CAS must refuse it rather than upsert over a wrap
  // the account's only copy of its data is sealed under.
  const wrappedDek = sampleWrappedDek(5);
  const seeded = await service.request<{ currentUpdatedAt: string | null }>({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(2), wrappedDek, expectedUpdatedAt: null },
  });
  assert.equal(seeded.status, 409, 'a first-time assertion against an existing record must conflict');
  assert.ok(seeded.body.currentUpdatedAt, 'and the 409 must name the token that would win');

  // Presenting the token it named wins, which is the other half of the promise.
  const put = await service.request<{ kind: string; updatedAt: string }>({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(2), wrappedDek, expectedUpdatedAt: seeded.body.currentUpdatedAt },
  });
  assert.equal(put.status, 200);
  assert.equal(put.body.kind, 'passphrase');

  // And replaying the token that just won must not: it is superseded now.
  const putAgain = await service.request<{ currentUpdatedAt: string | null }>({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(2), wrappedDek, expectedUpdatedAt: seeded.body.currentUpdatedAt },
  });
  assert.equal(putAgain.status, 409);

  const listed = await service.request<{ records: Array<{ kind: string; wrappedDek: string }> }>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken,
  });
  assert.equal(listed.status, 200);
  // Both kinds, because signup writes both (M192). The rotation above touched
  // exactly one of them, which is the other half of "kinds not submitted are
  // left untouched".
  assert.deepEqual(listed.body.records.map((record) => record.kind).toSorted(), ['passphrase', 'recovery']);
  // Byte-exact: any normalization here would destroy the wrapped DEK.
  assert.equal(listed.body.records.find((record) => record.kind === 'passphrase')?.wrappedDek, wrappedDek);

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

  const second = await service.signupThroughInvite({
    email: 'other-otter@example.org',
    authHash: sampleAuthHash(33),
  });

  const pull = await service.request<{ error: string }>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: second.tokens.accessToken,
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

test('the KDF endpoint answers for an unknown address in the same shape as a real one', async () => {
  await signUp();

  const real = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: EMAIL },
  });
  const dummy = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: 'never-registered@example.org' },
  });
  const dummyAgain = await service.request<{ kdfDescriptor: { salt: string } }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: 'never-registered@example.org' },
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
    (
      await service.request({
        method: 'POST',
        path: '/v1/auth/login',
        body: { email: EMAIL, authHash: NEW_AUTH_HASH },
      })
    ).status,
    200,
  );
  // SCOPED TO THE KIND, because the account has two records since M192 and an
  // unscoped `[record] =` picks whichever row Postgres returns first. It read
  // the untouched `recovery` wrap and compared it to the new `passphrase` one.
  const [record] = await database.db
    .select()
    .from(syncKeyRecords)
    .where(and(eq(syncKeyRecords.accountId, accountId), eq(syncKeyRecords.kind, 'passphrase')));
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

test('a string that is not an address is refused by the real service, at kdf and at login', async () => {
  // M181's `@` rejection, INVERTED. An address is the identity now, so what
  // gets refused is a handle-shaped string with no mailbox in it. Asserted
  // against the real Express stack rather than the input parser alone.
  const kdf = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/kdf',
    body: { email: 'bright-otter-42' },
  });
  assert.equal(kdf.status, 400);
  assert.match(kdf.body.error, /@/);

  const login = await service.request<{ error: string }>({
    method: 'POST',
    path: '/v1/auth/login',
    body: { email: 'bright-otter-42', authHash: AUTH_HASH },
  });
  assert.equal(login.status, 400);

  // And nothing was written.
  const rows = await database.db.select().from(accounts);
  assert.equal(rows.length, 0);
});

test('case-folded and NFKC-equivalent addresses reach the one account', async () => {
  await signUp();

  // Every spelling normalises to the SAME stored address, so each reaches the
  // ORIGINAL account rather than nothing. Proven against Postgres because the
  // guarantee is the unique index and the canonical form, not the parser.
  for (const spelling of ['  ROUNDTRIP@Example.ORG ', 'ｒoundtrip@example.org']) {
    const login = await service.request<SessionBody>({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email: spelling, authHash: AUTH_HASH },
    });
    assert.equal(login.status, 200, `${spelling} must log in`);
    assert.equal(login.body.account.email, EMAIL);
  }

  const rows = await database.db.select().from(accounts);
  assert.equal(rows.length, 1);
});

test('PATCH /v1/auth/account edits the display name and nothing else', async () => {
  const { accessToken } = await signUp();

  const renamed = await service.request<SessionBody>({
    method: 'PATCH',
    path: '/v1/auth/account',
    accessToken,
    body: { displayName: 'Renamed', role: 'admin', dailyAiLimit: 500, email: 'someone-else@example.org' },
  });
  assert.equal(renamed.status, 200);
  // Standing is granted by an operator, never asked for by the account, and
  // the address is the identity rather than a field.
  assert.equal(renamed.body.account.email, EMAIL);

  const [row] = await database.db.select().from(accounts).where(eq(accounts.email, EMAIL));
  assert.equal(row?.displayName, 'Renamed');
  assert.equal(row?.role, 'member');
  assert.equal(row?.dailyAiLimit, 0);
});

test('the removed link endpoints are gone, not merely unreachable', async () => {
  // A 404 rather than a 400 or a 405: the routes do not exist, so an old
  // client fails closed instead of half-working. See PROTOCOL.md §6.
  for (const path of ['/v1/auth/verify-email', '/v1/auth/request-reset', '/v1/auth/reset']) {
    const response = await service.request<{ error: string }>({ method: 'POST', path, body: {} });
    assert.equal(response.status, 404, `${path} must not exist`);
  }
});

test('an unknown endpoint returns the documented JSON error shape', async () => {
  const response = await service.request<{ error: string }>({ method: 'GET', path: '/v1/nope' });
  assert.equal(response.status, 404);
  assert.notEqual(response.body.error.length, 0);
});

/**
 * The regression suite for the key-record CAS precision bug (M160 spec 06).
 *
 * Every OTHER CAS test in this repo hands `putKeyRecord` a `Date` it still
 * holds in memory, at whatever precision the database chose. These two go the
 * long way round instead — token out as an ISO-8601 string on the wire, token
 * back in as that same string — because the truncation only happens on that
 * trip, and skipping it is exactly why the bug survived to production.
 */

interface KeyRecordBody {
  kind: string;
  wrappedDek: string;
  updatedAt: string;
}

interface ConflictBody {
  currentUpdatedAt: string | null;
}

/**
 * Puts a known wrap on the account's `recovery` record and returns its token
 * exactly as a client sees it.
 *
 * A ROTATION, NOT A CREATION: signup wrote the record, so the CAS token is the
 * one it is carrying and `null` would be the 409 that says "a record already
 * exists". Named for what a client does — read the current token, then write.
 */
async function seedRecoveryRecord(accessToken: string, seed: number): Promise<string> {
  const current = await service.currentKeyRecordToken({ accessToken, kind: 'recovery' });
  const created = await service.request<KeyRecordBody>({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: sampleWrappedDek(seed), expectedUpdatedAt: current },
  });
  assert.equal(created.status, 200);
  return created.body.updatedAt;
}

test('key-record rotation survives a wire round-trip of its CAS token', async () => {
  const { accountId, accessToken } = await signUp();
  await seedRecoveryRecord(accessToken, 41);

  // The token as `regenerateRecoveryCode()` obtains it: from the LIST response,
  // already serialised to JSON and parsed back. This is the whole point of the
  // test — the value below is a string, not a `Date` kept from the insert.
  const listed = await service.request<{ records: KeyRecordBody[] }>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken,
  });
  assert.equal(listed.status, 200);
  // Found by KIND rather than by position: the account carries two records
  // since M192, and `records[0]` is whichever one Postgres returned first.
  const observedToken = listed.body.records.find((record) => record.kind === 'recovery')?.updatedAt;
  assert.ok(observedToken, 'the recovery record must be listed');

  // ISO-8601 as this protocol emits it carries exactly three fractional
  // digits. Anything the column can hold beyond them is unrepresentable here,
  // and would be silently dropped on the way out.
  assert.match(observedToken, /\.\d{3}Z$/);

  // ...and the stored value must be fully expressible in that format, or the
  // client is holding a truncation and the exact-equality CAS can never match.
  //
  // Read as TEXT deliberately. `pg` parses a `timestamp` into a JS `Date`,
  // which is millisecond-only, so a driver-parsed value would agree with the
  // wire even when the column holds a microsecond tail — the assertion would
  // look right and prove nothing. Postgres's own rendering is the only view
  // here that can still see the digits at issue.
  const stored = await database.pool.query<{ updatedAtText: string }>(
    `SELECT updated_at::text AS "updatedAtText" FROM sync_key_records WHERE account_id = $1 AND kind = 'recovery'`,
    [accountId],
  );
  assert.equal(stored.rows.length, 1);
  assert.equal(
    new Date(`${stored.rows[0]?.updatedAtText.replace(' ', 'T')}Z`).toISOString(),
    observedToken,
    'the wire token must be the whole stored value, not a truncation of it',
  );
  assert.doesNotMatch(
    stored.rows[0]?.updatedAtText ?? '',
    /\.\d{4,}$/,
    'the column must not be able to hold a sub-millisecond tail the wire cannot carry',
  );

  const rotatedDek = sampleWrappedDek(42);
  const rotated = await service.request<KeyRecordBody>({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: rotatedDek, expectedUpdatedAt: observedToken },
  });
  assert.equal(rotated.status, 200, 'a token read back over the wire must still win its CAS');
  assert.equal(rotated.body.wrappedDek, rotatedDek);
  assert.notEqual(rotated.body.updatedAt, observedToken, 'a successful rotation must mint a new token');
});

test('a stale token loses its key-record CAS, and the 409 reports a token that works', async () => {
  const { accessToken } = await signUp();
  const staleToken = await seedRecoveryRecord(accessToken, 51);

  const rotated = await service.request<KeyRecordBody>({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: sampleWrappedDek(52), expectedUpdatedAt: staleToken },
  });
  assert.equal(rotated.status, 200);
  const currentToken = rotated.body.updatedAt;

  // Replaying the now-superseded token is the genuine conflict this CAS exists
  // for, and it must still be refused.
  const replayed = await service.request<ConflictBody>({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: sampleWrappedDek(53), expectedUpdatedAt: staleToken },
  });
  assert.equal(replayed.status, 409);
  assert.equal(replayed.body.currentUpdatedAt, currentToken, 'the 409 must name the REAL current token');

  // And the retry the client is invited to make has to be able to succeed —
  // the half of the promise the precision bug quietly broke.
  const retried = await service.request<KeyRecordBody>({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: sampleWrappedDek(54), expectedUpdatedAt: replayed.body.currentUpdatedAt },
  });
  assert.equal(retried.status, 200, 'the token the 409 reported must be usable on the retry');
});
