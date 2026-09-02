/**
 * The admin API against a real Postgres and the committed migrations.
 *
 * TWO THINGS HERE CANNOT BE PROVEN WITH THE UNIT FAKES, and they are the
 * reason this file exists rather than another unit test:
 *
 * 1. **The deletion really cascades.** `AccountStore.deleteAccount` is one
 *    `DELETE FROM accounts`; everything else goes because `account_tokens`,
 *    `sync_blobs` and `sync_key_records` carry `ON DELETE CASCADE`. That is a
 *    property of the schema, so only the schema can demonstrate it — a fake
 *    that deletes the right maps proves the fake, not the database. This is
 *    the DSAR mechanism, and "we can show that it erased everything" is the
 *    obligation it was built for.
 *
 * 2. **The metadata is right, and the secrets are absent for real.** The rows
 *    here hold a genuine verifier, a genuine KDF descriptor, genuine wrapped
 *    DEKs and genuine ciphertext, put there by the ordinary user-facing
 *    endpoints. Asserting that none of it comes back out is a claim about the
 *    real query path (`db/admin-store.ts`), which is where a stray `select()`
 *    would live.
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

const ADMIN_TOKEN = 'integration-admin-token-0123456789abcdef';
const HANDLE = 'admin-subject';
const AUTH_HASH = sampleAuthHash(31);
const CIPHERTEXT = sampleCiphertext(5, 1024);
const WRAPPED_DEK = sampleWrappedDek(13);

interface SessionBody {
  account: { id: number; handle: string };
  tokens: { accessToken: string; refreshToken: string } | null;
}

interface AccountBody {
  account: {
    id: number;
    handle: string;
    createdAt: string;
    blob: { sizeBytes: number; updatedAt: string } | null;
    keyRecordKinds: string[];
  };
}

interface AccountListBody {
  accounts: AccountBody['account'][];
  total: number;
  limit: number;
  offset: number;
}

interface StatsBody {
  stats: {
    accounts: number;
    verifiedAccounts: number;
    accountsWithBlob: number;
    blobVersions: number;
    keyRecords: number;
    blobBytes: number;
  };
}

let database: TestDatabase;
let service: ServiceHarness;

before(async () => {
  database = await setupTestDatabase();
  service = await startService({ db: database.db, adminToken: ADMIN_TOKEN });
});

after(async () => {
  await service.close();
  await database.close();
});

beforeEach(async () => {
  await database.reset();
});

/** A fully-furnished account: session tokens, both key records, and a pushed blob. */
async function seedFurnishedAccount(): Promise<{ accountId: number; accessToken: string }> {
  const signup = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { handle: HANDLE, authHash: AUTH_HASH, kdfDescriptor: sampleKdfDescriptor(), displayName: 'Admin Subject' },
  });
  assert.equal(signup.status, 201);
  // Read without an `assert.ok(... !== undefined)` narrowing call: an
  // assertion function forces every later `const` in the same scope to carry
  // an explicit annotation (TS7022), which is noise this file does not need.
  const accessToken = signup.body.tokens?.accessToken ?? '';
  const accountId = signup.body.account.id;
  assert.notEqual(accessToken, '', 'signup must issue a session');

  for (const kind of ['passphrase', 'recovery']) {
    const put = await service.request({
      method: 'PUT',
      path: `/v1/sync/key-records/${kind}`,
      accessToken,
      body: {
        kdfDescriptor: kind === 'passphrase' ? sampleKdfDescriptor(2) : null,
        wrappedDek: WRAPPED_DEK,
        expectedUpdatedAt: null,
      },
    });
    assert.equal(put.status, 200, `${kind} key record must be stored`);
  }

  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: CIPHERTEXT },
  });
  assert.equal(push.status, 200);

  return { accountId, accessToken };
}

test('the metadata endpoints describe the real rows', async () => {
  const { accountId } = await seedFurnishedAccount();

  const single = await service.request<AccountBody>({
    method: 'GET',
    path: `/v1/admin/accounts/${accountId}`,
    adminToken: ADMIN_TOKEN,
  });
  assert.equal(single.status, 200);
  assert.equal(single.body.account.handle, HANDLE);
  // 1024 base64 characters decode to 768 bytes — the DECODED length is what
  // `size_bytes` holds and what an operator is told.
  assert.equal(single.body.account.blob?.sizeBytes, Buffer.from(CIPHERTEXT, 'base64').byteLength);
  assert.deepEqual(single.body.account.keyRecordKinds, ['passphrase', 'recovery']);

  const list = await service.request<AccountListBody>({
    method: 'GET',
    path: '/v1/admin/accounts',
    adminToken: ADMIN_TOKEN,
  });
  assert.equal(list.status, 200);
  assert.equal(list.body.total, 1);
  assert.equal(list.body.accounts[0]?.id, accountId);

  const stats = await service.request<StatsBody>({
    method: 'GET',
    path: '/v1/admin/stats',
    adminToken: ADMIN_TOKEN,
  });
  assert.equal(stats.status, 200);
  assert.equal(stats.body.stats.accounts, 1);
  assert.equal(stats.body.stats.accountsWithBlob, 1);
  assert.equal(stats.body.stats.keyRecords, 2);
  assert.equal(stats.body.stats.blobBytes, Buffer.from(CIPHERTEXT, 'base64').byteLength);
});

test('no admin response carries the ciphertext, the wrapped DEK, the verifier or the KDF descriptor', async () => {
  const { accountId } = await seedFurnishedAccount();

  // The real values, read straight out of Postgres — so the absence assertions
  // below are about material that genuinely exists for this account.
  const [accountRow] = await database.db.select().from(accounts).where(eq(accounts.id, accountId));
  const [blobRow] = await database.db.select().from(syncBlobs).where(eq(syncBlobs.accountId, accountId));
  const [tokenRow] = await database.db.select().from(accountTokens).where(eq(accountTokens.accountId, accountId));

  const forbiddenValues = [
    accountRow?.verifier,
    accountRow?.kdfDescriptor.salt,
    tokenRow?.tokenHash,
    blobRow?.ciphertext.toString('base64'),
    WRAPPED_DEK,
  ].filter((value): value is string => value !== undefined);

  // The seeded account really does hold all five, so the absence assertions
  // below are about material that exists rather than about an empty list.
  assert.equal(forbiddenValues.length, 5, 'the fixture must hold every forbidden value');

  for (const path of ['/v1/admin/accounts', `/v1/admin/accounts/${accountId}`, '/v1/admin/stats']) {
    const response = await fetch(`${service.baseUrl}${path}`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` },
    });
    assert.equal(response.status, 200, path);
    const body = await response.text();

    for (const value of forbiddenValues) {
      assert.ok(!body.includes(value), `${path} leaked a real stored secret`);
    }
    for (const name of ['ciphertext', 'verifier', 'kdfDescriptor', 'wrappedDek', 'tokenHash']) {
      assert.ok(!body.includes(name), `${path} names the forbidden field "${name}"`);
    }
  }
});

test('DELETE erases the account and every dependent row', async () => {
  const { accountId } = await seedFurnishedAccount();

  // Everything is genuinely there first — otherwise "it is gone" proves
  // nothing at all.
  assert.equal((await database.db.select().from(accounts).where(eq(accounts.id, accountId))).length, 1);
  assert.ok((await database.db.select().from(accountTokens).where(eq(accountTokens.accountId, accountId))).length > 0);
  assert.equal((await database.db.select().from(syncBlobs).where(eq(syncBlobs.accountId, accountId))).length, 1);
  assert.equal(
    (await database.db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId))).length,
    2,
  );

  const response = await service.request({
    method: 'DELETE',
    path: `/v1/admin/accounts/${accountId}`,
    adminToken: ADMIN_TOKEN,
  });
  assert.equal(response.status, 204);

  assert.deepEqual(await database.db.select().from(accounts).where(eq(accounts.id, accountId)), []);
  assert.deepEqual(await database.db.select().from(accountTokens).where(eq(accountTokens.accountId, accountId)), []);
  assert.deepEqual(await database.db.select().from(syncBlobs).where(eq(syncBlobs.accountId, accountId)), []);
  assert.deepEqual(await database.db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId)), []);

  // And the surface agrees with the tables.
  const afterDeletion = await service.request({
    method: 'GET',
    path: `/v1/admin/accounts/${accountId}`,
    adminToken: ADMIN_TOKEN,
  });
  assert.equal(afterDeletion.status, 404);
});

test("a deleted account's session token no longer authenticates anything", async () => {
  const { accountId, accessToken } = await seedFurnishedAccount();

  await service.request({ method: 'DELETE', path: `/v1/admin/accounts/${accountId}`, adminToken: ADMIN_TOKEN });

  // The token row went with the account, so the bearer middleware cannot
  // resolve it — erasure that left a working session behind would not be
  // erasure.
  const pull = await service.request({ method: 'GET', path: '/v1/sync/blob', accessToken });
  assert.equal(pull.status, 401);
});
