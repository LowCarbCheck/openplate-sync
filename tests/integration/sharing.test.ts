/**
 * The share family of ADR-0002, against a real Postgres and the committed
 * migrations.
 *
 * What is only provable here, and is therefore why this suite exists rather
 * than a set of handler unit tests:
 *   - both `ON DELETE CASCADE`s actually removing the row, from either end
 *   - the `UNIQUE (account_id, grantee_account_id)` index backing the CAS
 *   - the `CHECK (account_id <> grantee_account_id)` refusing a self-share
 *   - byte-exact round-tripping of the 125-byte wrap through `bytea`
 *   - that a revoke committed one request ago is already effective, because
 *     the authorisation row is read on every request and never cached
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { eq } from 'drizzle-orm';
import { accounts, syncShares } from '../../src/db/schema.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleCiphertext,
  sampleKdfDescriptor,
  sampleShareWrap,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

const FINGERPRINT = 'K3TB-9WQZ-4M7N';

interface SessionBody {
  account: { id: number };
  tokens: { accessToken: string } | null;
}

interface Party {
  accountId: number;
  accessToken: string;
}

interface GrantorShareList {
  shares: { granteeAccountId: number; recipientKeyFingerprint: string; updatedAt: string }[];
}

interface GranteeShareList {
  shares: { grantorAccountId: number; wrappedDek: string; recipientKeyFingerprint: string }[];
}

interface SharedBlobBody {
  grantorAccountId: number;
  blobVersion: number;
  envelopeVersion: number;
  ciphertext: string;
  createdAt: string;
}

let database: TestDatabase;
let service: ServiceHarness;

before(async () => {
  database = await setupTestDatabase();
  service = await startService({ db: database.db, sharing: true });
});

after(async () => {
  await service.close();
  await database.close();
});

beforeEach(async () => {
  await database.reset();
});

async function signUp(handle: string, seed: number): Promise<Party> {
  const response = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { handle, authHash: sampleAuthHash(seed), kdfDescriptor: sampleKdfDescriptor(seed) },
  });
  assert.equal(response.status, 201, `signup for ${handle}`);
  assert.ok(response.body.tokens);
  return { accountId: response.body.account.id, accessToken: response.body.tokens.accessToken };
}

/** A patient who has pushed one blob, and a clinician holding a grant on it. */
async function grantedPair(): Promise<{ patient: Party; clinician: Party; ciphertext: string }> {
  const patient = await signUp('patient', 41);
  const clinician = await signUp('clinician', 42);
  const ciphertext = sampleCiphertext(17, 512);

  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: patient.accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext },
  });
  assert.equal(push.status, 200);

  const grant = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
    body: { wrappedDek: sampleShareWrap(), recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(grant.status, 200);

  return { patient, clinician, ciphertext };
}

test('a grantor grants, lists and re-wraps a share under compare-and-swap', async () => {
  const { patient, clinician } = await grantedPair();

  const listed = await service.request<GrantorShareList>({
    method: 'GET',
    path: '/v1/sync/shares',
    accessToken: patient.accessToken,
  });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.shares.length, 1);
  assert.equal(listed.body.shares[0]?.granteeAccountId, clinician.accountId);
  assert.equal(listed.body.shares[0]?.recipientKeyFingerprint, FINGERPRINT);
  // The wrap is addressed to the clinician's key; the patient has no use for
  // it, so it does not go where nobody needs it (ADR-0002).
  assert.equal(
    Object.hasOwn(listed.body.shares[0] ?? {}, 'wrappedDek'),
    false,
    'the grantor list must never carry the wrap',
  );

  // A second first-time grant loses the CAS to the row that already exists.
  const stale = await service.request<{ currentUpdatedAt: string }>({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
    body: { wrappedDek: sampleShareWrap(6), recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.currentUpdatedAt, listed.body.shares[0]?.updatedAt);

  // The re-wrap a DEK rotation produces: same pair, new wrap, CAS honoured.
  const rewrap = await service.request<{ updatedAt: string }>({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
    body: {
      wrappedDek: sampleShareWrap(6),
      recipientKeyFingerprint: FINGERPRINT,
      expectedUpdatedAt: listed.body.shares[0]?.updatedAt,
    },
  });
  assert.equal(rewrap.status, 200);

  const received = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: clinician.accessToken,
  });
  assert.equal(received.status, 200);
  assert.equal(received.body.shares[0]?.grantorAccountId, patient.accountId);
  // Byte-exact: any re-encoding of the wrap destroys the GCM tag with it.
  assert.equal(received.body.shares[0]?.wrappedDek, sampleShareWrap(6));
});

test('an absent expectedUpdatedAt is a 400, and a self-share is refused', async () => {
  const patient = await signUp('cas', 43);
  const clinician = await signUp('cas-grantee', 44);

  // PROTOCOL.md §5.4's rule, transplanted: a caller must not be able to skip
  // the concurrency check by forgetting a field.
  const absent = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
    body: { wrappedDek: sampleShareWrap(), recipientKeyFingerprint: FINGERPRINT },
  });
  assert.equal(absent.status, 400);

  const selfShare = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${patient.accountId}`,
    accessToken: patient.accessToken,
    body: { wrappedDek: sampleShareWrap(), recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(selfShare.status, 400);

  const wrongSizeWrap = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
    body: { wrappedDek: sampleWrappedDek(), recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(wrongSizeWrap.status, 400, 'a 60-byte key-record wrap is not a 125-byte share wrap');
});

test('the shared blob carries grantorAccountId, without which the AAD cannot be rebuilt', async () => {
  const { patient, clinician, ciphertext } = await grantedPair();

  const shared = await service.request<SharedBlobBody>({
    method: 'GET',
    path: `/v1/sync/shared/${patient.accountId}/blob`,
    accessToken: clinician.accessToken,
  });
  assert.equal(shared.status, 200);
  // The blob's own AAD binds the grantor's account id (PROTOCOL.md §3.2), so a
  // grantee who does not learn it here cannot decrypt this response at all.
  assert.equal(shared.body.grantorAccountId, patient.accountId);
  assert.equal(shared.body.blobVersion, 1);
  assert.equal(shared.body.envelopeVersion, 1);
  assert.equal(shared.body.ciphertext, ciphertext);
});

test('revoke from the grantor end is effective on the very next request', async () => {
  const { patient, clinician } = await grantedPair();
  const path = `/v1/sync/shared/${patient.accountId}/blob`;

  const beforeRevoke = await service.request({ method: 'GET', path, accessToken: clinician.accessToken });
  assert.equal(beforeRevoke.status, 200);

  const revoke = await service.request({
    method: 'DELETE',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
  });
  assert.equal(revoke.status, 204);

  // No cache, no grace period: the authorisation row is read on every request.
  const afterRevoke = await service.request({ method: 'GET', path, accessToken: clinician.accessToken });
  assert.equal(afterRevoke.status, 404);

  // Hard delete, not a tombstone — there is no row left to carry an assertion
  // that this care relationship ever existed (ADR-0002).
  const rows = await database.db.select().from(syncShares).where(eq(syncShares.accountId, patient.accountId));
  assert.deepEqual(rows, []);

  // Idempotent: revoking again is still a 204.
  const again = await service.request({
    method: 'DELETE',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: patient.accessToken,
  });
  assert.equal(again.status, 204);
});

test('a grantee can revoke a share aimed at them, so nobody can park junk in their list', async () => {
  const { patient, clinician } = await grantedPair();

  const drop = await service.request({
    method: 'DELETE',
    path: `/v1/sync/shared/${patient.accountId}`,
    accessToken: clinician.accessToken,
  });
  assert.equal(drop.status, 204);

  const received = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: clinician.accessToken,
  });
  assert.deepEqual(received.body.shares, []);

  const grantorView = await service.request<GrantorShareList>({
    method: 'GET',
    path: '/v1/sync/shares',
    accessToken: patient.accessToken,
  });
  assert.deepEqual(grantorView.body.shares, []);
});

test('grantee is read-only: no key records, no push, no history, no third-party blob', async () => {
  const { patient, clinician } = await grantedPair();

  // The patient's key records exist, and are the thing that must stay out of
  // reach: a grantee who could pull the `recovery` wrap would be one
  // brute-forced recovery code away from rotation authority over the account.
  const seedRecord = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken: patient.accessToken,
    body: { kdfDescriptor: null, wrappedDek: sampleWrappedDek(), expectedUpdatedAt: null },
  });
  assert.equal(seedRecord.status, 200);

  // There is no grantee route to them, under any spelling.
  for (const path of [
    `/v1/sync/shared/${patient.accountId}/key-records`,
    `/v1/sync/shared/${patient.accountId}/key-records/recovery`,
    `/v1/sync/shared/${patient.accountId}/blob/1`,
    `/v1/sync/shared/${patient.accountId}/account`,
  ]) {
    const response = await service.request({ method: 'GET', path, accessToken: clinician.accessToken });
    assert.equal(response.status, 404, `${path} must not exist`);
  }

  // And no write verb against the grantor, either.
  for (const method of ['POST', 'PUT', 'PATCH']) {
    const response = await service.request({
      method,
      path: `/v1/sync/shared/${patient.accountId}/blob`,
      accessToken: clinician.accessToken,
      body: { baseVersion: 1, envelopeVersion: 1, ciphertext: sampleCiphertext(99, 64) },
    });
    assert.equal(response.status, 404, `${method} on a shared blob must not exist`);
  }

  // The owner-only routes still resolve to the CALLER, never to the grantor:
  // holding a share must not turn the clinician into the patient.
  const ownRecords = await service.request<{ records: unknown[] }>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken: clinician.accessToken,
  });
  assert.equal(ownRecords.status, 200);
  assert.deepEqual(ownRecords.body.records, [], "the grantee's own key records, not the grantor's");

  const ownBlob = await service.request({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: clinician.accessToken,
  });
  assert.equal(ownBlob.status, 404, "the grantee has pushed no blob of their own, and must not see the grantor's");

  // The patient's blob is still at version 1 — nothing the grantee did wrote.
  const patientBlob = await service.request<{ blobVersion: number }>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: patient.accessToken,
  });
  assert.equal(patientBlob.body.blobVersion, 1);
});

test('both cascades: deleting either account removes the share row', async () => {
  const first = await grantedPair();
  await database.db.delete(accounts).where(eq(accounts.id, first.patient.accountId));
  assert.deepEqual(await database.db.select().from(syncShares), [], 'deleting the grantor kills the grant it made');

  await database.reset();

  const second = await grantedPair();
  await database.db.delete(accounts).where(eq(accounts.id, second.clinician.accountId));
  assert.deepEqual(await database.db.select().from(syncShares), [], 'deleting the grantee kills the wrap aimed at it');
});

test('a missing share, a foreign share and an un-pushed grantor are indistinguishable', async () => {
  const { patient, clinician } = await grantedPair();
  const stranger = await signUp('stranger', 45);

  // A grantor who exists and has pushed, but granted nothing to this caller.
  const unpushed = await signUp('quiet', 46);
  const quietGrant = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: unpushed.accessToken,
    body: { wrappedDek: sampleShareWrap(8), recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(quietGrant.status, 200, 'granted, but this account has never pushed a blob');

  const probes: readonly { label: string; path: string; accessToken: string }[] = [
    // Granted, but the grantor has never pushed a blob.
    {
      label: 'un-pushed grantor',
      path: `/v1/sync/shared/${unpushed.accountId}/blob`,
      accessToken: clinician.accessToken,
    },
    // A real, live share — but between two other people.
    { label: 'foreign share', path: `/v1/sync/shared/${patient.accountId}/blob`, accessToken: stranger.accessToken },
    // An account that exists and has a blob, but granted nothing to anybody here.
    { label: 'no share at all', path: `/v1/sync/shared/${patient.accountId}/blob`, accessToken: unpushed.accessToken },
    // An account id that does not exist. Absence of a share must not confirm
    // that an account exists — so this must be the same answer as the rest.
    { label: 'no such account', path: '/v1/sync/shared/999999/blob', accessToken: clinician.accessToken },
  ];

  const answers: string[] = [];
  for (const probe of probes) {
    const response = await fetch(`${service.baseUrl}${probe.path}`, {
      headers: { authorization: `Bearer ${probe.accessToken}` },
    });
    assert.equal(response.status, 404, `${probe.label} must be 404`);
    answers.push(`${response.status} ${await response.text()}`);
  }
  for (const answer of answers) {
    assert.equal(answer, answers[0], 'every share 404 must be byte-for-byte identical');
  }
});
