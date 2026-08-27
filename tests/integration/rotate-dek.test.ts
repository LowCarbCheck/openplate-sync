/**
 * `POST /v1/sync/rotate-dek` — ADR-0002's Tier 2 revocation, against a real
 * Postgres and the committed migrations.
 *
 * WHY THIS SUITE EXISTS RATHER THAN HANDLER UNIT TESTS. The property under
 * test is atomicity, and atomicity is not a property of the handler — it is a
 * property of one Postgres transaction. A fake store can be made to "roll
 * back" by writing nothing, which proves nothing at all. Every assertion
 * below therefore reads the state back through the REAL endpoints (or, where
 * only the database can answer, through the pool) after a submission that was
 * refused part-way through.
 *
 * WHAT THE SERVER CAN AND CANNOT PROVE ABOUT "the old DEK opens nothing".
 * The cryptographic claim is a client-side one: the service holds no key and
 * never will. What is provable here, and what the third test asserts, is
 * everything the server contributes to that claim — that every wrap of the
 * old DEK it was holding is gone, that the ciphertext it now serves is the
 * post-rotation blob rather than the one the old DEK sealed, and that a
 * revoked grantee is served nothing at all.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
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

interface KeyRecordList {
  records: { kind: string; wrappedDek: string; updatedAt: string }[];
}

interface GrantorShareList {
  shares: { granteeAccountId: number; recipientKeyFingerprint: string; updatedAt: string }[];
}

interface GranteeShareList {
  shares: { grantorAccountId: number; wrappedDek: string }[];
}

interface BlobBody {
  blobVersion: number;
  ciphertext: string;
}

interface RotationBody {
  newVersion: number;
  keptShares: number;
  revokedShares: number;
}

interface ConflictBody {
  currentVersion: number;
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

async function signUp(email: string, seed: number): Promise<Party> {
  const response = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { email, authHash: sampleAuthHash(seed), kdfDescriptor: sampleKdfDescriptor(seed) },
  });
  assert.equal(response.status, 201, `signup for ${email}`);
  assert.ok(response.body.tokens);
  return { accountId: response.body.account.id, accessToken: response.body.tokens.accessToken };
}

/** The pre-rotation wraps, so every "did it change" assertion compares against known bytes. */
const OLD_PASSPHRASE_WRAP = sampleWrappedDek(11);
const OLD_RECOVERY_WRAP = sampleWrappedDek(12);
const NEW_PASSPHRASE_WRAP = sampleWrappedDek(21);
const NEW_RECOVERY_WRAP = sampleWrappedDek(22);
const OLD_SHARE_WRAP = sampleShareWrap(31);
const NEW_SHARE_WRAP = sampleShareWrap(41);
const OLD_CIPHERTEXT = sampleCiphertext(17, 512);
const NEW_CIPHERTEXT = sampleCiphertext(23, 512);

/** An account set up the way a real one is: one blob, both key records. */
async function setUpOwner(): Promise<Party> {
  const owner = await signUp('patient@example.test', 41);

  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: owner.accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: OLD_CIPHERTEXT },
  });
  assert.equal(push.status, 200);

  const passphrase = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken: owner.accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(41), wrappedDek: OLD_PASSPHRASE_WRAP, expectedUpdatedAt: null },
  });
  assert.equal(passphrase.status, 200);

  const recovery = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken: owner.accessToken,
    body: { kdfDescriptor: null, wrappedDek: OLD_RECOVERY_WRAP, expectedUpdatedAt: null },
  });
  assert.equal(recovery.status, 200);

  return owner;
}

async function grant(owner: Party, grantee: Party, wrap: string): Promise<void> {
  const response = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${grantee.accountId}`,
    accessToken: owner.accessToken,
    body: { wrappedDek: wrap, recipientKeyFingerprint: FINGERPRINT, expectedUpdatedAt: null },
  });
  assert.equal(response.status, 200, 'grant');
}

function rotationBody(shares: { granteeAccountId: number; wrappedDek: string }[], baseVersion = 1) {
  return {
    blob: { baseVersion, envelopeVersion: 1, ciphertext: NEW_CIPHERTEXT },
    keyRecords: [
      { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(77), wrappedDek: NEW_PASSPHRASE_WRAP },
      { kind: 'recovery', kdfDescriptor: null, wrappedDek: NEW_RECOVERY_WRAP },
    ],
    shares: shares.map((share) => ({ ...share, recipientKeyFingerprint: FINGERPRINT })),
  };
}

async function readBlob(party: Party): Promise<BlobBody> {
  const response = await service.request<BlobBody>({
    method: 'GET',
    path: '/v1/sync/blob',
    accessToken: party.accessToken,
  });
  assert.equal(response.status, 200);
  return response.body;
}

async function readKeyRecords(party: Party): Promise<Map<string, { wrappedDek: string; updatedAt: string }>> {
  const response = await service.request<KeyRecordList>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken: party.accessToken,
  });
  assert.equal(response.status, 200);
  return new Map(response.body.records.map((record) => [record.kind, record]));
}

test('rotation is atomic: a submission refused part-way leaves the account exactly as it was', async () => {
  const owner = await setUpOwner();
  const clinician = await signUp('clinician@example.test', 42);
  await grant(owner, clinician, OLD_SHARE_WRAP);

  const beforeRotation = await readKeyRecords(owner);

  // THE INJECTED FAILURE. A keep list naming an account with no share row
  // fails INSIDE the transaction, and it fails LATE — after the new blob
  // version has been inserted and both key records have been re-wrapped.
  // Everything those two steps wrote must be gone when this returns.
  const stranger = await signUp('stranger@example.test', 43);
  const refused = await service.request({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([
      { granteeAccountId: clinician.accountId, wrappedDek: NEW_SHARE_WRAP },
      { granteeAccountId: stranger.accountId, wrappedDek: NEW_SHARE_WRAP },
    ]),
  });
  assert.equal(refused.status, 400);

  const blob = await readBlob(owner);
  assert.equal(blob.blobVersion, 1, 'the blob write must have rolled back');
  assert.equal(blob.ciphertext, OLD_CIPHERTEXT, 'the pre-rotation ciphertext must still be what is served');

  const afterRotation = await readKeyRecords(owner);
  assert.equal(
    afterRotation.get('passphrase')?.wrappedDek,
    OLD_PASSPHRASE_WRAP,
    'the passphrase wrap must have rolled back',
  );
  assert.equal(afterRotation.get('recovery')?.wrappedDek, OLD_RECOVERY_WRAP, 'the recovery wrap must have rolled back');
  assert.equal(
    afterRotation.get('passphrase')?.updatedAt,
    beforeRotation.get('passphrase')?.updatedAt,
    'a rolled-back rotation must not even move the CAS token',
  );

  // And the share the submission DID name correctly is untouched — neither
  // re-wrapped nor revoked by the delete clause that ran before the failure.
  const received = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: clinician.accessToken,
  });
  assert.equal(received.status, 200);
  assert.equal(received.body.shares.length, 1, 'the share delete must have rolled back too');
  assert.equal(received.body.shares[0]?.wrappedDek, OLD_SHARE_WRAP);
});

test('rotation revokes omitted shares and re-wraps the ones it keeps', async () => {
  const owner = await setUpOwner();
  const kept = await signUp('kept@example.test', 42);
  const dropped = await signUp('dropped@example.test', 43);
  await grant(owner, kept, OLD_SHARE_WRAP);
  await grant(owner, dropped, OLD_SHARE_WRAP);

  // SILENCE IS REVOCATION: `dropped` is simply not named.
  const rotated = await service.request<RotationBody>({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([{ granteeAccountId: kept.accountId, wrappedDek: NEW_SHARE_WRAP }]),
  });
  assert.equal(rotated.status, 200);
  assert.equal(rotated.body.newVersion, 2);
  assert.equal(rotated.body.keptShares, 1);
  assert.equal(rotated.body.revokedShares, 1);

  const keptView = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: kept.accessToken,
  });
  assert.equal(keptView.body.shares.length, 1, 'a resubmitted share survives');
  assert.equal(keptView.body.shares[0]?.wrappedDek, NEW_SHARE_WRAP, 'and carries its NEW wrap');

  const droppedView = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: dropped.accessToken,
  });
  assert.equal(droppedView.body.shares.length, 0, 'an omitted share is deleted in the same transaction');

  const grantorView = await service.request<GrantorShareList>({
    method: 'GET',
    path: '/v1/sync/shares',
    accessToken: owner.accessToken,
  });
  assert.deepEqual(
    grantorView.body.shares.map((share) => share.granteeAccountId),
    [kept.accountId],
  );
});

test('old DEK opens nothing after rotation: every wrap the server held for it is gone', async () => {
  const owner = await setUpOwner();
  const revoked = await signUp('revoked@example.test', 42);
  const kept = await signUp('kept@example.test', 43);
  await grant(owner, revoked, OLD_SHARE_WRAP);
  await grant(owner, kept, OLD_SHARE_WRAP);

  const rotation = await service.request({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([{ granteeAccountId: kept.accountId, wrappedDek: NEW_SHARE_WRAP }]),
  });
  assert.equal(rotation.status, 200);

  // 1. The revoked grantee is served nothing — not their wrap, not the blob.
  const revokedList = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: revoked.accessToken,
  });
  assert.equal(revokedList.body.shares.length, 0);
  const revokedBlob = await service.request({
    method: 'GET',
    path: `/v1/sync/shared/${owner.accountId}/blob`,
    accessToken: revoked.accessToken,
  });
  assert.equal(revokedBlob.status, 404);

  // 2. Not one wrap of the old DEK survives anywhere the server can hand out:
  //    not in a share row, not in either key record.
  const remainingWraps = await database.pool.query<{ wrapped_dek: Buffer }>(
    'SELECT wrapped_dek FROM sync_shares WHERE account_id = $1',
    [owner.accountId],
  );
  const oldShareBytes = Buffer.from(OLD_SHARE_WRAP, 'base64');
  for (const row of remainingWraps.rows) {
    assert.ok(!row.wrapped_dek.equals(oldShareBytes), 'no share may still carry a wrap of the old DEK');
  }
  const records = await readKeyRecords(owner);
  assert.equal(records.get('passphrase')?.wrappedDek, NEW_PASSPHRASE_WRAP);
  assert.equal(records.get('recovery')?.wrappedDek, NEW_RECOVERY_WRAP);

  // 3. What the kept grantee is served is the POST-rotation ciphertext — the
  //    bytes the old DEK sealed are no longer what this endpoint returns.
  const keptBlob = await service.request<BlobBody & { grantorAccountId: number }>({
    method: 'GET',
    path: `/v1/sync/shared/${owner.accountId}/blob`,
    accessToken: kept.accessToken,
  });
  assert.equal(keptBlob.status, 200);
  assert.equal(keptBlob.body.blobVersion, 2);
  assert.equal(keptBlob.body.ciphertext, NEW_CIPHERTEXT);
  assert.notEqual(keptBlob.body.ciphertext, OLD_CIPHERTEXT);
});

test('rotation CAS: a stale baseVersion is refused, and the tokens a rotation writes survive the wire', async () => {
  const owner = await setUpOwner();
  const clinician = await signUp('clinician@example.test', 42);
  await grant(owner, clinician, OLD_SHARE_WRAP);

  // A second push moves the blob to version 2 while the client still believes 1.
  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: owner.accessToken,
    body: { baseVersion: 1, envelopeVersion: 1, ciphertext: sampleCiphertext(19, 256) },
  });
  assert.equal(push.status, 200);

  const stale = await service.request<ConflictBody>({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([{ granteeAccountId: clinician.accountId, wrappedDek: NEW_SHARE_WRAP }], 1),
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.currentVersion, 2);

  // Nothing of the refused rotation landed: the share still holds the old wrap.
  const untouched = await service.request<GranteeShareList>({
    method: 'GET',
    path: '/v1/sync/shared',
    accessToken: clinician.accessToken,
  });
  assert.equal(untouched.body.shares[0]?.wrappedDek, OLD_SHARE_WRAP);

  // The same submission at the CURRENT version is accepted.
  const rotated = await service.request<RotationBody>({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([{ granteeAccountId: clinician.accountId, wrappedDek: NEW_SHARE_WRAP }], 2),
  });
  assert.equal(rotated.status, 200);
  assert.equal(rotated.body.newVersion, 3);

  // THE CAS TOKENS THIS ROTATION WROTE MUST ROUND-TRIP THROUGH ISO-8601.
  //
  // This is the bug that shipped once already (M160/06): a timestamp stored
  // at microsecond precision leaves as a millisecond ISO string, so the token
  // a client reads back is a TRUNCATION of what is stored and the exact-match
  // CAS can never hold again — every later rotation 409s forever. Passing an
  // in-memory `Date` here would prove nothing; these tokens are read out of
  // JSON responses as strings and handed straight back, exactly as a client
  // does.
  const records = await readKeyRecords(owner);
  const passphraseToken = records.get('passphrase')?.updatedAt;
  assert.ok(passphraseToken);
  const reRotate = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken: owner.accessToken,
    body: {
      kdfDescriptor: sampleKdfDescriptor(88),
      wrappedDek: sampleWrappedDek(31),
      expectedUpdatedAt: passphraseToken,
    },
  });
  assert.equal(reRotate.status, 200, 'the key-record token a rotation wrote must still satisfy the CAS');

  const grants = await service.request<GrantorShareList>({
    method: 'GET',
    path: '/v1/sync/shares',
    accessToken: owner.accessToken,
  });
  const shareToken = grants.body.shares[0]?.updatedAt;
  assert.ok(shareToken);
  const reGrant = await service.request({
    method: 'PUT',
    path: `/v1/sync/shares/${clinician.accountId}`,
    accessToken: owner.accessToken,
    body: {
      wrappedDek: sampleShareWrap(51),
      recipientKeyFingerprint: FINGERPRINT,
      expectedUpdatedAt: shareToken,
    },
  });
  assert.equal(reGrant.status, 200, 'the share token a rotation wrote must still satisfy the CAS');
});
