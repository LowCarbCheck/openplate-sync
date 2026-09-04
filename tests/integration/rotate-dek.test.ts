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
import { eq } from 'drizzle-orm';
import { accounts } from '../../src/db/schema.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleRecoveryCode,
  sampleCiphertext,
  sampleKdfDescriptor,
  sampleShareWrap,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

const FINGERPRINT = 'K3TB-9WQZ-4M7N';

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

/**
 * An account, created the only way this service can: an invite is minted and
 * redeemed. `signupThroughInvite` is the harness's helper for exactly that.
 */
async function signUp(name: string, seed: number): Promise<Party> {
  const session = await service.signupThroughInvite({
    email: `${name}@example.org`,
    authHash: sampleAuthHash(seed),
  });
  return { accountId: session.account.id, accessToken: session.tokens.accessToken };
}

/** The pre-rotation wraps, so every "did it change" assertion compares against known bytes. */
const OLD_PASSPHRASE_WRAP = sampleWrappedDek(11);
const OLD_RECOVERY_WRAP = sampleWrappedDek(12);
const NEW_PASSPHRASE_WRAP = sampleWrappedDek(21);
const NEW_RECOVERY_WRAP = sampleWrappedDek(22);
const OLD_SHARE_WRAP = sampleShareWrap(31);
const NEW_SHARE_WRAP = sampleShareWrap(41);
const OLD_CIPHERTEXT = sampleCiphertext(17, 512);
/** The recovery credential every rotation below mints (M192 addendum). */
const NEW_RECOVERY_AUTH_HASH = sampleAuthHash(71);
const NEW_RECOVERY_CODE = sampleRecoveryCode(5);
const NEW_CIPHERTEXT = sampleCiphertext(23, 512);

/** An account set up the way a real one is: one blob, both key records. */
async function setUpOwner(): Promise<Party> {
  const owner = await signUp('patient', 41);

  const push = await service.request({
    method: 'POST',
    path: '/v1/sync/blob',
    accessToken: owner.accessToken,
    body: { baseVersion: 0, envelopeVersion: 1, ciphertext: OLD_CIPHERTEXT },
  });
  assert.equal(push.status, 200);

  // ROTATIONS, not creations: signup wrote both records since M192, so the CAS
  // token is the one each is carrying and `null` would be the 409 that says a
  // record already exists. These replace the harness's generic wraps with the
  // named ones every "did it change" assertion below compares against.
  const passphrase = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken: owner.accessToken,
    body: {
      kdfDescriptor: sampleKdfDescriptor(41),
      wrappedDek: OLD_PASSPHRASE_WRAP,
      expectedUpdatedAt: await service.currentKeyRecordToken({ accessToken: owner.accessToken, kind: 'passphrase' }),
    },
  });
  assert.equal(passphrase.status, 200);

  const recovery = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken: owner.accessToken,
    body: {
      kdfDescriptor: null,
      wrappedDek: OLD_RECOVERY_WRAP,
      expectedUpdatedAt: await service.currentKeyRecordToken({ accessToken: owner.accessToken, kind: 'recovery' }),
    },
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
    // BOTH REQUIRED (M192 addendum). The `recovery` wrap above is sealed under
    // a KEK derived from this code, so the account's recovery verifier and its
    // escrow move with it in the same transaction.
    newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
    recoveryCode: NEW_RECOVERY_CODE,
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
  const clinician = await signUp('clinician', 42);
  await grant(owner, clinician, OLD_SHARE_WRAP);

  const beforeRotation = await readKeyRecords(owner);

  // THE INJECTED FAILURE. A keep list naming an account with no share row
  // fails INSIDE the transaction, and it fails LATE — after the new blob
  // version has been inserted and both key records have been re-wrapped.
  // Everything those two steps wrote must be gone when this returns.
  const stranger = await signUp('stranger', 43);
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
  const kept = await signUp('kept', 42);
  const dropped = await signUp('dropped', 43);
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
  const revoked = await signUp('revoked', 42);
  const kept = await signUp('kept', 43);
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

test('a rotation without the new recovery credential is a 400, and nothing moves', async () => {
  // THE M192 ADDENDUM, pinned. The `recovery` key record a rotation re-wraps is
  // sealed under a KEK derived from a code the client has just minted, so a
  // rotation that left the account's recovery verifier and escrow on the OLD
  // code produced an escrowed code that authenticated and unwrapped nothing.
  // Latent since M181; fatal once a mailed reset started delivering that code.
  const owner = await setUpOwner();
  const complete = rotationBody([]);

  for (const missing of ['newRecoveryAuthHash', 'recoveryCode'] as const) {
    // Inference keeps the builder's own shape, so `delete` below names a key
    // the compiler knows exists rather than an open dictionary's.
    const body: Partial<ReturnType<typeof rotationBody>> = { ...complete };
    delete body[missing];
    const refused = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/sync/rotate-dek',
      accessToken: owner.accessToken,
      body,
    });
    assert.equal(refused.status, 400, `omitting ${missing} must be refused`);
    // The message NAMES the field: a client upgrading past the addendum has to
    // be able to tell which one it forgot.
    assert.match(refused.body.error, new RegExp(missing));
  }

  // A malformed code is refused too, by the same parser signup uses.
  const badCode = await service.request({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: { ...complete, recoveryCode: 'not-base32' },
  });
  assert.equal(badCode.status, 400);

  // And nothing moved: the blob is still at the version `setUpOwner` left.
  const blob = await readBlob(owner);
  assert.equal(blob.blobVersion, 1);
});

test('a rotation replaces the recovery verifier and the escrow in the same transaction', async () => {
  const owner = await setUpOwner();
  const [rowBefore] = await database.db.select().from(accounts).where(eq(accounts.id, owner.accountId));
  assert.ok(rowBefore?.recoveryCodeEscrow, 'signup must have written an escrow');

  const rotated = await service.request({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner.accessToken,
    body: rotationBody([]),
  });
  assert.equal(rotated.status, 200);

  const [rowAfter] = await database.db.select().from(accounts).where(eq(accounts.id, owner.accountId));
  assert.ok(rowAfter?.recoveryCodeEscrow);
  assert.notDeepEqual(rowAfter.recoveryCodeEscrow, rowBefore.recoveryCodeEscrow, 'the escrow must be re-sealed');
  assert.notEqual(rowAfter.recoveryVerifier, rowBefore.recoveryVerifier, 'the verifier must move with it');

  // THE PROPERTY ALL OF THAT EXISTS FOR: the NEW code is what a mailed reset
  // now hands back, and it is the code the re-wrapped `recovery` record is
  // sealed under. Read through the real endpoints, not out of the column.
  const requested = await service.request({
    method: 'POST',
    path: '/v1/auth/reset/request',
    body: { email: 'patient@example.org' },
  });
  assert.equal(requested.status, 202);
  const resetToken = service.mailer.resets.at(-1)?.resetToken;
  assert.ok(resetToken, 'a reset must have been mailed');

  const opened = await service.request<{ recoveryCode: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken },
  });
  assert.equal(opened.status, 200);
  assert.equal(opened.body.recoveryCode, NEW_RECOVERY_CODE.replaceAll('-', ''));

  // ...and it authenticates, which the OLD code no longer does.
  const recovered = await service.request({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { email: 'patient@example.org', recoveryAuthHash: NEW_RECOVERY_AUTH_HASH },
  });
  assert.equal(recovered.status, 200);
});

test('rotation CAS: a stale baseVersion is refused, and the tokens a rotation writes survive the wire', async () => {
  const owner = await setUpOwner();
  const clinician = await signUp('clinician', 42);
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
