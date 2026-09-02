/**
 * `POST /v1/auth/recover` and `POST /v1/auth/recover-rotate` — the second
 * authenticator, against a real Postgres and the committed migrations.
 *
 * WHY THIS SUITE EXISTS RATHER THAN MORE HANDLER UNIT TESTS. The property
 * under test is ATOMICITY, and atomicity is not a property of the handler —
 * it is a property of one Postgres transaction. The unit suite's fake store
 * can be made to "roll back" by simply writing nothing, which proves exactly
 * nothing about the real one. Every assertion below reads state back through
 * the REAL endpoints after a rotation that was interrupted part-way through.
 *
 * HOW THE INTERRUPTION IS INJECTED, and why it is honest. There is no test
 * hook in the production code. The suite adds a `CHECK (false) NOT VALID`
 * constraint to `sync_key_records`, which Postgres enforces on new writes and
 * ignores for existing rows. The rotation's transaction therefore updates the
 * account's verifiers, reaches the key-record upsert, and dies there — a real
 * database failure at exactly the step between "the verifier moved" and "the
 * re-wrapped DEK landed". That half-state is the whole reason the method
 * exists: it would leave a user who logs in with a new passphrase and
 * decrypts nothing.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

const HANDLE = 'bright-otter-42';
const OLD_AUTH_HASH = sampleAuthHash(11);
const NEW_AUTH_HASH = sampleAuthHash(12);
const RECOVERY_AUTH_HASH = sampleAuthHash(31);
const NEW_RECOVERY_AUTH_HASH = sampleAuthHash(32);
const OLD_PASSPHRASE_WRAP = sampleWrappedDek(51);
const OLD_RECOVERY_WRAP = sampleWrappedDek(52);
const NEW_PASSPHRASE_WRAP = sampleWrappedDek(61);
const NEW_RECOVERY_WRAP = sampleWrappedDek(62);

interface SessionBody {
  account: { id: number; handle: string };
  tokens: { accessToken: string } | null;
}

interface KeyRecordList {
  records: { kind: string; wrappedDek: string }[];
}

interface ErrorBody {
  error: string;
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

/** An account set up the way a real one is: a recovery code, and both key records. */
async function setUpAccount(): Promise<{ accountId: number; accessToken: string }> {
  const signup = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: {
      handle: HANDLE,
      authHash: OLD_AUTH_HASH,
      kdfDescriptor: sampleKdfDescriptor(1),
      recoveryAuthHash: RECOVERY_AUTH_HASH,
    },
  });
  assert.equal(signup.status, 201);
  assert.ok(signup.body.tokens);
  const accessToken = signup.body.tokens.accessToken;

  const passphrase = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/passphrase',
    accessToken,
    body: { kdfDescriptor: sampleKdfDescriptor(1), wrappedDek: OLD_PASSPHRASE_WRAP, expectedUpdatedAt: null },
  });
  assert.equal(passphrase.status, 200);

  const recovery = await service.request({
    method: 'PUT',
    path: '/v1/sync/key-records/recovery',
    accessToken,
    body: { kdfDescriptor: null, wrappedDek: OLD_RECOVERY_WRAP, expectedUpdatedAt: null },
  });
  assert.equal(recovery.status, 200);

  return { accountId: signup.body.account.id, accessToken };
}

/** The `POST /v1/auth/recover-rotate` request body, named so a test overriding one field cannot invent another. */
interface RecoverRotateBody {
  handle: string;
  recoveryAuthHash: string;
  newAuthHash: string;
  newRecoveryAuthHash?: string;
  kdfDescriptor: ReturnType<typeof sampleKdfDescriptor>;
  keyRecords: { kind: string; kdfDescriptor: ReturnType<typeof sampleKdfDescriptor> | null; wrappedDek: string }[];
}

function recoverRotateBody(overrides: Partial<RecoverRotateBody> = {}): RecoverRotateBody {
  return {
    handle: HANDLE,
    recoveryAuthHash: RECOVERY_AUTH_HASH,
    newAuthHash: NEW_AUTH_HASH,
    kdfDescriptor: sampleKdfDescriptor(2),
    keyRecords: [{ kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: NEW_PASSPHRASE_WRAP }],
    ...overrides,
  };
}

async function login(authHash: string): Promise<number> {
  const response = await service.request({
    method: 'POST',
    path: '/v1/auth/login',
    body: { handle: HANDLE, authHash },
  });
  return response.status;
}

async function readKeyRecords(accessToken: string): Promise<Map<string, string>> {
  const response = await service.request<KeyRecordList>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken,
  });
  assert.equal(response.status, 200);
  return new Map(response.body.records.map((record) => [record.kind, record.wrappedDek]));
}

// ── The path the whole spec exists for ─────────────────────────────────────

test('recover, set a new passphrase, log in with it', async () => {
  await setUpAccount();

  // 1. The recovery code alone authenticates.
  const recovered = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: RECOVERY_AUTH_HASH },
  });
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.account.handle, HANDLE);

  // 2. It buys the right to set a new passphrase and re-wrap the DEK.
  const rotated = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: recoverRotateBody(),
  });
  assert.equal(rotated.status, 200);
  assert.ok(rotated.body.tokens);

  // 3. The new passphrase logs in; the old one is dead.
  assert.equal(await login(NEW_AUTH_HASH), 200);
  assert.equal(await login(OLD_AUTH_HASH), 401);

  // 4. And it can actually decrypt: the passphrase record carries the new
  //    wrap, while the untouched recovery record still carries the old one.
  const records = await readKeyRecords(rotated.body.tokens.accessToken);
  assert.equal(records.get('passphrase'), NEW_PASSPHRASE_WRAP);
  assert.equal(records.get('recovery'), OLD_RECOVERY_WRAP);
});

test('rotating the recovery code moves its verifier and its key record together', async () => {
  await setUpAccount();

  const rotated = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: recoverRotateBody({
      newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: NEW_PASSPHRASE_WRAP },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: NEW_RECOVERY_WRAP },
      ],
    }),
  });
  assert.equal(rotated.status, 200);
  assert.ok(rotated.body.tokens);

  // The code that now authenticates is the code that now unwraps.
  const withNewCode = await service.request({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: NEW_RECOVERY_AUTH_HASH },
  });
  assert.equal(withNewCode.status, 200);
  const withOldCode = await service.request({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: RECOVERY_AUTH_HASH },
  });
  assert.equal(withOldCode.status, 401);

  const records = await readKeyRecords(rotated.body.tokens.accessToken);
  assert.equal(records.get('recovery'), NEW_RECOVERY_WRAP);
});

// ── One generic failure ────────────────────────────────────────────────────

test('an unknown handle and a wrong recovery code produce the SAME failure', async () => {
  await setUpAccount();

  const unknownHandle = await service.request<ErrorBody>({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: 'nobody-at-all', recoveryAuthHash: RECOVERY_AUTH_HASH },
  });
  const wrongCode = await service.request<ErrorBody>({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: NEW_RECOVERY_AUTH_HASH },
  });

  assert.equal(unknownHandle.status, 401);
  assert.equal(wrongCode.status, 401);
  // Byte-identical, not merely "both a 401". A different sentence would be an
  // enumeration oracle wearing the same status code.
  assert.deepEqual(unknownHandle.body, wrongCode.body);

  // The rotation endpoint answers the same way, and it must: it is reached
  // with a guessed code far more often than the read-only one is.
  const rotateUnknown = await service.request<ErrorBody>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: recoverRotateBody({ handle: 'nobody-at-all' }),
  });
  const rotateWrong = await service.request<ErrorBody>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: recoverRotateBody({ recoveryAuthHash: NEW_RECOVERY_AUTH_HASH }),
  });
  assert.equal(rotateUnknown.status, 401);
  assert.deepEqual(rotateUnknown.body, rotateWrong.body);
});

// ── The adversarial half-update test ───────────────────────────────────────

test('a rotation interrupted between the verifier and the key record is rolled back whole', async () => {
  const account = await setUpAccount();

  // Injects the failure. `NOT VALID` means Postgres enforces this on writes
  // and never checks the rows already there, so the setup above survives and
  // the very next key-record write dies. That write is the step immediately
  // after the verifier update inside the rotation's transaction.
  await database.pool.query('ALTER TABLE sync_key_records ADD CONSTRAINT tmp_break_rotation CHECK (false) NOT VALID');

  try {
    const interrupted = await service.request({
      method: 'POST',
      path: '/v1/auth/recover-rotate',
      body: recoverRotateBody({
        newRecoveryAuthHash: NEW_RECOVERY_AUTH_HASH,
        keyRecords: [
          { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: NEW_PASSPHRASE_WRAP },
          { kind: 'recovery', kdfDescriptor: null, wrappedDek: NEW_RECOVERY_WRAP },
        ],
      }),
    });
    // The failure is a fault, not a refusal: the caller is told nothing
    // happened, which is exactly true.
    assert.equal(interrupted.status, 500);
  } finally {
    await database.pool.query('ALTER TABLE sync_key_records DROP CONSTRAINT tmp_break_rotation');
  }

  // NOTHING WAS HALF-WRITTEN. Each assertion below names a distinct disaster
  // that a partial application would have caused.

  // (a) The OLD PASSPHRASE STILL WORKS, and the new one was never installed.
  //     Had the verifier committed alone, this account would log in with a
  //     passphrase whose KEK unwraps nothing.
  assert.equal(await login(OLD_AUTH_HASH), 200);
  assert.equal(await login(NEW_AUTH_HASH), 401);

  // (b) The old recovery code still authenticates and the new one does not.
  //     A rotated recovery verifier without its re-wrapped record would leave
  //     a code that logs in and then unwraps nothing.
  const oldCode = await service.request({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: RECOVERY_AUTH_HASH },
  });
  assert.equal(oldCode.status, 200);
  const newCode = await service.request({
    method: 'POST',
    path: '/v1/auth/recover',
    body: { handle: HANDLE, recoveryAuthHash: NEW_RECOVERY_AUTH_HASH },
  });
  assert.equal(newCode.status, 401);

  // (c) Both key records are byte-for-byte unchanged.
  const records = await readKeyRecords(account.accessToken);
  assert.equal(records.get('passphrase'), OLD_PASSPHRASE_WRAP);
  assert.equal(records.get('recovery'), OLD_RECOVERY_WRAP);

  // (d) The pre-rotation session was never revoked, because the revocation
  //     rode in the same transaction. `readKeyRecords` above already proved
  //     the token still resolves; stated here so the property is named.
  assert.ok(account.accessToken.length > 0);

  // (e) The account is not wedged: with the constraint gone, the same
  //     rotation now applies in full. A rollback that left invisible damage
  //     would surface here.
  const retried = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/recover-rotate',
    body: recoverRotateBody(),
  });
  assert.equal(retried.status, 200);
  assert.equal(await login(NEW_AUTH_HASH), 200);
});
