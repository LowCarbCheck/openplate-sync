/**
 * Validation of a rotation submission — the refusals that must happen BEFORE
 * a transaction is opened.
 *
 * The load-bearing assertion in most of these is not the status: it is that
 * `store.calls` stayed empty. A rotation that reaches the database and is
 * rejected there is a different (and worse) design than one refused up front,
 * and only the call log can tell the two apart.
 *
 * Atomicity is deliberately NOT tested here. It is a property of one Postgres
 * transaction, and a fake store can be made to "roll back" by writing
 * nothing, which proves nothing — see `tests/integration/rotate-dek.test.ts`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRotateDek, type RotateDekRequest } from '../../src/server/rotate-dek-handler.js';
import { SHARE_WRAPPED_DEK_BYTES } from '../../src/server/share-routes.js';
import { createFakeRotationStore } from './fake-rotation-store.js';

const KDF_DESCRIPTOR = { salt: 'AAAA', params: { memorySizeKib: 65536, iterations: 3, parallelism: 1 } };

function request(overrides: Partial<RotateDekRequest> = {}): RotateDekRequest {
  return {
    accountId: 1,
    blob: { baseVersion: 1, envelopeVersion: 1, ciphertext: new Uint8Array(64).fill(7) },
    keyRecords: [
      { kind: 'passphrase', kdfDescriptor: KDF_DESCRIPTOR, wrappedDek: new Uint8Array(60).fill(1) },
      { kind: 'recovery', kdfDescriptor: null, wrappedDek: new Uint8Array(60).fill(2) },
    ],
    shares: [],
    // Already derived by the route from `newRecoveryAuthHash` and
    // `recoveryCode` (M192 addendum): by the time the handler sees them they
    // are a verifier and a sealed blob, which is why "missing" is refused in
    // the route and not here.
    recoveryVerifier: 'a'.repeat(64),
    recoveryCodeEscrow: new Uint8Array(60).fill(9),
    sharingEnabled: true,
    ...overrides,
  };
}

function shareWrap(fill = 3): Uint8Array {
  return new Uint8Array(SHARE_WRAPPED_DEK_BYTES).fill(fill);
}

test('a complete submission reaches the store and reports what it did', async () => {
  const store = createFakeRotationStore();
  const result = await handleRotateDek(
    request({ shares: [{ granteeAccountId: 2, wrappedDek: shareWrap(), recipientKeyFingerprint: 'ABCD' }] }),
    store,
  );

  assert.equal(result.status, 'ok');
  assert.equal(store.calls.length, 1);
  assert.equal(store.calls[0]?.shares.length, 1);
});

test('a submission missing a key record kind is refused before any transaction opens', async () => {
  const store = createFakeRotationStore();
  const only = request().keyRecords.filter((record) => record.kind === 'passphrase');

  const result = await handleRotateDek(request({ keyRecords: only }), store);

  assert.equal(result.status, 'invalid');
  assert.match(result.status === 'invalid' ? result.reason : '', /both key record kinds/);
  assert.equal(store.calls.length, 0, 'a partial rotation must never reach the database');
});

test('the §5.4 kind rules still apply inside a rotation', async () => {
  const store = createFakeRotationStore();

  const recoveryWithDescriptor = await handleRotateDek(
    request({
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: KDF_DESCRIPTOR, wrappedDek: new Uint8Array(60).fill(1) },
        { kind: 'recovery', kdfDescriptor: KDF_DESCRIPTOR, wrappedDek: new Uint8Array(60).fill(2) },
      ],
    }),
    store,
  );
  assert.equal(recoveryWithDescriptor.status, 'invalid');

  const passphraseWithout = await handleRotateDek(
    request({
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: null, wrappedDek: new Uint8Array(60).fill(1) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: new Uint8Array(60).fill(2) },
      ],
    }),
    store,
  );
  assert.equal(passphraseWithout.status, 'invalid');
  assert.equal(store.calls.length, 0);
});

test('a duplicate grantee in the keep list is refused rather than resolved by array order', async () => {
  const store = createFakeRotationStore();

  const result = await handleRotateDek(
    request({
      shares: [
        { granteeAccountId: 2, wrappedDek: shareWrap(3), recipientKeyFingerprint: 'ABCD' },
        { granteeAccountId: 2, wrappedDek: shareWrap(4), recipientKeyFingerprint: 'ABCD' },
      ],
    }),
    store,
  );

  assert.equal(result.status, 'invalid');
  assert.equal(store.calls.length, 0);
});

test('a share wrap of the wrong length is refused — 125 bytes, not the key record 60', async () => {
  const store = createFakeRotationStore();

  const result = await handleRotateDek(
    request({ shares: [{ granteeAccountId: 2, wrappedDek: new Uint8Array(60), recipientKeyFingerprint: 'ABCD' }] }),
    store,
  );

  assert.equal(result.status, 'invalid');
  assert.equal(store.calls.length, 0);
});

test('an empty keep list is valid and means revoke everything', async () => {
  const store = createFakeRotationStore();

  const result = await handleRotateDek(request({ shares: [] }), store);

  assert.equal(result.status, 'ok');
  assert.equal(store.calls.length, 1);
  assert.deepEqual(store.calls[0]?.shares, []);
});

test('an instance without SYNC_SHARING rotates fine, but refuses a keep list', async () => {
  const store = createFakeRotationStore();

  // The whole point of not gating this route: an owner who has never shared
  // anything still gets to retire a DEK they believe leaked.
  const withoutShares = await handleRotateDek(request({ sharingEnabled: false, shares: [] }), store);
  assert.equal(withoutShares.status, 'ok');

  const withShares = await handleRotateDek(
    request({
      sharingEnabled: false,
      shares: [{ granteeAccountId: 2, wrappedDek: shareWrap(), recipientKeyFingerprint: 'ABCD' }],
    }),
    store,
  );
  assert.equal(withShares.status, 'invalid');
  assert.equal(store.calls.length, 1, 'only the first submission was allowed through');
});

test('the store conflict and unknown-share answers are carried back unchanged', async () => {
  const store = createFakeRotationStore();

  store.result = { ok: false, reason: 'blob-conflict', currentVersion: 9 };
  const conflict = await handleRotateDek(request(), store);
  assert.equal(conflict.status, 'conflict');
  assert.equal(conflict.status === 'conflict' ? conflict.currentVersion : 0, 9);

  store.result = { ok: false, reason: 'unknown-share', granteeAccountId: 4 };
  const unknown = await handleRotateDek(request(), store);
  assert.equal(unknown.status, 'unknown-share');
});
