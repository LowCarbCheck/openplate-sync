import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handlePushBlob } from '../../src/server/push-handler.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';

function ciphertext(): Uint8Array {
  return new TextEncoder().encode('opaque-ciphertext-bytes');
}

test('the first push for an account (baseVersion 0) is accepted and returns newVersion 1', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePushBlob(
    { accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  assert.deepEqual(result, { status: 'accepted', newVersion: 1 });
});

test('a push with a STALE baseVersion is rejected as a conflict, not a blind overwrite (D3)', async () => {
  const storage = createFakeStorageAdapter();
  await handlePushBlob({ accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() }, storage);
  // A second device, unaware of the first device's write, retries at the SAME stale baseVersion.
  const result = await handlePushBlob(
    { accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  assert.deepEqual(result, { status: 'conflict', currentVersion: 1 });
});

test('pushing at the CORRECT current version after a conflict succeeds (retry-after-merge flow)', async () => {
  const storage = createFakeStorageAdapter();
  await handlePushBlob({ accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() }, storage);
  const result = await handlePushBlob(
    { accountId: 1, baseVersion: 1, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  assert.deepEqual(result, { status: 'accepted', newVersion: 2 });
});

test('rejects a negative baseVersion as invalid, never reaching storage', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePushBlob(
    { accountId: 1, baseVersion: -1, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  assert.equal(result.status, 'invalid');
  assert.equal(await storage.getBlob(1), null);
});

test('rejects an empty ciphertext as invalid', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePushBlob(
    { accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: new Uint8Array(0) },
    storage,
  );
  assert.equal(result.status, 'invalid');
});

test('two different accounts have independent version counters', async () => {
  const storage = createFakeStorageAdapter();
  const resultA = await handlePushBlob(
    { accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  const resultB = await handlePushBlob(
    { accountId: 2, baseVersion: 0, envelopeVersion: 1, ciphertext: ciphertext() },
    storage,
  );
  assert.deepEqual(resultA, { status: 'accepted', newVersion: 1 });
  assert.deepEqual(resultB, { status: 'accepted', newVersion: 1 });
});
