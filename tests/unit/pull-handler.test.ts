import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handlePullBlob } from '../../src/server/pull-handler.js';
import { handlePushBlob } from '../../src/server/push-handler.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';

test('pulling for an account with no blob yet returns not-found', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePullBlob(1, storage);
  assert.deepEqual(result, { status: 'not-found' });
});

test('pulling after a push returns the just-pushed blob', async () => {
  const storage = createFakeStorageAdapter();
  const ciphertext = new TextEncoder().encode('the blob');
  await handlePushBlob({ accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext }, storage);

  const result = await handlePullBlob(1, storage);
  assert.equal(result.status, 'found');
  if (result.status === 'found') {
    assert.equal(result.blob.blobVersion, 1);
    assert.equal(result.blob.envelopeVersion, 1);
    assert.deepEqual(result.blob.ciphertext, ciphertext);
  }
});

test('a pull for account 2 never sees account 1 data', async () => {
  const storage = createFakeStorageAdapter();
  await handlePushBlob(
    { accountId: 1, baseVersion: 0, envelopeVersion: 1, ciphertext: new TextEncoder().encode('account 1') },
    storage,
  );
  const result = await handlePullBlob(2, storage);
  assert.deepEqual(result, { status: 'not-found' });
});
