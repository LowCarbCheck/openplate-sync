import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  handleDeleteKeyRecord,
  handleListKeyRecords,
  handlePutKeyRecord,
} from '../../src/server/key-records-handler.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';

function wrappedDek(): Uint8Array {
  return new TextEncoder().encode('opaque-wrapped-dek-bytes');
}

test('putting a passphrase key record requires a kdfDescriptor', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePutKeyRecord(
    { accountId: 1, kind: 'passphrase', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(result.status, 'invalid');
});

test('putting a recovery key record must NOT carry a kdfDescriptor (D5 — HKDF-only)', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePutKeyRecord(
    {
      accountId: 1,
      kind: 'recovery',
      kdfDescriptor: { salt: 'not-allowed' },
      wrappedDek: wrappedDek(),
      expectedUpdatedAt: null,
    },
    storage,
  );
  assert.equal(result.status, 'invalid');
});

test('a valid passphrase key record is stored and listable', async () => {
  const storage = createFakeStorageAdapter();
  const descriptor = { salt: 'c2FsdA==', memorySizeKib: 65536, iterations: 3, parallelism: 1 };
  const putResult = await handlePutKeyRecord(
    { accountId: 1, kind: 'passphrase', kdfDescriptor: descriptor, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(putResult.status, 'ok');

  const records = await handleListKeyRecords(1, storage);
  assert.equal(records.length, 1);
  assert.equal(records[0]?.kind, 'passphrase');
  assert.deepEqual(records[0]?.kdfDescriptor, descriptor);
});

test('a valid recovery key record (no kdfDescriptor) is stored and listable', async () => {
  const storage = createFakeStorageAdapter();
  const putResult = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(putResult.status, 'ok');

  const records = await handleListKeyRecords(1, storage);
  assert.equal(records.length, 1);
  assert.equal(records[0]?.kdfDescriptor, null);
});

test('deleting a key record removes it', async () => {
  const storage = createFakeStorageAdapter();
  await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  await handleDeleteKeyRecord({ accountId: 1, kind: 'recovery' }, storage);
  const records = await handleListKeyRecords(1, storage);
  assert.equal(records.length, 0);
});

test('rejects an empty wrappedDek as invalid', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: new Uint8Array(0), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(result.status, 'invalid');
});

// ---------------------------------------------------------------------------
// CAS (security review finding #2) — mirrors the blob endpoint's optimistic
// concurrency: a write only succeeds when `expectedUpdatedAt` matches what
// the caller last observed, so a rotation/first-time-setup race can never
// silently overwrite another write.
// ---------------------------------------------------------------------------

test('a first-time create (expectedUpdatedAt: null) succeeds when no record exists yet', async () => {
  const storage = createFakeStorageAdapter();
  const result = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(result.status, 'ok');
});

test('a SECOND first-time create (expectedUpdatedAt: null) conflicts once a record already exists', async () => {
  const storage = createFakeStorageAdapter();
  const first = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(first.status, 'ok');

  // Simulates two concurrent first-time setups racing the same (account, kind) —
  // the loser must get a real conflict, never silently overwrite the winner.
  const second = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(second.status, 'conflict');
  if (second.status === 'conflict') {
    assert.ok(second.currentUpdatedAt !== null);
  }
});

test('a rotation with the CORRECT expectedUpdatedAt succeeds and replaces the record', async () => {
  const storage = createFakeStorageAdapter();
  const created = await handlePutKeyRecord(
    {
      accountId: 1,
      kind: 'passphrase',
      kdfDescriptor: { salt: 'a' },
      wrappedDek: wrappedDek(),
      expectedUpdatedAt: null,
    },
    storage,
  );
  assert.equal(created.status, 'ok');
  if (created.status !== 'ok') return;

  const rotated = await handlePutKeyRecord(
    {
      accountId: 1,
      kind: 'passphrase',
      kdfDescriptor: { salt: 'b' },
      wrappedDek: wrappedDek(),
      expectedUpdatedAt: created.record.updatedAt,
    },
    storage,
  );
  assert.equal(rotated.status, 'ok');

  const records = await handleListKeyRecords(1, storage);
  assert.equal(records.length, 1);
  assert.deepEqual(records[0]?.kdfDescriptor, { salt: 'b' });
});

test('a rotation with a STALE expectedUpdatedAt conflicts (never a blind overwrite)', async () => {
  const storage = createFakeStorageAdapter();
  const created = await handlePutKeyRecord(
    {
      accountId: 1,
      kind: 'passphrase',
      kdfDescriptor: { salt: 'a' },
      wrappedDek: wrappedDek(),
      expectedUpdatedAt: null,
    },
    storage,
  );
  assert.equal(created.status, 'ok');

  const staleTimestamp = new Date(0);
  const result = await handlePutKeyRecord(
    {
      accountId: 1,
      kind: 'passphrase',
      kdfDescriptor: { salt: 'attacker-value' },
      wrappedDek: wrappedDek(),
      expectedUpdatedAt: staleTimestamp,
    },
    storage,
  );
  assert.equal(result.status, 'conflict');

  // The record must still hold the ORIGINAL value — the stale write never landed.
  const records = await handleListKeyRecords(1, storage);
  assert.deepEqual(records[0]?.kdfDescriptor, { salt: 'a' });
});

test('different accounts never conflict with each other', async () => {
  const storage = createFakeStorageAdapter();
  const forAccountOne = await handlePutKeyRecord(
    { accountId: 1, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  const forAccountTwo = await handlePutKeyRecord(
    { accountId: 2, kind: 'recovery', kdfDescriptor: null, wrappedDek: wrappedDek(), expectedUpdatedAt: null },
    storage,
  );
  assert.equal(forAccountOne.status, 'ok');
  assert.equal(forAccountTwo.status, 'ok');
});
