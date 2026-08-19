/**
 * Authz-layer unit tests for `registerSyncRoutes` (security review finding
 * #5): every route MUST call `context.resolveEntitledUser` first and 403 on
 * `null` BEFORE the route's own handler core runs — never leak a 404/400/etc
 * from a handler that never should have been reached. Spins up a real
 * Express app on an ephemeral loopback port (no extra HTTP-testing
 * dependency needed) against a fake `SyncStorageAdapter` and a mock
 * `resolveEntitledUser` this file controls per test via a distinct account
 * id (keeps tests isolated without needing a fresh server per test).
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { registerSyncRoutes } from '../../src/server/register-routes.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';
import type { SyncHostContext } from '../../src/contract-types.js';
import { asArray, asObject, asString, type JsonValue } from '../../src/lib/json.js';

let server: Server;
let baseUrl: string;

/** `null` makes every route's `resolveEntitledUser` resolve `null` (not entitled); a number entitles that userId. */
let currentEntitledUserId: number | null = null;

before(async () => {
  const app = express();
  const context: SyncHostContext = {
    storage: createFakeStorageAdapter(),
    resolveEntitledUser: async () => (currentEntitledUserId === null ? null : { userId: currentEntitledUserId }),
  };
  registerSyncRoutes(app, context);

  server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (address === null) throw new Error('expected a listening server');
  // SAFETY: `listen(0)` binds a TCP port, and Node only returns the string
  // form of an address for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
});

function samplePushBody(): string {
  return JSON.stringify({
    baseVersion: 0,
    envelopeVersion: 1,
    ciphertext: Buffer.from('opaque-bytes').toString('base64'),
  });
}

function sampleKeyRecordBody(): string {
  return JSON.stringify({
    kdfDescriptor: null,
    wrappedDek: Buffer.from('opaque-wrapped-dek').toString('base64'),
    expectedUpdatedAt: null,
  });
}

test('GET /v1/sync/blob returns 403 when not entitled', async () => {
  currentEntitledUserId = null;
  const response = await fetch(`${baseUrl}/v1/sync/blob`);
  assert.equal(response.status, 403);
});

test('GET /v1/sync/blob reaches the handler once entitled (404, no blob yet)', async () => {
  currentEntitledUserId = 101;
  const response = await fetch(`${baseUrl}/v1/sync/blob`);
  assert.equal(response.status, 404);
});

test('POST /v1/sync/blob returns 403 when not entitled', async () => {
  currentEntitledUserId = null;
  const response = await fetch(`${baseUrl}/v1/sync/blob`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: samplePushBody(),
  });
  assert.equal(response.status, 403);
});

test('POST /v1/sync/blob reaches the handler once entitled (200 accepted)', async () => {
  currentEntitledUserId = 102;
  const response = await fetch(`${baseUrl}/v1/sync/blob`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: samplePushBody(),
  });
  assert.equal(response.status, 200);
});

test('GET /v1/sync/key-records returns 403 when not entitled', async () => {
  currentEntitledUserId = null;
  const response = await fetch(`${baseUrl}/v1/sync/key-records`);
  assert.equal(response.status, 403);
});

test('GET /v1/sync/key-records reaches the handler once entitled (200, empty list)', async () => {
  currentEntitledUserId = 103;
  const response = await fetch(`${baseUrl}/v1/sync/key-records`);
  assert.equal(response.status, 200);
  const body: JsonValue = await response.json();
  assert.deepEqual(asArray(asObject(body)?.records), []);
});

test('PUT /v1/sync/key-records/:kind returns 403 when not entitled', async () => {
  currentEntitledUserId = null;
  const response = await fetch(`${baseUrl}/v1/sync/key-records/recovery`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: sampleKeyRecordBody(),
  });
  assert.equal(response.status, 403);
});

test('PUT /v1/sync/key-records/:kind reaches the handler once entitled (200 created)', async () => {
  currentEntitledUserId = 104;
  const response = await fetch(`${baseUrl}/v1/sync/key-records/recovery`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: sampleKeyRecordBody(),
  });
  assert.equal(response.status, 200);
});

test('DELETE /v1/sync/key-records/:kind returns 403 when not entitled', async () => {
  currentEntitledUserId = null;
  const response = await fetch(`${baseUrl}/v1/sync/key-records/recovery`, { method: 'DELETE' });
  assert.equal(response.status, 403);
});

test('DELETE /v1/sync/key-records/:kind reaches the handler once entitled (204)', async () => {
  currentEntitledUserId = 105;
  const response = await fetch(`${baseUrl}/v1/sync/key-records/recovery`, { method: 'DELETE' });
  assert.equal(response.status, 204);
});

test('the 403 body never leaks handler-shaped data — same generic message across every route', async () => {
  currentEntitledUserId = null;
  const responses = await Promise.all([
    fetch(`${baseUrl}/v1/sync/blob`),
    fetch(`${baseUrl}/v1/sync/key-records`),
    fetch(`${baseUrl}/v1/sync/key-records/passphrase`, { method: 'DELETE' }),
  ]);
  for (const response of responses) {
    assert.equal(response.status, 403);
    const body: JsonValue = await response.json();
    assert.equal(asString(asObject(body)?.error), 'sync not enabled for this account');
  }
});
