/**
 * The two halves of the M128 spec-01 review carry-over, tested together
 * because they are one behaviour split across two mechanisms:
 *
 *  1. A blob over `MAX_BLOB_BYTES` must be rejected with `413` and the
 *     documented `{"error": "..."}` body — by the ROUTE, since body-parser's
 *     limit deliberately sits above the cap so a legitimate maximum-size blob
 *     survives base64 inflation.
 *  2. A body large enough for body-parser to reject must produce the SAME
 *     shape, which Express's default handler does not do (it returns HTML).
 *
 * Plus the capacity-cliff warning band, which is the only thing that will
 * tell anyone the chunked-blob work needs starting.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { registerSyncRoutes } from '../../src/server/register-routes.js';
import { createErrorMiddleware } from '../../src/server/error-middleware.js';
import { MAX_BLOB_BYTES } from '../../src/protocol.js';
import {
  BLOB_SIZE_WARN_BYTES,
  BLOB_SIZE_WARN_RATIO,
  blobCapacityPercent,
  shouldWarnBlobSize,
} from '../../src/server/blob-size-telemetry.js';
import { createSilentLogger, type LogFields } from '../../src/logger.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';
import { asObject, asString, type JsonValue } from '../../src/lib/json.js';

let server: Server;
let baseUrl: string;
const warnings: Array<{ message: string; fields?: LogFields }> = [];

before(async () => {
  const app = express();
  const logger = {
    ...createSilentLogger(),
    warn: (message: string, fields?: LogFields) => {
      warnings.push({ message, fields });
    },
  };
  registerSyncRoutes(app, {
    storage: createFakeStorageAdapter(),
    resolveEntitledUser: async () => ({ userId: 1 }),
    logger,
  });
  app.use(createErrorMiddleware(createSilentLogger()));

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

async function push(ciphertextBytes: number, baseVersion: number): Promise<Response> {
  return fetch(`${baseUrl}/v1/sync/blob`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      baseVersion,
      envelopeVersion: 1,
      ciphertext: Buffer.alloc(ciphertextBytes, 7).toString('base64'),
    }),
  });
}

test('the warning band starts at 80% of the cap', () => {
  assert.equal(BLOB_SIZE_WARN_RATIO, 0.8);
  assert.equal(BLOB_SIZE_WARN_BYTES, Math.floor(MAX_BLOB_BYTES * 0.8));
  assert.equal(shouldWarnBlobSize(BLOB_SIZE_WARN_BYTES - 1), false);
  assert.equal(shouldWarnBlobSize(BLOB_SIZE_WARN_BYTES), true);
  assert.equal(blobCapacityPercent(MAX_BLOB_BYTES), 100);
  assert.equal(blobCapacityPercent(MAX_BLOB_BYTES / 2), 50);
});

test('a decoded blob over the cap is a 413 with the documented error body', async () => {
  // Body-parser cannot catch this: its limit is base64-inflated on purpose.
  const response = await push(MAX_BLOB_BYTES + 1, 0);
  assert.equal(response.status, 413);
  const body: JsonValue = await response.json();
  assert.notEqual(asString(asObject(body)?.error), null);
});

test('a blob exactly at the cap is accepted', async () => {
  const response = await push(MAX_BLOB_BYTES, 0);
  // The whole reason JSON_BODY_LIMIT sits above MAX_BLOB_BYTES.
  assert.equal(response.status, 200);
});

test('a push inside the warning band logs a capacity warning naming the account', async () => {
  warnings.length = 0;
  const response = await push(BLOB_SIZE_WARN_BYTES + 10, 1);
  assert.equal(response.status, 200);
  assert.equal(warnings.length, 1);
  assert.equal(warnings[0]?.fields?.accountId, 1);
  assert.equal(warnings[0]?.fields?.maxBytes, MAX_BLOB_BYTES);
});

test('a small push logs no capacity warning', async () => {
  warnings.length = 0;
  const response = await push(128, 2);
  assert.equal(response.status, 200);
  assert.equal(warnings.length, 0);
});

test('a body too large even for body-parser still yields the JSON error shape', async () => {
  const response = await fetch(`${baseUrl}/v1/sync/blob`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    // Well past the base64-inflated body limit.
    body: JSON.stringify({ baseVersion: 0, envelopeVersion: 1, ciphertext: 'A'.repeat(MAX_BLOB_BYTES * 2) }),
  });
  assert.equal(response.status, 413);
  assert.equal(response.headers.get('content-type')?.includes('application/json'), true);
  const body: JsonValue = await response.json();
  assert.notEqual(asString(asObject(body)?.error), null);
});

test('malformed JSON yields a 400 in the documented shape, not an HTML page', async () => {
  const response = await fetch(`${baseUrl}/v1/sync/blob`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{ not json',
  });
  assert.equal(response.status, 400);
  const body: JsonValue = await response.json();
  assert.notEqual(asString(asObject(body)?.error), null);
});
