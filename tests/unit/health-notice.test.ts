/**
 * The operator's notice on the `/health` handshake (M181 spec 07).
 *
 * Boots the REAL app with fake stores, because the property under test is a
 * PUBLICATION property — "an instance with nothing to say sends no field at
 * all" — and a test that built the response object itself could not observe
 * it. The absence branch is the one that matters: a client older than this
 * field must parse the body exactly as before, and an `undefined` that
 * survives `JSON.stringify` is the difference between that and a `null` an
 * older decoder may reject.
 */
import { after, test } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/server/create-app.js';
import { isProtocolHandshake, type OperatorNotice } from '../../src/protocol.js';
import { asObject, type JsonObject, type JsonValue } from '../../src/lib/json.js';
import { createThrottleStore } from '../../src/lib/throttle.js';
import { createSilentLogger } from '../../src/logger.js';
import { createAuthFixture } from './auth-context-fixture.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';
import { createFakeRotationStore } from './fake-rotation-store.js';

const servers: Server[] = [];

after(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

/** Reads `/health` off a real listening app configured with (or without) a notice. */
async function readHandshake(notice: OperatorNotice | null): Promise<JsonObject> {
  const fixture = createAuthFixture();
  const app = createApp({
    authContext: fixture.ctx,
    storage: createFakeStorageAdapter(),
    rotation: createFakeRotationStore(),
    throttle: createThrottleStore({ freeAttempts: 10_000, baseLockoutMs: 1, maxLockoutMs: 1, attemptResetMs: 1 }),
    logger: createSilentLogger(),
    trustProxy: false,
    notice,
  });
  const server = app.listen(0);
  servers.push(server);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (address === null) throw new Error('expected a listening server');
  // SAFETY: `listen(0)` binds a TCP port; Node only returns a string address
  // for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;

  const response = await fetch(`http://127.0.0.1:${port}/health`);
  assert.equal(response.status, 200);
  const body: JsonValue = await response.json();
  // Decoded at the boundary rather than asserted into shape: a body that is
  // not a JSON object is a failure of this endpoint, not of the assertion
  // below it.
  const decoded = asObject(body);
  assert.ok(decoded !== null, 'the handshake body must be a JSON object');
  return decoded;
}

test('an instance with no notice sends no notice field, and stays readable to an older client', async () => {
  const body = await readHandshake(null);

  assert.ok(!('notice' in body), 'a configured-nothing instance must not add a field to the healthcheck body');
  // The rest of the handshake is untouched — this is an additive change or it
  // is a compatibility break wearing its clothes. `isProtocolHandshake` is the
  // decoder a real client applies, so this asserts what a client would accept
  // rather than re-deriving the shape here.
  assert.ok(isProtocolHandshake(body), 'the body must still decode as a handshake');
});

test('a configured notice is published on the same unauthenticated handshake', async () => {
  // Unauthenticated on purpose: the notice has to reach a person who cannot
  // sign in, which is exactly the person a shutdown notice is written for.
  const body = await readHandshake({ text: 'We move on 1 March.', url: 'https://example.org/moving' });

  assert.deepEqual(body.notice, { text: 'We move on 1 March.', url: 'https://example.org/moving' });
});

test('a notice with no link publishes no url key', async () => {
  const body = await readHandshake({ text: 'Read this before you sync again.' });

  assert.deepEqual(body.notice, { text: 'Read this before you sync again.' });
});
