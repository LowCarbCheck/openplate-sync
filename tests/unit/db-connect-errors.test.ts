/**
 * Which connection failures are worth waiting on, and which are a typo.
 *
 * The distinction was found by smoke-testing the entrypoint against a
 * misspelled database name: it retried for ten seconds logging "not reachable
 * yet" and then failed with a message about connectivity, which points the
 * operator at their network instead of at their `DATABASE_URL`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isUnrecoverableConnectError } from '../../src/db/client.js';

test('a nonexistent database, bad password or bad auth spec are not worth retrying', () => {
  assert.equal(isUnrecoverableConnectError({ code: '3D000' }), true);
  assert.equal(isUnrecoverableConnectError({ code: '28P01' }), true);
  assert.equal(isUnrecoverableConnectError({ code: '28000' }), true);
});

test('a refused connection IS worth retrying — that is the compose start-up race', () => {
  assert.equal(isUnrecoverableConnectError({ code: 'ECONNREFUSED' }), false);
  assert.equal(isUnrecoverableConnectError({ code: 'ETIMEDOUT' }), false);
  assert.equal(isUnrecoverableConnectError(new Error('socket hang up')), false);
  assert.equal(isUnrecoverableConnectError(null), false);
  assert.equal(isUnrecoverableConnectError(undefined), false);
});
