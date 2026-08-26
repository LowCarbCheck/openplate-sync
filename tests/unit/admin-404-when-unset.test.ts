/**
 * With no `ADMIN_TOKEN`, the admin API does not exist — to anybody.
 *
 * WHY THIS IS THE FIRST TEST AND NOT A LATER HARDENING PASS. This service
 * auto-deploys on push, so the commit that adds an admin route is the commit
 * that puts it in production, on an instance with real accounts on it. The
 * only thing that makes shipping the feature safe before anyone has decided to
 * enable it is that an unconfigured deployment is INDISTINGUISHABLE from one
 * where the feature was never written. That has to be true in the same commit
 * as the first route, not retrofitted after somebody notices.
 *
 * A 401 would be the failure. It announces that a credential exists here and
 * is merely locked, which on a service whose threat model assumes the attacker
 * can reach it is an invitation to come back with a wordlist. So every admin
 * path must answer exactly what an unknown path answers — same status, same
 * body — including for a caller who presents a perfectly well-formed bearer
 * token, which is the case a "did we forget to mount auth" bug would sail
 * through.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

let harness: AdminHarness;

/** Every path the admin API would occupy if it were mounted. */
const ADMIN_PATHS: readonly { method: string; path: string }[] = [
  { method: 'GET', path: '/v1/admin/accounts' },
  { method: 'GET', path: '/v1/admin/accounts/1' },
  { method: 'DELETE', path: '/v1/admin/accounts/1' },
  { method: 'GET', path: '/v1/admin/stats' },
  { method: 'GET', path: '/v1/admin' },
  { method: 'GET', path: '/v1/admin/anything-else' },
];

/** A syntactically perfect credential. It must buy nothing, because there is nothing to buy. */
const VALID_LOOKING_TOKEN = 'a'.repeat(48);

before(async () => {
  harness = await startAdminHarness({ adminToken: null });
  harness.admin.seed({ id: 1, email: 'seeded@example.test' });
});

after(async () => {
  await harness.close();
});

test('every admin path 404s when no admin token is configured', async () => {
  for (const route of ADMIN_PATHS) {
    const response = await harness.request(route);
    assert.equal(response.status, 404, `${route.method} ${route.path} must be 404, not ${response.status}`);
  }
});

test('a well-formed bearer token buys nothing — still 404, never 401', async () => {
  for (const route of ADMIN_PATHS) {
    const response = await harness.request({ ...route, token: VALID_LOOKING_TOKEN });
    assert.equal(
      response.status,
      404,
      `${route.method} ${route.path} with a bearer token must be 404, not ${response.status}`,
    );
  }
});

test('an admin path is byte-for-byte the answer an unknown path gives', async () => {
  // Compared against the real 404 rather than against a literal, so a future
  // change to the not-found body cannot make the admin tree distinguishable
  // while both tests still pass.
  const unknown = await harness.request({ method: 'GET', path: '/definitely-not-a-route' });
  const unknownBody = await unknown.text();

  for (const route of ADMIN_PATHS) {
    const response = await harness.request({ ...route, token: VALID_LOOKING_TOKEN });
    const body = await response.text();
    assert.equal(response.status, unknown.status, `${route.path} status`);
    // DELETE answers with no body on a 204 elsewhere; here every case is a 404
    // and must carry the identical body.
    assert.equal(body, unknownBody, `${route.path} body`);
  }
});

test('nothing about the admin surface is logged, because nothing was reached', async () => {
  await harness.request({ method: 'GET', path: '/v1/admin/accounts', token: VALID_LOOKING_TOKEN });

  const rejections = harness.logLines.filter((line) => line.message === 'Admin request rejected');
  assert.deepEqual(rejections, [], 'an unmounted admin API must not log admin auth failures');
});
