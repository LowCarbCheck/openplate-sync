/**
 * With `SYNC_SHARING` unset, the share family does not exist — to anybody.
 *
 * WHY THIS IS THE FIRST TEST AND NOT A LATER HARDENING PASS. This service
 * auto-deploys on push, so the commit that adds a share route is the commit
 * that puts it in production, on an instance with real accounts on it. The
 * only thing that makes shipping the family before any operator has opted in
 * safe is that an unconfigured deployment is INDISTINGUISHABLE from one where
 * the feature was never written — ADR-0002's prohibition 10, which is the same
 * bargain ADR-0001 struck for the admin API.
 *
 * THE HARD PART IS THE ORDER, NOT THE 404. The share paths sit INSIDE
 * `SYNC_API_PREFIX`, which already carries a bearer middleware. Leaving the
 * routes merely unmounted would let that middleware answer first, so an
 * anonymous probe would get `401` — which announces that a credential exists
 * here worth guessing, and tells the prober that the tree is real and merely
 * locked. So the assertions below deliberately include the ANONYMOUS case:
 * that is the one a terminator mounted on the wrong side of authentication
 * fails, and the authenticated case alone would sail straight past it.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleShareWrap,
  startService,
  type ServiceHarness,
} from './service-harness.js';

/** Every path the share family would occupy if it were mounted. */
const SHARE_ROUTES: readonly { method: string; path: string; body?: unknown }[] = [
  { method: 'GET', path: '/v1/sync/shares' },
  {
    method: 'PUT',
    path: '/v1/sync/shares/2',
    body: { wrappedDek: sampleShareWrap(), recipientKeyFingerprint: 'ABCD-EFGH-JKMN', expectedUpdatedAt: null },
  },
  { method: 'DELETE', path: '/v1/sync/shares/2' },
  { method: 'GET', path: '/v1/sync/shared' },
  { method: 'GET', path: '/v1/sync/shared/2/blob' },
  { method: 'DELETE', path: '/v1/sync/shared/2' },
  { method: 'GET', path: '/v1/sync/shares/anything-else' },
];

let database: TestDatabase;
let service: ServiceHarness;
let accessToken: string;

interface SessionBody {
  account: { id: number };
  tokens: { accessToken: string } | null;
}

before(async () => {
  database = await setupTestDatabase();
  // This file signs up once, in `before`, so it resets the database itself
  // rather than relying on whichever file happened to run ahead of it.
  await database.reset();
  // No `sharing: true` — this is how every deployment boots today.
  service = await startService({ db: database.db });
  const signup = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { email: 'dark@example.test', authHash: sampleAuthHash(31), kdfDescriptor: sampleKdfDescriptor() },
  });
  assert.equal(signup.status, 201);
  assert.ok(signup.body.tokens);
  accessToken = signup.body.tokens.accessToken;
});

after(async () => {
  await service.close();
  await database.close();
});

test('sharing disabled: every share path 404s for an anonymous caller, never 401', async () => {
  for (const route of SHARE_ROUTES) {
    const response = await service.request({ method: route.method, path: route.path, body: route.body });
    assert.equal(
      response.status,
      404,
      `${route.method} ${route.path} must be 404 without a token, not ${response.status}`,
    );
  }
});

test('sharing disabled: a real access token buys nothing on the share tree', async () => {
  for (const route of SHARE_ROUTES) {
    const response = await service.request({ method: route.method, path: route.path, body: route.body, accessToken });
    assert.equal(
      response.status,
      404,
      `${route.method} ${route.path} with a token must be 404, not ${response.status}`,
    );
  }
});

test('sharing disabled: a share path is byte-for-byte the answer an unknown path gives', async () => {
  // Compared against the REAL 404 rather than a literal, so a future change to
  // the not-found body cannot make the share tree distinguishable while this
  // test still passes.
  const unknown = await fetch(`${service.baseUrl}/definitely-not-a-route`);
  const unknownBody = await unknown.text();

  for (const route of SHARE_ROUTES) {
    const response = await fetch(`${service.baseUrl}${route.path}`, {
      method: route.method,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    assert.equal(response.status, unknown.status, `${route.path} status`);
    assert.equal(await response.text(), unknownBody, `${route.path} body`);
  }
});

test('sharing disabled: the owner-only sync routes are untouched by the terminator', async () => {
  // The terminator is mounted on two subtrees of `SYNC_API_PREFIX`, not on the
  // prefix itself. If it ever widened, this is what would catch it.
  const blob = await service.request({ method: 'GET', path: '/v1/sync/blob', accessToken });
  assert.equal(blob.status, 404, 'a fresh account has no blob — but the route must still be the sync route');
  const records = await service.request<{ records: unknown[] }>({
    method: 'GET',
    path: '/v1/sync/key-records',
    accessToken,
  });
  assert.equal(records.status, 200);
  assert.deepEqual(records.body.records, []);
});
