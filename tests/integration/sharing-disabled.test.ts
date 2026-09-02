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
  sampleCiphertext,
  sampleKdfDescriptor,
  sampleShareWrap,
  sampleWrappedDek,
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
    body: { handle: 'dark-otter', authHash: sampleAuthHash(31), kdfDescriptor: sampleKdfDescriptor() },
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

test('sharing disabled: rotate-dek is NOT part of the dark surface, and refuses a keep list', async () => {
  // Uses its OWN account, so the fresh-account assertions above stay true
  // whatever order these run in.
  const signup = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { handle: 'rotator-otter', authHash: sampleAuthHash(32), kdfDescriptor: sampleKdfDescriptor(2) },
  });
  assert.equal(signup.status, 201);
  assert.ok(signup.body.tokens);
  const owner = signup.body.tokens.accessToken;

  const keyRecords = [
    { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(2), wrappedDek: sampleWrappedDek(51) },
    { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(52) },
  ];

  // THE RULING THIS TEST PINS: an owner who has never shared anything — on an
  // instance that cannot share at all — still gets to retire a DEK they
  // believe leaked. Gating the only mechanism that can do that behind an
  // unrelated sharing flag would leave such a self-hoster with no way to
  // rotate. The endpoint discloses nothing about a care graph: it rewrites
  // the caller's own blob and their own two key records, rows every account
  // on every deployment already has.
  const rotated = await service.request<{ newVersion: number; revokedShares: number }>({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner,
    body: {
      blob: { baseVersion: 0, envelopeVersion: 1, ciphertext: sampleCiphertext(29, 128) },
      keyRecords,
      shares: [],
    },
  });
  assert.equal(rotated.status, 200);
  assert.equal(rotated.body.newVersion, 1);
  assert.equal(rotated.body.revokedShares, 0);

  // A keep list here asserts state that cannot exist. Accepting it silently
  // would report clinicians re-wrapped on an instance that has never held a
  // share row.
  const withKeepList = await service.request({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: owner,
    body: {
      blob: { baseVersion: 1, envelopeVersion: 1, ciphertext: sampleCiphertext(30, 128) },
      keyRecords,
      shares: [{ granteeAccountId: 1, wrappedDek: sampleShareWrap(), recipientKeyFingerprint: 'ABCD' }],
    },
  });
  assert.equal(withKeepList.status, 400);

  // And it is an ORDINARY authenticated route, so an anonymous caller gets the
  // 401 the rest of `/v1/sync` gives — deliberately not the share tree's 404.
  const anonymous = await service.request({ method: 'POST', path: '/v1/sync/rotate-dek', body: {} });
  assert.equal(anonymous.status, 401);
});
