/**
 * With `SYNC_RESEARCH` unset, the research contribution family does not exist
 * — to anybody.
 *
 * WHY THIS IS THE FIRST TEST AND NOT A LATER HARDENING PASS. This service
 * auto-deploys on push, so the commit that adds a contribution route is the
 * commit that puts it in production, on an instance with real accounts on it.
 * The only thing that makes shipping the family before any operator has opted
 * in safe is that an unconfigured deployment is INDISTINGUISHABLE from one
 * where the feature was never written — ADR-0003 prohibition 9, the same
 * bargain ADR-0001 struck for the admin API and ADR-0002 for shares. And the
 * stakes are higher here than for either: the mere EXISTENCE of this tree
 * would tell a prober that this deployment holds a cohort.
 *
 * THE HARD PART IS THE ORDER, NOT THE 404. These paths sit INSIDE
 * `SYNC_API_PREFIX`, which already carries a bearer middleware. Leaving them
 * merely unmounted would let that middleware answer first, so an anonymous
 * probe would get `401` — which announces that a credential exists here worth
 * guessing. So the assertions below deliberately include the ANONYMOUS case:
 * that is the one a terminator mounted on the wrong side of authentication
 * fails, and the authenticated case alone would sail straight past it.
 * (Verified by defect injection, M161 slice 1: moving the terminator below
 * `app.use(SYNC_API_PREFIX, requireAuth)` fails ONLY the anonymous test.)
 *
 * INDEPENDENCE FROM `SYNC_SHARING` IS ALSO PINNED HERE, at the bottom: this
 * file boots with sharing ON and research OFF, so a future refactor that
 * folded the two flags into one would fail rather than quietly widen a
 * research deployment into every sharing deployment.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleContributionBody,
  sampleKdfDescriptor,
  startService,
  type ServiceHarness,
} from './service-harness.js';

/** Every path the research family would occupy if it were mounted. */
const RESEARCH_ROUTES: readonly { method: string; path: string; body?: unknown }[] = [
  { method: 'GET', path: '/v1/sync/contributions' },
  {
    method: 'PUT',
    path: '/v1/sync/contributions/2',
    body: {
      pseudonym: 'J7K2QW9ZP4M6N8R3T5V0XB1CDE',
      schemaTier: 'daily-intake:v1',
      body: sampleContributionBody(),
      contributionVersion: 1,
    },
  },
  { method: 'DELETE', path: '/v1/sync/contributions/2' },
  { method: 'GET', path: '/v1/sync/study/contributions' },
  { method: 'GET', path: '/v1/sync/study/withdrawals' },
  { method: 'GET', path: '/v1/sync/contributions/anything-else' },
  { method: 'GET', path: '/v1/sync/study/anything-else' },
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
  // This file signs up in `before`, so it resets the database itself rather
  // than relying on whichever file happened to run ahead of it.
  await database.reset();
  // No `research: true` — this is how every deployment boots today. `sharing`
  // IS on, which is what makes the two flags' independence assertable below.
  service = await startService({ db: database.db, sharing: true });
  const signup = await service.request<SessionBody>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: { handle: 'dark-study', authHash: sampleAuthHash(61), kdfDescriptor: sampleKdfDescriptor(6) },
  });
  assert.equal(signup.status, 201);
  assert.ok(signup.body.tokens);
  accessToken = signup.body.tokens.accessToken;
});

after(async () => {
  await service.close();
  await database.close();
});

test('research disabled: every contribution path 404s for an anonymous caller, never 401', async () => {
  for (const route of RESEARCH_ROUTES) {
    const response = await service.request({ method: route.method, path: route.path, body: route.body });
    assert.equal(
      response.status,
      404,
      `${route.method} ${route.path} must be 404 without a token, not ${response.status}`,
    );
  }
});

test('research disabled: a real access token buys nothing on the research tree', async () => {
  for (const route of RESEARCH_ROUTES) {
    const response = await service.request({ method: route.method, path: route.path, body: route.body, accessToken });
    assert.equal(
      response.status,
      404,
      `${route.method} ${route.path} with a token must be 404, not ${response.status}`,
    );
  }
});

test('research disabled: a contribution path is byte-for-byte the answer an unknown path gives', async () => {
  // Compared against the REAL 404 rather than a literal, so a future change to
  // the not-found body cannot make the research tree distinguishable while
  // this test still passes.
  const unknown = await fetch(`${service.baseUrl}/definitely-not-a-route`);
  const unknownBody = await unknown.text();

  for (const route of RESEARCH_ROUTES) {
    const response = await fetch(`${service.baseUrl}${route.path}`, {
      method: route.method,
      headers: { authorization: `Bearer ${accessToken}` },
    });
    assert.equal(response.status, unknown.status, `${route.path} status`);
    assert.equal(await response.text(), unknownBody, `${route.path} body`);
  }
});

test('research disabled: the owner-only sync routes are untouched by the terminator', async () => {
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

test('research disabled: SYNC_SHARING does not imply SYNC_RESEARCH', async () => {
  // This instance HAS sharing. If the two flags were ever folded together,
  // the share tree below would still answer 200 while the research tree above
  // answered 404 — so asserting both in one file is what pins the
  // independence PROTOCOL.md §5.18 states.
  const shares = await service.request<{ shares: unknown[] }>({
    method: 'GET',
    path: '/v1/sync/shares',
    accessToken,
  });
  assert.equal(shares.status, 200, 'sharing is ON here');
  assert.deepEqual(shares.body.shares, []);

  const contributions = await service.request({ method: 'GET', path: '/v1/sync/contributions', accessToken });
  assert.equal(contributions.status, 404, 'research is OFF here, and one flag must not turn on the other');
});
