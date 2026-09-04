/**
 * The admin credential discriminates, and the assertions prove BOTH halves.
 *
 * THE SHAPE OF THESE TESTS IS THE POINT, and it is borrowed from
 * `openplate-gateway/tests/unit/auth-indistinguishable.test.ts`. Asserting
 * only that a wrong token is rejected would pass on an admin API that rejects
 * everything, including the operator — a surface that is "secure" and useless.
 * Asserting only that the right token produces no error would pass on one that
 * was never mounted behind auth at all. So each case pins a status that
 * distinguishes REJECTED AT AUTH (401) from PAST AUTH (200, or the route's own
 * 404 for an id that does not exist), and the two must differ.
 *
 * Every rejected case is also compared against the OTHERS rather than against
 * a literal: absent, malformed, wrong-scheme and simply-wrong must be one
 * answer. A distinct "malformed" describes the shape of a valid credential; a
 * distinct "unknown token" confirms that what was presented parsed as one, so
 * a guessing loop can tell "close" from "wrong".
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { hashToken } from '../../src/lib/tokens.js';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';

let harness: AdminHarness;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
  harness.admin.seed({ id: 7, email: 'operator@example.org' });
});

after(async () => {
  await harness.close();
});

/** Every way a caller can fail to present the operator's credential. */
const REJECTED_CASES: readonly { name: string; authorization: string | null }[] = [
  { name: 'no Authorization header at all', authorization: null },
  { name: 'a Basic scheme', authorization: 'Basic dXNlcjpwYXNzd29yZA==' },
  { name: 'Bearer with nothing after it', authorization: 'Bearer' },
  { name: 'a bare token with no scheme', authorization: ADMIN_TOKEN },
  { name: 'a well-formed but wrong token', authorization: `Bearer ${'z'.repeat(41)}` },
  { name: 'a prefix of the real token', authorization: `Bearer ${ADMIN_TOKEN.slice(0, -1)}` },
  { name: 'the real token with one extra character', authorization: `Bearer ${ADMIN_TOKEN}x` },
];

async function requestWithHeader(path: string, authorization: string | null): Promise<Response> {
  const headers: Record<string, string> = {};
  if (authorization !== null) headers.authorization = authorization;
  return fetch(`${harness.baseUrl}${path}`, { method: 'GET', headers });
}

test('a wrong token is rejected AT AUTH with 401, in one identical answer', async () => {
  const bodies: string[] = [];

  for (const testCase of REJECTED_CASES) {
    const response = await requestWithHeader('/v1/admin/stats', testCase.authorization);
    assert.equal(response.status, 401, `${testCase.name} must be 401, saw ${response.status}`);
    bodies.push(await response.text());
  }

  const [first] = bodies;
  for (const [index, body] of bodies.entries()) {
    assert.equal(body, first, `${REJECTED_CASES[index]?.name ?? index} must give the same body as the others`);
  }
});

test('the right token gets PAST auth — a different status entirely', async () => {
  const response = await harness.request({ method: 'GET', path: '/v1/admin/stats', token: ADMIN_TOKEN });

  // 200, and specifically NOT 401: this is what separates "the mount is
  // behind auth and auth accepts the operator" from "everything is rejected".
  assert.equal(response.status, 200);
  assert.notEqual(response.status, 401);
});

test("past auth, an unknown account id is the route's own 404 — not the auth layer's 401", async () => {
  const rejected = await requestWithHeader('/v1/admin/accounts/999999', `Bearer ${'z'.repeat(41)}`);
  const accepted = await harness.request({ method: 'GET', path: '/v1/admin/accounts/999999', token: ADMIN_TOKEN });

  assert.equal(rejected.status, 401, 'a wrong token must not reach the route');
  assert.equal(accepted.status, 404, 'the right token must reach the route and be told the id does not exist');
  assert.notEqual(accepted.status, rejected.status);
});

test('a known account id past auth is a 200, so 404 above means "no such id" and not "no such route"', async () => {
  const response = await harness.request({ method: 'GET', path: '/v1/admin/accounts/7', token: ADMIN_TOKEN });
  assert.equal(response.status, 200);
});

test('the presented token is never echoed, in the response or the log', async () => {
  const guess = 'sync-admin-guess-value-that-is-long-enough';
  const response = await requestWithHeader('/v1/admin/stats', `Bearer ${guess}`);
  const body = await response.text();

  assert.equal(response.status, 401);
  assert.ok(!body.includes(guess), 'the response must not quote the presented token');

  const logged = harness.logLines.map((line) => JSON.stringify(line)).join('\n');
  assert.ok(!logged.includes(guess), 'the log must not quote the presented token');
  assert.ok(!logged.includes(ADMIN_TOKEN), 'the log must not quote the configured token either');
  // The rejection IS logged — an admin 401 is never routine — with the method
  // and the path and nothing that could be replayed.
  assert.ok(
    harness.logLines.some((line) => line.message === 'Admin request rejected'),
    'an admin rejection must be logged',
  );
});

// ── An admin ACCOUNT's own access token (M192) ─────────────────────────────

test("an admin account's own access token reaches the admin API", async () => {
  // The console lives in the client at /admin, behind the same sign-in as
  // everything else, so the person using it holds a session rather than a
  // shell variable. This is the credential that makes that possible.
  const admin = await harness.fakeAccounts.seedAccount({ email: 'boss@example.org', role: 'admin' });
  await harness.fakeAccounts.insertTokens([
    {
      accountId: admin.id,
      kind: 'access',
      tokenHash: hashToken('an-admin-session-token'),
      familyId: 'family-admin',
      expiresAt: new Date(harness.fixture.now().getTime() + 60_000),
    },
  ]);

  const response = await harness.request({
    method: 'GET',
    path: '/v1/admin/stats',
    token: 'an-admin-session-token',
  });
  assert.equal(response.status, 200);
});

test("a MEMBER's valid session gets the same answer a garbage token gets", async () => {
  // Saying "you are signed in but not an admin" would confirm to any account
  // holder that the surface exists and is worth attacking from another angle.
  const member = await harness.fakeAccounts.seedAccount({ email: 'member@example.org', role: 'member' });
  await harness.fakeAccounts.insertTokens([
    {
      accountId: member.id,
      kind: 'access',
      tokenHash: hashToken('a-member-session-token'),
      familyId: 'family-member',
      expiresAt: new Date(harness.fixture.now().getTime() + 60_000),
    },
  ]);

  const asMember = await requestWithHeader('/v1/admin/stats', 'Bearer a-member-session-token');
  const asGarbage = await requestWithHeader('/v1/admin/stats', `Bearer ${'z'.repeat(41)}`);
  assert.equal(asMember.status, 401);
  assert.equal(asMember.status, asGarbage.status);
  assert.equal(await asMember.text(), await asGarbage.text());
});

test('a SUSPENDED admin gets 403 account-suspended, not 401 and not a way in', async () => {
  const admin = await harness.fakeAccounts.seedAccount({ email: 'suspended-boss@example.org', role: 'admin' });
  await harness.fakeAccounts.suspendAccount({ accountId: admin.id, suspendedAt: harness.fixture.now() });
  // Minted AFTER the suspension revoked everything, so the token itself is
  // live and the account is not — the combination the middleware must catch.
  await harness.fakeAccounts.insertTokens([
    {
      accountId: admin.id,
      kind: 'access',
      tokenHash: hashToken('a-suspended-admin-token'),
      familyId: 'family-suspended',
      expiresAt: new Date(harness.fixture.now().getTime() + 60_000),
    },
  ]);

  const response = await requestWithHeader('/v1/admin/stats', 'Bearer a-suspended-admin-token');
  assert.equal(response.status, 403);
  // They have proved who they are; the honest answer is why the door is shut.
  assert.match(await response.text(), /account-suspended/);
});
