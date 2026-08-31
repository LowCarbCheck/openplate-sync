/**
 * The invite endpoints of the operator API (M166).
 *
 * The property worth the most here is NOT "minting works". It is that the raw
 * token appears in exactly one response and never again — the single carve-out
 * ADR-0001 allows, and the one that would erode silently if nobody pinned it.
 * `admin-no-forbidden-fields.test.ts` walks every READ body for that value;
 * this file asserts the other half, that the mint response really does carry
 * it, so the two together say "here and nowhere else" rather than just
 * "nowhere".
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { asArray, asNumber, asObject, asString, type JsonValue } from '../../src/lib/json.js';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';

let harness: AdminHarness;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
});

after(async () => {
  await harness.close();
});

interface MintOptions {
  note?: string;
  expiresInDays?: number;
}

interface MintResponse {
  status: number;
  body: JsonValue;
}

async function mint(body: MintOptions = {}): Promise<MintResponse> {
  const response = await harness.request({ method: 'POST', path: '/v1/admin/invites', token: ADMIN_TOKEN, body });
  // SAFETY: every admin endpoint answers `application/json`, and a body that
  // did not parse would have thrown above rather than reached this cast.
  return { status: response.status, body: (await response.json()) as JsonValue };
}

/** Pulls the new invite's id out of a mint response, failing the test if it is not there. */
function mintedId(response: MintResponse): number {
  const id = asNumber(asObject(asObject(response.body)?.invite)?.id);
  if (id === null) throw new Error('the mint response carried no invite id');
  return id;
}

test('minting returns the raw token exactly once, and it is a real secret', async () => {
  const minted = await mint({ note: 'for a friend' });
  assert.equal(minted.status, 201);

  const token = asString(asObject(minted.body)?.token);
  assert.ok(token !== null, 'the mint response must carry the raw token');
  // 256 bits of randomness, base64url — not a short code somebody could guess
  // or a sequential id. Length is the cheap proxy for that.
  assert.ok(token.length >= 40, `expected a long random token, got ${token.length} characters`);

  // The same token must not come back from a read.
  const list = await harness.request({ method: 'GET', path: '/v1/admin/invites', token: ADMIN_TOKEN });
  assert.ok(!(await list.text()).includes(token), 'the raw token came back from a read endpoint');
});

test('two invites never share a token', async () => {
  const first = asString(asObject((await mint()).body)?.token);
  const second = asString(asObject((await mint()).body)?.token);
  assert.notEqual(first, second);
});

test('the invite body carries exactly the documented fields and nothing else', async () => {
  // A whitelist, like the account body's. A field added to the projection
  // fails here and has to be justified against ADR-0001 before it ships.
  await mint({ note: 'shape check' });
  const response = await harness.request({ method: 'GET', path: '/v1/admin/invites', token: ADMIN_TOKEN });
  // SAFETY: as in `mint` — the endpoint answers JSON or `json()` throws.
  const invites = asArray(asObject((await response.json()) as JsonValue)?.invites);
  const first = asObject(invites?.[0]);

  assert.deepEqual(Object.keys(first ?? {}).toSorted(), [
    'createdAt',
    'expiresAt',
    'id',
    'note',
    'redeemedAccountId',
    'redeemedAt',
  ]);
});

test('an absurd expiry is refused rather than clamped', async () => {
  // Clamping would hand back a capability with a lifetime the operator did not
  // ask for and would not notice.
  assert.equal((await mint({ expiresInDays: 100_000 })).status, 400);
  assert.equal((await mint({ expiresInDays: 0 })).status, 400);
  assert.equal((await mint({ expiresInDays: 1.5 })).status, 400);
});

test('revoking an unredeemed invite removes it', async () => {
  const inviteId = mintedId(await mint({ note: 'to be revoked' }));

  const revoked = await harness.request({
    method: 'DELETE',
    path: `/v1/admin/invites/${String(inviteId)}`,
    token: ADMIN_TOKEN,
  });
  assert.equal(revoked.status, 204);

  const again = await harness.request({
    method: 'DELETE',
    path: `/v1/admin/invites/${String(inviteId)}`,
    token: ADMIN_TOKEN,
  });
  assert.equal(again.status, 404);
});

test('a redeemed invite cannot be revoked, because it is an audit record', async () => {
  const inviteId = mintedId(await mint({ note: 'already used' }));
  harness.invites.markRedeemed(inviteId, 3);

  const response = await harness.request({
    method: 'DELETE',
    path: `/v1/admin/invites/${String(inviteId)}`,
    token: ADMIN_TOKEN,
  });
  // There is no capability left to withdraw, and the row is where an account's
  // provenance is recorded.
  assert.equal(response.status, 404);
});

test('the invite endpoints require the admin credential', async () => {
  for (const input of [
    { method: 'GET', path: '/v1/admin/invites' },
    { method: 'POST', path: '/v1/admin/invites' },
    { method: 'DELETE', path: '/v1/admin/invites/1' },
  ]) {
    const response = await harness.request({ ...input, token: null });
    assert.equal(response.status, 401, `${input.method} ${input.path}`);
  }
});

test('minting logs the invite id and never the token', async () => {
  const minted = await mint({ note: 'log check' });
  const token = asString(asObject(minted.body)?.token) ?? '';
  const serialized = JSON.stringify(harness.logLines);
  assert.ok(serialized.includes('Signup invite minted'));
  assert.ok(!serialized.includes(token), 'the raw token reached the log');
});
