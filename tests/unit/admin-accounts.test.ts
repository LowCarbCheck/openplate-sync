/**
 * The operator's edits: `PATCH /accounts/:id`, `POST /accounts/:id/reset-mail`,
 * `POST /invites/:id/resend`, and the guard that stops an administrator from
 * locking everybody out.
 *
 * ADR-0001 FORBADE AN ADMIN-SIDE AUTH MUTATION, AND THE OWNER OVERRODE THAT ON
 * 2026-09-04 for exactly three things: role, suspension, and sending a reset
 * mail. The prohibition it did NOT relax is the one about secrets in a
 * response, so every case below that changes something also checks that the
 * body it gets back is still an `AccountView` and nothing more.
 *
 * THE SELF-CHANGE GUARD IS THE LOAD-BEARING ONE. An organization with one
 * administrator who demotes or suspends their own account has locked everybody
 * out of `/v1/admin`, and the remedy is a shell on the container. The static
 * `ADMIN_TOKEN` is exempt because it has no self — it is the break-glass
 * credential that exists for exactly that situation.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { asNumber, asObject, asString, type JsonValue } from '../../src/lib/json.js';
import { hashToken } from '../../src/lib/tokens.js';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';

let harness: AdminHarness;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
});

after(async () => {
  await harness.close();
});

beforeEach(() => {
  harness.admin.clear();
});

interface PatchResponse {
  status: number;
  body: JsonValue;
}

/** The parsed body of an admin response, as the boundary type every reader below decodes. */
async function jsonBody(answered: Response): Promise<JsonValue> {
  // SAFETY: every admin endpoint answers `application/json` by contract, and a
  // body that did not parse throws inside `json()` rather than reaching this
  // line. `JsonValue` is the boundary type `lib/json.ts` decodes, so every
  // reader goes through `asObject` / `asString` / `asNumber` and none of them
  // trusts this shape.
  return (await answered.json()) as JsonValue;
}

async function patchAccount(input: { id: number; body: unknown; token?: string }): Promise<PatchResponse> {
  const response = await harness.request({
    method: 'PATCH',
    path: `/v1/admin/accounts/${input.id}`,
    token: input.token ?? ADMIN_TOKEN,
    body: input.body,
  });
  return { status: response.status, body: await jsonBody(response) };
}

/**
 * A fresh address per call.
 *
 * The harness is built once for the file, so the account store carries every
 * account any earlier test made. Reusing an address would hit the real
 * `email-taken` rule and fail as a fixture problem rather than as the property
 * under test.
 */
let addressCounter = 0;
function nextEmail(): string {
  addressCounter += 1;
  return `person-${addressCounter}@example.org`;
}

/** Seeds an account in BOTH stores: the metadata store the routes read, and the account store they write. */
async function seedAccount(input: { role?: 'admin' | 'member'; dailyAiLimit?: number } = {}): Promise<number> {
  const email = nextEmail();
  const account = await harness.fakeAccounts.seedAccount({
    email,
    role: input.role ?? 'member',
    dailyAiLimit: input.dailyAiLimit ?? 0,
  });
  harness.admin.seed({
    id: account.id,
    email,
    role: input.role ?? 'member',
    dailyAiLimit: input.dailyAiLimit ?? 0,
  });
  return account.id;
}

/** Mints a live access token for an account, so a test can act AS that admin. */
async function tokenFor(accountId: number, raw: string): Promise<string> {
  await harness.fakeAccounts.insertTokens([
    {
      accountId,
      kind: 'access',
      tokenHash: hashToken(raw),
      familyId: `family-${accountId}`,
      expiresAt: new Date(harness.fixture.now().getTime() + 60_000),
    },
  ]);
  return raw;
}

// ── PATCH ──────────────────────────────────────────────────────────────────

test('PATCH changes a role, an allowance and a name, and returns the AccountView', async () => {
  const id = await seedAccount();

  const changed = await patchAccount({ id, body: { role: 'admin', dailyAiLimit: 200, displayName: 'Anna S.' } });
  assert.equal(changed.status, 200);

  // The store really moved, not just the response.
  const account = await harness.fakeAccounts.findAccountById(id);
  assert.equal(account?.role, 'admin');
  assert.equal(account?.dailyAiLimit, 200);
  assert.equal(account?.displayName, 'Anna S.');

  // ADR-0001's surviving prohibition: the body is an account view and nothing
  // more. `admin-no-forbidden-fields.test.ts` walks the read endpoints; this
  // pins the one that WRITES, which is the newer surface.
  const view = asObject(asObject(changed.body)?.account);
  assert.deepEqual(Object.keys(view ?? {}).toSorted(), [
    'aiUsedToday',
    'blob',
    'createdAt',
    'dailyAiLimit',
    'displayName',
    'email',
    'id',
    'keyRecordKinds',
    'role',
    'suspendedAt',
  ]);
});

test('an absent field means untouched, and an empty patch is a 400', async () => {
  const id = await seedAccount({ role: 'admin', dailyAiLimit: 200 });

  // Only the name moves; the role and the allowance are not in the body.
  assert.equal((await patchAccount({ id, body: { displayName: 'Renamed' } })).status, 200);
  const account = await harness.fakeAccounts.findAccountById(id);
  assert.equal(account?.displayName, 'Renamed');
  assert.equal(account?.role, 'admin');
  assert.equal(account?.dailyAiLimit, 200);

  // A patch that names nothing is a caller that believes it changed something.
  // Same rule the owner-side `PATCH /v1/auth/account` applies to an absent key.
  const empty = await patchAccount({ id, body: {} });
  assert.equal(empty.status, 400);
  assert.match(asString(asObject(empty.body)?.error) ?? '', /at least one/);
});

test('displayName: null clears the name, which is a value and not an omission', async () => {
  const id = await seedAccount();
  await patchAccount({ id, body: { displayName: 'Anna' } });

  assert.equal((await patchAccount({ id, body: { displayName: null } })).status, 200);
  assert.equal((await harness.fakeAccounts.findAccountById(id))?.displayName, null);
});

test('a malformed field is a 400 that names it, and changes nothing', async () => {
  const id = await seedAccount({ role: 'member', dailyAiLimit: 5 });

  for (const [body, expected] of [
    [{ role: 'superuser' }, /role/],
    [{ dailyAiLimit: -1 }, /dailyAiLimit/],
    [{ dailyAiLimit: 1_000_000 }, /dailyAiLimit/],
    [{ dailyAiLimit: 1.5 }, /dailyAiLimit/],
    [{ suspended: 'yes' }, /suspended/],
  ] as const) {
    const refused = await patchAccount({ id, body });
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.match(asString(asObject(refused.body)?.error) ?? '', expected);
  }

  const account = await harness.fakeAccounts.findAccountById(id);
  assert.equal(account?.role, 'member');
  assert.equal(account?.dailyAiLimit, 5);
});

test('suspending revokes every session, and reactivating does NOT restore one', async () => {
  const id = await seedAccount();
  await tokenFor(id, 'annas-session');

  assert.equal((await patchAccount({ id, body: { suspended: true } })).status, 200);
  assert.notEqual((await harness.fakeAccounts.findAccountById(id))?.suspendedAt, null);
  // THE HALF AN OPERATOR DOES NOT SEE IN THE ROW: a `suspended_at` alone leaves
  // the phone in somebody's pocket syncing for another quarter of an hour.
  const revoked = harness.fakeAccounts.allTokens().filter((token) => token.accountId === id);
  assert.ok(revoked.length > 0, 'the fixture must have had a session to revoke');
  assert.ok(
    revoked.every((token) => token.revokedAt !== null),
    'suspending must revoke every session in the same effect',
  );

  assert.equal((await patchAccount({ id, body: { suspended: false } })).status, 200);
  assert.equal((await harness.fakeAccounts.findAccountById(id))?.suspendedAt, null);
  // Reactivation deliberately restores nothing: the person signs in again.
  assert.ok(
    harness.fakeAccounts
      .allTokens()
      .filter((token) => token.accountId === id)
      .every((token) => token.revokedAt !== null),
  );
});

test('a patch on an id that does not exist is a 404', async () => {
  assert.equal((await patchAccount({ id: 424_242, body: { displayName: 'Nobody' } })).status, 404);
});

// ── The self-change guard ──────────────────────────────────────────────────

test('an admin ACCOUNT cannot suspend, demote or delete itself', async () => {
  const id = await seedAccount({ role: 'admin' });
  const token = await tokenFor(id, 'the-boss-session');

  for (const body of [{ suspended: true }, { role: 'member' }] as const) {
    const refused = await patchAccount({ id, body, token });
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.deepEqual(refused.body, { error: 'self-change' });
  }

  // Deletion is the most complete lockout there is, and unlike a suspension it
  // cannot be undone.
  const deleted = await harness.request({ method: 'DELETE', path: `/v1/admin/accounts/${id}`, token });
  assert.equal(deleted.status, 400);
  assert.deepEqual(await deleted.json(), { error: 'self-change' });

  // Nothing moved.
  const account = await harness.fakeAccounts.findAccountById(id);
  assert.equal(account?.role, 'admin');
  assert.equal(account?.suspendedAt, null);
  assert.equal(harness.fakeAccounts.hasAccount(id), true);
});

test('an admin may rename itself and raise its own allowance: neither is a lockout', async () => {
  const id = await seedAccount({ role: 'admin' });
  const token = await tokenFor(id, 'the-boss-session-2');

  const renamed = await patchAccount({ id, body: { displayName: 'The Boss', dailyAiLimit: 500 }, token });
  assert.equal(renamed.status, 200);
  assert.equal((await harness.fakeAccounts.findAccountById(id))?.displayName, 'The Boss');
});

test('an admin may suspend and demote SOMEBODY ELSE', async () => {
  const boss = await seedAccount({ role: 'admin' });
  const other = await seedAccount({ role: 'admin' });
  const token = await tokenFor(boss, 'the-boss-session-3');

  assert.equal((await patchAccount({ id: other, body: { role: 'member', suspended: true }, token })).status, 200);
  const account = await harness.fakeAccounts.findAccountById(other);
  assert.equal(account?.role, 'member');
  assert.notEqual(account?.suspendedAt, null);
});

test('the STATIC token is exempt: it has no self, and it is the way back in', async () => {
  // The credential that exists for exactly the situation the guard prevents.
  const id = await seedAccount({ role: 'admin' });

  assert.equal((await patchAccount({ id, body: { role: 'member' }, token: ADMIN_TOKEN })).status, 200);
  assert.equal((await harness.fakeAccounts.findAccountById(id))?.role, 'member');
});

// ── The admin-account bearer path ──────────────────────────────────────────

test("an admin account's own access token reaches every write route", async () => {
  const boss = await seedAccount({ role: 'admin' });
  const subject = await seedAccount();
  const token = await tokenFor(boss, 'the-boss-session-4');

  // The console lives in the client at /admin, behind the same sign-in as
  // everything else, so these are the calls it makes.
  assert.equal((await patchAccount({ id: subject, body: { dailyAiLimit: 10 }, token })).status, 200);
  const mail = await harness.request({
    method: 'POST',
    path: `/v1/admin/accounts/${subject}/reset-mail`,
    token,
  });
  assert.equal(mail.status, 202);
});

test('a MEMBER account is refused on the write routes, exactly as a garbage token is', async () => {
  const member = await seedAccount();
  const subject = await seedAccount();
  const token = await tokenFor(member, 'a-member-session');

  const asMember = await patchAccount({ id: subject, body: { dailyAiLimit: 10 }, token });
  const asGarbage = await patchAccount({ id: subject, body: { dailyAiLimit: 10 }, token: 'z'.repeat(41) });
  assert.equal(asMember.status, 401);
  assert.deepEqual(asMember.body, asGarbage.body);
  // ...and nothing moved.
  assert.equal((await harness.fakeAccounts.findAccountById(subject))?.dailyAiLimit, 0);
});

// ── reset-mail ─────────────────────────────────────────────────────────────

test('reset-mail writes a reset row and reports emailed:false with a link on a mailless instance', async () => {
  const id = await seedAccount();

  const response = await harness.request({ method: 'POST', path: `/v1/admin/accounts/${id}/reset-mail`, token: ADMIN_TOKEN });
  assert.equal(response.status, 202);
  // SAFETY: this endpoint answers JSON, and a body that did not parse would
  // have thrown above.
  const body = asObject(await jsonBody(response));
  assert.equal(body?.emailed, false, 'this harness configures no mail');
  // No link either, because the harness configures no client base URL. Both
  // absent is the honest answer: an operator with neither has nothing to hand
  // over, and inventing a link would point at nowhere.
  assert.equal(body?.link, null);

  // THE WRITE HAPPENED, which is what makes the 202 mean anything.
  const live = harness.fakeAccounts.allPasswordResets().filter((row) => row.accountId === id && row.consumedAt === null);
  assert.equal(live.length, 1);
});

test('reset-mail on an unknown account is a 404 and writes nothing', async () => {
  const resetsBefore = harness.fakeAccounts.allPasswordResets().length;
  const response = await harness.request({
    method: 'POST',
    path: '/v1/admin/accounts/424242/reset-mail',
    token: ADMIN_TOKEN,
  });
  assert.equal(response.status, 404);
  assert.equal(harness.fakeAccounts.allPasswordResets().length, resetsBefore);
});

// ── resend ─────────────────────────────────────────────────────────────────

test('resend mints a NEW token on the SAME invite and extends its expiry', async () => {
  const minted = await harness.request({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'invitee@example.org' },
  });
  assert.equal(minted.status, 201);
  const mintedBody = asObject(await jsonBody(minted));
  const inviteId = asNumber(asObject(mintedBody?.invite)?.id) ?? 0;
  const firstToken = asString(mintedBody?.token);
  const firstDigest = harness.invites.digestOf(inviteId);

  const resent = await harness.request({
    method: 'POST',
    path: `/v1/admin/invites/${inviteId}/resend`,
    token: ADMIN_TOKEN,
  });
  assert.equal(resent.status, 202);
  const resentBody = asObject(await jsonBody(resent));
  // THE SAME ROW: a second invite would leave the first live until something
  // revoked it, and the list would show two invitations where the operator
  // believes there is one.
  assert.equal(asNumber(asObject(resentBody?.invite)?.id), inviteId);
  assert.equal(harness.invites.rows().filter((row) => row.email === 'invitee@example.org').length, 1);

  // A NEW token, and the old digest is gone, which is what "resend" means.
  assert.notEqual(asString(resentBody?.token), firstToken);
  assert.notEqual(harness.invites.digestOf(inviteId), firstDigest);
});

test('resending a redeemed or unknown invite is a 404', async () => {
  const minted = await harness.request({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'spent@example.org' },
  });
  const inviteId = asNumber(asObject(asObject(await jsonBody(minted))?.invite)?.id) ?? 0;
  harness.invites.markRedeemed(inviteId, 1);

  // A redeemed invite is an audit record with no capability left in it, so
  // there is nothing to resend and it reads the same as an id that never was.
  const spent = await harness.request({
    method: 'POST',
    path: `/v1/admin/invites/${inviteId}/resend`,
    token: ADMIN_TOKEN,
  });
  const unknown = await harness.request({ method: 'POST', path: '/v1/admin/invites/424242/resend', token: ADMIN_TOKEN });
  assert.equal(spent.status, 404);
  assert.equal(unknown.status, 404);
  assert.equal(await spent.text(), await unknown.text());
});

// ── stats ──────────────────────────────────────────────────────────────────

test('stats reports the three fields the console shows beside the counts', async () => {
  await seedAccount({ role: 'admin' });
  await seedAccount();

  const response = await harness.request({ method: 'GET', path: '/v1/admin/stats', token: ADMIN_TOKEN });
  assert.equal(response.status, 200);
  const stats = asObject(asObject(await jsonBody(response))?.stats);
  assert.deepEqual(Object.keys(stats ?? {}).toSorted(), [
    'accounts',
    'accountsWithBlob',
    'admins',
    'aiRequestsToday',
    'blobBytes',
    'blobVersions',
    'keyRecords',
    'pendingInvites',
  ]);
  assert.equal(asNumber(stats?.admins), 1);
});
