/**
 * An admin action is logged with the account id and never with the address.
 *
 * The rule is `logger.ts`'s and the ADR restates it: the opaque account id is
 * the correlation key, and the user's own identifier is not. A log line
 * outlives the request by months, gets shipped to whatever aggregates logs,
 * and is pasted into issues — so a user-facing identifier in it is a
 * disclosure with a long tail, and one no operator asked for. The id answers
 * every operational question the address would ("which account did we erase,
 * and can we prove it") without naming the account to a reader.
 *
 * M181 replaced the address with a handle and did NOT relax this rule; M192
 * put the address back as the identity and does not relax it either. If
 * anything the rule matters more now: an address in a log corpus names a
 * person in the world, which a handle never did.
 *
 * The check is over the SERIALIZED line, not over a named field, because the
 * failure this guards against is somebody adding the identifier as context to
 * a message string rather than as a field.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';
const SEEDED_EMAIL = 'never-in-a-log-line@example.org';

let harness: AdminHarness;
let accountId = 0;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
  const created = await harness.fakeAccounts.seedAccount({
    email: SEEDED_EMAIL,
    verifier: 'verifier-value-never-in-a-log-line',
  });
  accountId = created.id;
  harness.admin.seed({ id: accountId, email: SEEDED_EMAIL, blobSizeBytes: 512 });
});

after(async () => {
  await harness.close();
});

test('an admin deletion logs the account id and not the address', async () => {
  const response = await harness.request({
    method: 'DELETE',
    path: `/v1/admin/accounts/${accountId}`,
    token: ADMIN_TOKEN,
  });
  assert.equal(response.status, 204);

  const serialized = harness.logLines.map((line) => JSON.stringify(line)).join('\n');

  // The positive half: the action IS logged, and with the id that makes it
  // auditable. Without this, an implementation that logged nothing at all
  // would satisfy the absence check below.
  const deletion = harness.logLines.find((line) => line.message.includes('Account deleted by admin'));
  assert.ok(deletion !== undefined, 'an admin deletion must be logged');
  assert.equal(deletion.fields?.accountId, accountId);

  // The absence half.
  assert.ok(!serialized.includes(SEEDED_EMAIL), 'no log line may contain the account address');
  assert.ok(!serialized.includes('verifier-value-never'), 'and certainly not a fragment of the verifier');
});
