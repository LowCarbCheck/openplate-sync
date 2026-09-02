/**
 * Admin deletion goes through `AccountStore.deleteAccount` — the SAME method
 * the self-service path calls.
 *
 * WHY THIS IS WORTH A TEST OF ITS OWN. The two deletion paths differ in
 * authorisation and in nothing else: a user proves their passphrase, an
 * operator proves the admin token, and then both must erase the identical set
 * of rows. If the admin route grew its own `DELETE FROM accounts`, the two
 * would drift the first time the erasure semantics changed — a new dependent
 * table, a retention rule, an audit row — and the difference would be
 * discovered during an audit rather than during review.
 *
 * The assertion is on the CALL, not on the outcome, and deliberately so.
 * Asserting only "the row is gone" would pass on an inlined SQL delete that
 * happens to remove the same rows today. Only the call proves the two paths
 * share one implementation, which is what stops them diverging tomorrow.
 *
 * The harness's store is a thin wrapper that records the call and delegates
 * to the real fake, so the outcome is checked too — a spy that swallowed the
 * effect would let a broken delete pass.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';

let harness: AdminHarness;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
});

after(async () => {
  await harness.close();
});

test('DELETE /v1/admin/accounts/:id calls the shared store method with that id', async () => {
  const created = await harness.fakeAccounts.createAccount({
    handle: 'to-be-erased',
    displayName: null,
    verifier: 'verifier-value-never-in-a-response',
    kdfDescriptor: { salt: 'AAAA', params: { memorySizeKib: 65536, iterations: 3, parallelism: 1 } },
  });
  assert.ok(created.ok, 'fixture account must be created');
  const accountId = created.account.id;
  harness.admin.seed({ id: accountId, handle: 'to-be-erased', blobSizeBytes: 128 });

  const response = await harness.request({
    method: 'DELETE',
    path: `/v1/admin/accounts/${accountId}`,
    token: ADMIN_TOKEN,
  });

  assert.equal(response.status, 204);
  // THE ASSERTION THIS FILE EXISTS FOR.
  assert.deepEqual(harness.deletedAccountIds, [accountId]);
  // …and the call actually did something, so the spy is not the only witness.
  assert.equal(harness.fakeAccounts.hasAccount(accountId), false);
});

test('deleting an id that does not exist is a 404 and calls the store for nothing', async () => {
  const deletionsBefore = harness.deletedAccountIds.length;

  const response = await harness.request({ method: 'DELETE', path: '/v1/admin/accounts/424242', token: ADMIN_TOKEN });

  assert.equal(response.status, 404);
  assert.equal(harness.deletedAccountIds.length, deletionsBefore, 'a 404 must not have erased anything');
});
