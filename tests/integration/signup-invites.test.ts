/**
 * Invite redemption against REAL Postgres (M166).
 *
 * This file exists for the one property the unit suite structurally cannot
 * reach. `tests/unit/fake-account-store.ts` reproduces the RULES by ordering
 * its writes, but the rules are enforced in production by a transaction and a
 * conditional UPDATE, and neither a rollback nor a row lock has any meaning in
 * a JavaScript Map. Concurrency is a property of the database, so it is tested
 * against the database.
 *
 * Two things are proved here and nowhere else:
 *
 *  - Concurrent redemptions of ONE invite produce exactly one account. If the
 *    store did a SELECT-then-UPDATE, both callers would see it unredeemed and
 *    two people would get in on one invitation.
 *  - A duplicate-handle signup leaves the invite spendable. That is the
 *    transaction's rollback, observed from outside: the conditional UPDATE has
 *    already run and been undone by the time the caller sees the 409.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import { createDrizzleInviteStore } from '../../src/db/invite-store.js';
import { sampleAuthHash, sampleKdfDescriptor, startService, type ServiceHarness } from './service-harness.js';

let database: TestDatabase;

before(async () => {
  database = await setupTestDatabase();
});

after(async () => {
  await database.close();
});

beforeEach(async () => {
  await database.reset();
});

/** The signup request as this service's wire contract defines it (PROTOCOL.md §5.8). */
interface SignupRequest {
  handle: string;
  authHash: string;
  kdfDescriptor: ReturnType<typeof sampleKdfDescriptor>;
  /** Absent on an open instance; required on an invite-only one. */
  inviteToken?: string;
}

function signupBody(handle: string, inviteToken?: string): SignupRequest {
  const body: SignupRequest = {
    handle,
    authHash: sampleAuthHash(11),
    kdfDescriptor: sampleKdfDescriptor(),
  };
  // Assigned only when given, so the "no invite at all" case genuinely omits
  // the field rather than sending an explicit `undefined`.
  if (inviteToken !== undefined) body.inviteToken = inviteToken;
  return body;
}

/** Mints one live invite straight through the store — the admin API is tested separately. */
async function mintInvite(): Promise<string> {
  const store = createDrizzleInviteStore(database.db);
  const minted = await store.mint({ note: 'integration', expiresAt: new Date(Date.now() + 60 * 60 * 1000) });
  return minted.token;
}

test('an invite admits exactly one account, even under concurrent redemption', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'invite' });
  try {
    const token = await mintInvite();

    // Fired together, deliberately not awaited in sequence. With a
    // SELECT-then-UPDATE both would find the invite unredeemed.
    const attempts = await Promise.all(
      ['one-otter', 'two-otter', 'three-otter'].map((handle) =>
        service.request<{ error?: string }>({ method: 'POST', path: '/v1/auth/signup', body: signupBody(handle, token) }),
      ),
    );

    const created = attempts.filter((response) => response.status === 201);
    const refused = attempts.filter((response) => response.status === 403);
    assert.equal(created.length, 1, `expected exactly one account, got ${created.length}`);
    assert.equal(refused.length, 2);
  } finally {
    await service.close();
  }
});

test('a duplicate handle is refused and the invite is NOT consumed', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'invite' });
  try {
    const first = await mintInvite();
    const second = await mintInvite();

    const created = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('taken', first),
    });
    assert.equal(created.status, 201);

    // The second invite is spent on an address that already exists.
    const conflict = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('taken', second),
    });
    assert.equal(conflict.status, 409);

    // THE ROLLBACK, OBSERVED. If the conditional UPDATE had committed, this
    // would now be a 403 and the holder would have lost their invitation to a
    // typo.
    const retry = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('fresh', second),
    });
    assert.equal(retry.status, 201);
  } finally {
    await service.close();
  }
});

test('an expired invite is refused', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'invite' });
  try {
    const store = createDrizzleInviteStore(database.db);
    const minted = await store.mint({ note: 'already dead', expiresAt: new Date(Date.now() - 1000) });

    const response = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('late', minted.token),
    });
    assert.equal(response.status, 403);
  } finally {
    await service.close();
  }
});

test('an open instance ignores the invite requirement entirely', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'open' });
  try {
    const response = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('anyone'),
    });
    assert.equal(response.status, 201);
  } finally {
    await service.close();
  }
});

test('the handshake advertises the mode, so a client need not provoke a 403', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'invite' });
  try {
    const response = await service.request<{ signupMode?: string }>({ method: 'GET', path: '/health' });
    assert.equal(response.status, 200);
    assert.equal(response.body.signupMode, 'invite');
  } finally {
    await service.close();
  }
});
