/**
 * The abuse controls, exercised through the real HTTP stack with the REAL
 * throttle configuration (the round-trip suite deliberately runs permissive —
 * see `PERMISSIVE_THROTTLE` — because every test request comes from
 * 127.0.0.1 and would otherwise lock itself out after five accounts).
 *
 * Five properties, each a way a public instance gets abused:
 *  - repeated signups from one IP lock out with a `429` and a `Retry-After`
 *  - repeated failed logins lock out, and a *different* IP-scoped bucket is
 *    unaffected, so a throttle cannot be turned into an account-lockout DoS
 *  - bulk KDF-descriptor probing locks out, and rotating the probed address
 *    does not buy a fresh allowance
 *  - the namespaces are independent, so one endpoint's abuse does not deny
 *    service on the others
 *  - repeated reset requests lock out and are NEVER cleared, because a person
 *    forgets their password once and a caller filling a mailbox does not
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_THROTTLE_CONFIG } from '../../src/lib/throttle.js';
import { createDrizzleInviteStore } from '../../src/db/invite-store.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  startService,
} from './service-harness.js';

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

/** Mints one live invite for an address, straight through the store. */
async function mintInvite(email: string): Promise<string> {
  const store = createDrizzleInviteStore(database.db);
  const minted = await store.mint({
    email,
    displayName: null,
    role: 'member',
    dailyAiLimit: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    now: new Date(),
  });
  if (!minted.ok) throw new Error(`could not mint an invite for ${email}: ${minted.reason}`);
  return minted.minted.token;
}

function signupBody(inviteToken: string) {
  return {
    inviteToken,
    authHash: sampleAuthHash(11),
    kdfDescriptor: sampleKdfDescriptor(),
    recoveryAuthHash: sampleAuthHash(31),
    recoveryCode: sampleRecoveryCode(),
    keyRecords: [
      { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
      { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
    ],
  };
}

test('signup throttles by IP after the free allowance, with a Retry-After', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    // `freeAttempts` failures leave the bucket unlocked; it is the NEXT one
    // that trips it. So the free allowance plus one all still succeed, and
    // only the request after that is refused.
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const token = await mintInvite(`flood-${attempt}@example.org`);
      const response = await service.request({
        method: 'POST',
        path: '/v1/auth/signup',
        body: signupBody(token),
      });
      assert.equal(response.status, 201);
    }

    const last = await mintInvite('flood-last@example.org');
    const blocked = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody(last),
    });
    assert.equal(blocked.status, 429);
    // A client that cannot tell how long to wait retries immediately and
    // makes the problem worse.
    assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  } finally {
    await service.close();
  }
});

test('repeated failed logins lock the bucket, and a successful login clears it', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    const token = await mintInvite('target@example.org');
    const created = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(token) });
    assert.equal(created.status, 201);

    // One short of the lockout, then a correct login, which must reset the
    // counter — a user who fumbles their passphrase twice and then gets it
    // right must not be walking around one mistake from a lockout.
    for (let attempt = 0; attempt < DEFAULT_THROTTLE_CONFIG.freeAttempts - 1; attempt += 1) {
      const failed = await service.request({
        method: 'POST',
        path: '/v1/auth/login',
        body: { email: 'target@example.org', authHash: sampleAuthHash(99) },
      });
      assert.equal(failed.status, 401);
    }

    const success = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email: 'target@example.org', authHash: sampleAuthHash(11) },
    });
    assert.equal(success.status, 200);

    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const failed = await service.request({
        method: 'POST',
        path: '/v1/auth/login',
        body: { email: 'target@example.org', authHash: sampleAuthHash(99) },
      });
      assert.equal(failed.status, 401);
    }

    const locked = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email: 'target@example.org', authHash: sampleAuthHash(99) },
    });
    assert.equal(locked.status, 429);

    // A DIFFERENT account from the same IP is a different bucket, so hammering
    // one address cannot lock the whole instance.
    const otherAccount = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { email: 'someone-else@example.org', authHash: sampleAuthHash(11) },
    });
    assert.equal(otherAccount.status, 401);
  } finally {
    await service.close();
  }
});

test('bulk KDF probing locks out, and rotating the probed address does not evade it', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    // A DIFFERENT address every time — this is exactly the enumeration attack,
    // so the bucket must be keyed by source alone. A per-address bucket would
    // hand out a fresh allowance for every address probed and never fire.
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const response = await service.request<{ kdfDescriptor: unknown }>({
        method: 'POST',
        path: '/v1/auth/kdf',
        body: { email: `probe-${attempt}@example.org` },
      });
      assert.equal(response.status, 200);
    }

    const blocked = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/kdf',
      body: { email: 'probe-last@example.org' },
    });
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) >= 1);
  } finally {
    await service.close();
  }
});

test('the KDF throttle is independent of the login and signup buckets', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    // Exhaust kdf...
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      await service.request({ method: 'POST', path: '/v1/auth/kdf', body: { email: `probe-${attempt}@example.org` } });
    }
    assert.equal(
      (await service.request({ method: 'POST', path: '/v1/auth/kdf', body: { email: 'probe-x@example.org' } })).status,
      429,
    );

    // ...and a legitimate signup from the same IP still works. Namespaces keep
    // one endpoint's abuse from denying service on the others.
    const token = await mintInvite('unaffected@example.org');
    const created = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(token) });
    assert.equal(created.status, 201);
  } finally {
    await service.close();
  }
});

test('reset requests throttle per address and are never cleared by a success', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    const token = await mintInvite('forgetful@example.org');
    assert.equal(
      (await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(token) })).status,
      201,
    );

    // Every request counts, including the ones that found an account and sent a
    // letter. A person forgets their password once; a caller filling somebody's
    // mailbox, or measuring the difference between a known and an unknown
    // address, does it thousands of times.
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const response = await service.request({
        method: 'POST',
        path: '/v1/auth/reset/request',
        body: { email: 'forgetful@example.org' },
      });
      assert.equal(response.status, 202);
    }

    const blocked = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/reset/request',
      body: { email: 'forgetful@example.org' },
    });
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) >= 1);

    // A DIFFERENT address from the same IP is a different bucket, so one
    // person's flood cannot lock everybody else out of their own reset.
    const other = await service.request({
      method: 'POST',
      path: '/v1/auth/reset/request',
      body: { email: 'somebody-else@example.org' },
    });
    assert.equal(other.status, 202);
  } finally {
    await service.close();
  }
});
