/**
 * The abuse controls, exercised through the real HTTP stack with the REAL
 * throttle configuration (the round-trip suite deliberately runs permissive —
 * see `PERMISSIVE_THROTTLE` — because every test request comes from
 * 127.0.0.1 and would otherwise lock itself out after five accounts).
 *
 * Four properties, each a way a public instance gets abused:
 *  - `SIGNUP_MODE=closed` actually closes signups
 *  - repeated signups from one IP lock out with a `429` and a `Retry-After`
 *  - repeated failed logins lock out, and a *different* IP-scoped bucket is
 *    unaffected, so a throttle cannot be turned into an account-lockout DoS
 *  - bulk KDF-descriptor probing locks out, and rotating the probed address
 *    does not buy a fresh allowance
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_THROTTLE_CONFIG } from '../../src/lib/throttle.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
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

function signupBody(handle: string) {
  return { handle, authHash: sampleAuthHash(11), kdfDescriptor: sampleKdfDescriptor() };
}

test('SIGNUP_MODE=closed closes signups with a 403', async () => {
  const service: ServiceHarness = await startService({ db: database.db, signupMode: 'closed' });
  try {
    const response = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('closed'),
    });
    assert.equal(response.status, 403);
    assert.match(response.body.error, /not accepting/i);
  } finally {
    await service.close();
  }
});

test('signup throttles by IP after the free allowance, with a Retry-After', async () => {
  const service = await startService({ db: database.db, throttleConfig: DEFAULT_THROTTLE_CONFIG });
  try {
    // `freeAttempts` failures leave the bucket unlocked; it is the NEXT one
    // that trips it. So the free allowance plus one all still succeed, and
    // only the request after that is refused.
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const response = await service.request({
        method: 'POST',
        path: '/v1/auth/signup',
        body: signupBody(`flood-${attempt}`),
      });
      assert.equal(response.status, 201);
    }

    const blocked = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('flood-last'),
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
    const created = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('target-otter'),
    });
    assert.equal(created.status, 201);

    // One short of the lockout, then a correct login, which must reset the
    // counter — a user who fumbles their passphrase twice and then gets it
    // right must not be walking around one mistake from a lockout.
    for (let attempt = 0; attempt < DEFAULT_THROTTLE_CONFIG.freeAttempts - 1; attempt += 1) {
      const failed = await service.request({
        method: 'POST',
        path: '/v1/auth/login',
        body: { handle: 'target-otter', authHash: sampleAuthHash(99) },
      });
      assert.equal(failed.status, 401);
    }

    const success = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { handle: 'target-otter', authHash: sampleAuthHash(11) },
    });
    assert.equal(success.status, 200);

    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const failed = await service.request({
        method: 'POST',
        path: '/v1/auth/login',
        body: { handle: 'target-otter', authHash: sampleAuthHash(99) },
      });
      assert.equal(failed.status, 401);
    }

    const locked = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { handle: 'target-otter', authHash: sampleAuthHash(99) },
    });
    assert.equal(locked.status, 429);

    // A DIFFERENT account from the same IP is a different bucket, so hammering
    // one address cannot lock the whole instance.
    const otherAccount = await service.request({
      method: 'POST',
      path: '/v1/auth/login',
      body: { handle: 'someone-else', authHash: sampleAuthHash(11) },
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
    // so the bucket must be keyed by source alone. A per-handle bucket would
    // hand out a fresh allowance for every address probed and never fire.
    for (let attempt = 0; attempt <= DEFAULT_THROTTLE_CONFIG.freeAttempts; attempt += 1) {
      const response = await service.request<{ kdfDescriptor: unknown }>({
        method: 'POST',
        path: '/v1/auth/kdf',
        body: { handle: `probe-${attempt}` },
      });
      assert.equal(response.status, 200);
    }

    const blocked = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/kdf',
      body: { handle: 'probe-last' },
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
      await service.request({ method: 'POST', path: '/v1/auth/kdf', body: { handle: `probe-${attempt}` } });
    }
    assert.equal(
      (await service.request({ method: 'POST', path: '/v1/auth/kdf', body: { handle: 'probe-x' } })).status,
      429,
    );

    // ...and a legitimate signup from the same IP still works. Namespaces keep
    // one endpoint's abuse from denying service on the others.
    const created = await service.request({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody('unaffected'),
    });
    assert.equal(created.status, 201);
  } finally {
    await service.close();
  }
});
