/**
 * Invite redemption against REAL Postgres (M166, addressed in M192).
 *
 * This file exists for the properties the unit suite structurally cannot
 * reach. `tests/unit/fake-account-store.ts` reproduces the RULES by ordering
 * its writes, but the rules are enforced in production by a transaction and a
 * conditional UPDATE, and neither a rollback nor a row lock has any meaning in
 * a JavaScript Map. Concurrency is a property of the database, so it is tested
 * against the database.
 *
 * Three things are proved here and nowhere else:
 *
 *  - Concurrent redemptions of ONE invite produce exactly one account. If the
 *    store did a SELECT-then-UPDATE, both callers would see it unredeemed and
 *    two people would get in on one invitation.
 *  - A signup for an address that already has an account leaves the invite
 *    spendable. That is the transaction's rollback, observed from outside: the
 *    conditional UPDATE has already run and been undone by the time the caller
 *    sees the 409.
 *  - The five writes of a signup commit together. An account with no key
 *    records logs in and decrypts nothing, and the client has thrown the
 *    passphrase away by the time it would find out.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { eq } from 'drizzle-orm';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import { createDrizzleInviteStore } from '../../src/db/invite-store.js';
import { generateSignupInviteToken } from '../../src/lib/tokens.js';
import { accounts, signupInvites, syncKeyRecords } from '../../src/db/schema.js';
import {
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
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

/** The signup request as this service's wire contract defines it (PROTOCOL.md §5.8). */
interface SignupRequest {
  authHash: string;
  kdfDescriptor: ReturnType<typeof sampleKdfDescriptor>;
  recoveryAuthHash: string;
  recoveryCode: string;
  keyRecords: { kind: string; kdfDescriptor: unknown; wrappedDek: string }[];
  displayName?: string;
  /** The only field that identifies anything: the address comes from the invite row. */
  inviteToken?: string;
}

function signupBody(inviteToken?: string): SignupRequest {
  const body: SignupRequest = {
    authHash: sampleAuthHash(11),
    kdfDescriptor: sampleKdfDescriptor(),
    recoveryAuthHash: sampleAuthHash(31),
    recoveryCode: sampleRecoveryCode(),
    keyRecords: [
      { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
      { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
    ],
  };
  // Assigned only when given, so the "no invite at all" case genuinely omits
  // the field rather than sending an explicit `undefined`.
  if (inviteToken !== undefined) body.inviteToken = inviteToken;
  return body;
}

/** Mints one live invite straight through the store — the admin API is tested separately. */
async function mintInvite(email: string, expiresAt = new Date(Date.now() + 60 * 60 * 1000)): Promise<string> {
  const store = createDrizzleInviteStore(database.db);
  const minted = await store.mint({
    email,
    displayName: null,
    role: 'member',
    dailyAiLimit: 0,
    expiresAt,
    now: new Date(),
  });
  if (!minted.ok) throw new Error(`could not mint an invite for ${email}: ${minted.reason}`);
  return minted.minted.token;
}

test('an invite admits exactly one account, even under concurrent redemption', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const token = await mintInvite('one-account-only@example.org');

    // Fired together, deliberately not awaited in sequence. With a
    // SELECT-then-UPDATE both would find the invite unredeemed.
    const attempts = await Promise.all(
      [1, 2, 3].map(() =>
        service.request<{ error?: string }>({ method: 'POST', path: '/v1/auth/signup', body: signupBody(token) }),
      ),
    );

    const created = attempts.filter((response) => response.status === 201);
    const refused = attempts.filter((response) => response.status !== 201);
    assert.equal(created.length, 1, `expected exactly one account, got ${created.length}`);
    assert.equal(refused.length, 2);
  } finally {
    await service.close();
  }
});

test('a signup for an address that already has an account is refused and the invite is NOT consumed', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const first = await mintInvite('taken@example.org');
    const created = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(first) });
    assert.equal(created.status, 201);

    // A SECOND invite for the same address. `InviteStore.mint` refuses one for
    // an address that already has an account, so this is written straight into
    // the table to reach the handler's own guard.
    const second = await mintInviteForTakenAddress('taken@example.org');

    const conflict = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(second) });
    assert.equal(conflict.status, 409);

    // THE ROLLBACK, OBSERVED. If the conditional UPDATE had committed, the
    // invite would now be spent and a retry after the operator fixed the
    // address would find nothing left.
    const rows = await database.db.select().from(accounts).where(eq(accounts.email, 'taken@example.org'));
    assert.equal(rows.length, 1, 'the conflicting signup must not have created a second row');

    const retry = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(second) });
    // Still a 409 (the address is still taken), and still not consumed — which
    // is exactly what "the 409 costs the invite nothing" means.
    assert.equal(retry.status, 409);
  } finally {
    await service.close();
  }
});

/**
 * Mints an invite for an address that already has an account, bypassing
 * `InviteStore.mint`'s own refusal.
 *
 * The store guard and the transaction guard defend different things: the store
 * stops an operator inviting somebody who is already here, and the transaction
 * stops a `409` from burning an invite that was minted before the account
 * existed. Only the second is under test above, and reaching it needs a row the
 * store would not write.
 */
async function mintInviteForTakenAddress(email: string): Promise<string> {
  const token = generateSignupInviteToken();
  await database.db.insert(signupInvites).values({
    tokenHash: token.hash,
    email,
    displayName: null,
    role: 'member',
    dailyAiLimit: 0,
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });
  return token.raw;
}

test('a successful signup commits the account, the escrow and BOTH key records together', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const token = await mintInvite('everything@example.org');
    const created = await service.request<{ account: { id: number } }>({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody(token),
    });
    assert.equal(created.status, 201);
    const accountId = created.body.account.id;

    const [row] = await database.db.select().from(accounts).where(eq(accounts.id, accountId));
    assert.ok(row, 'the account row must exist');
    // The escrow, without which no mailed reset can ever be answered.
    assert.ok(row.recoveryCodeEscrow !== null, 'signup must write an escrow');
    assert.ok(row.recoveryCodeEscrow.byteLength > 32, 'the escrow must be iv + ciphertext + tag');
    assert.ok(row.recoveryVerifier !== null, 'signup must write a recovery verifier');

    const records = await database.db.select().from(syncKeyRecords).where(eq(syncKeyRecords.accountId, accountId));
    assert.deepEqual(records.map((record) => record.kind).toSorted(), ['passphrase', 'recovery']);
  } finally {
    await service.close();
  }
});

test('an expired invite is refused', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const token = await mintInvite('late@example.org', new Date(Date.now() - 1000));
    const response = await service.request({ method: 'POST', path: '/v1/auth/signup', body: signupBody(token) });
    assert.equal(response.status, 403);
  } finally {
    await service.close();
  }
});

test('there is no signup without an invite, on any instance', async () => {
  // There is no open mode and no closed mode any more: the invite is the only
  // door, so a body without one is the same 403 a wrong token gets.
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const response = await service.request<{ error: string }>({
      method: 'POST',
      path: '/v1/auth/signup',
      body: signupBody(),
    });
    assert.equal(response.status, 403);
    assert.equal(response.body.error, 'invite-invalid');
  } finally {
    await service.close();
  }
});

test('invite-lookup shows the addressee, and every bad token is one 404', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const store = createDrizzleInviteStore(database.db);
    const minted = await store.mint({
      email: 'lookup@example.org',
      displayName: 'A Person',
      role: 'member',
      dailyAiLimit: 0,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
      now: new Date(),
    });
    if (!minted.ok) throw new Error('expected a minted invite');

    const found = await service.request<{ email: string; displayName: string | null }>({
      method: 'POST',
      path: '/v1/auth/invite-lookup',
      body: { inviteToken: minted.minted.token },
    });
    assert.equal(found.status, 200);
    assert.equal(found.body.email, 'lookup@example.org');
    assert.equal(found.body.displayName, 'A Person');

    for (const inviteToken of ['si_never-minted', 'gi_a-gateway-invite', '']) {
      const missing = await service.request<{ error: string }>({
        method: 'POST',
        path: '/v1/auth/invite-lookup',
        body: { inviteToken },
      });
      assert.equal(missing.status, 404, `token "${inviteToken}"`);
      assert.equal(missing.body.error, 'invite-invalid');
    }
  } finally {
    await service.close();
  }
});

test('the handshake reports protocol version 2 and carries no signupMode', async () => {
  const service: ServiceHarness = await startService({ db: database.db });
  try {
    const response = await service.request<{ protocolVersion: number; signupMode?: string }>({
      method: 'GET',
      path: '/health',
    });
    assert.equal(response.status, 200);
    assert.equal(response.body.protocolVersion, 2);
    // The field went with the setting it described.
    assert.equal(response.body.signupMode, undefined);
  } finally {
    await service.close();
  }
});
