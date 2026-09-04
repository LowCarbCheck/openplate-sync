/**
 * The research contribution family of ADR-0003, against a real Postgres and
 * the committed migrations.
 *
 * What is only provable here, and is therefore why this suite exists rather
 * than a set of handler unit tests:
 *   - both `ON DELETE CASCADE`s actually removing the row, from either end
 *   - the `UNIQUE (contributor_account_id, study_account_id)` index and the
 *     monotonic version CAS built on top of it
 *   - the `CHECK (contributor <> study)` refusing a self-contribution
 *   - withdrawal being ONE transaction — proved with a LATE failure, after the
 *     contribution row has already been deleted inside it
 *   - byte-exact round-tripping of the sealed envelope through `bytea`
 *   - that `rotate-dek` never touches this lane
 *   - and the one that matters most: that no study-side response carries a
 *     contributor's account id
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { eq } from 'drizzle-orm';
import { accounts, researchContributions, researchWithdrawals } from '../../src/db/schema.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  sampleAuthHash,
  sampleRecoveryCode,
  sampleCiphertext,
  sampleContributionBody,
  sampleKdfDescriptor,
  sampleWrappedDek,
  startService,
  type ServiceHarness,
} from './service-harness.js';

/** A plausible client-derived pseudonym: 128 bits, Crockford base32. The server never computes or verifies one. */
const PSEUDONYM = 'J7K2QW9ZP4M6N8R3T5V0XB1CDE';
const SCHEMA_TIER = 'daily-intake:v1';

interface Party {
  accountId: number;
  accessToken: string;
}

interface ContributionSummary {
  studyAccountId: number;
  pseudonym: string;
  schemaTier: string;
  contributionVersion: number;
  createdAt: string;
  updatedAt: string;
}

interface ContributorList {
  contributions: ContributionSummary[];
}

interface StudyRow {
  pseudonym: string;
  contributionVersion: number;
  schemaTier: string;
  body: string;
  createdAt: string;
}

interface StudyList {
  studyAccountId: number;
  contributions: StudyRow[];
}

interface WithdrawalList {
  withdrawals: { pseudonym: string; withdrawnAt: string }[];
}

let database: TestDatabase;
let service: ServiceHarness;

before(async () => {
  database = await setupTestDatabase();
  service = await startService({ db: database.db, research: true });
});

after(async () => {
  await service.close();
  await database.close();
});

beforeEach(async () => {
  await database.reset();
});

/**
 * An account, created the only way this service can: an invite is minted and
 * redeemed. `signupThroughInvite` is the harness's helper for exactly that.
 */
async function signUp(name: string, seed: number): Promise<Party> {
  const session = await service.signupThroughInvite({
    email: `${name}@example.org`,
    authHash: sampleAuthHash(seed),
  });
  return { accountId: session.account.id, accessToken: session.tokens.accessToken };
}

/** A contributor enrolled in one study, having pushed version 1. */
async function enrolledPair(): Promise<{ contributor: Party; study: Party; sealed: string }> {
  const contributor = await signUp('contributor', 51);
  const study = await signUp('study', 52);
  const sealed = sampleContributionBody(23, 200);

  const push = await service.request<ContributionSummary>({
    method: 'PUT',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
    body: { pseudonym: PSEUDONYM, schemaTier: SCHEMA_TIER, body: sealed, contributionVersion: 1 },
  });
  assert.equal(push.status, 200);
  return { contributor, study, sealed };
}

test('a contributor pushes, lists and re-pushes under contribution CAS', async () => {
  const { contributor, study, sealed } = await enrolledPair();

  const listed = await service.request<ContributorList>({
    method: 'GET',
    path: '/v1/sync/contributions',
    accessToken: contributor.accessToken,
  });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.contributions.length, 1);
  const [enrolment] = listed.body.contributions;
  assert.ok(enrolment);
  assert.equal(enrolment.studyAccountId, study.accountId);
  assert.equal(enrolment.pseudonym, PSEUDONYM);
  assert.equal(enrolment.contributionVersion, 1);
  // PROTOCOL.md §5.18: the contributor's own list never returns `body`. The
  // client still holds the source it was reduced from.
  assert.ok(!Object.hasOwn(enrolment, 'body'), 'the contributor list must never carry the sealed body');

  // THE CAS TOKEN, ROUND-TRIPPED THROUGH A STRING. The token here is the
  // integer version, but the row's timestamps ride the same wire, and an
  // in-memory `Date` compared against an in-memory `Date` is exactly what let
  // the µs/ms precision bug hide on `sync_key_records`. So: take the ISO
  // string out of the JSON, hand it back to `new Date`, and require the
  // re-serialisation to be identical — which is only true if the column
  // cannot hold a sub-millisecond tail.
  assert.equal(new Date(enrolment.createdAt).toISOString(), enrolment.createdAt);
  assert.equal(new Date(enrolment.updatedAt).toISOString(), enrolment.updatedAt);
  // And read the digits the wire cannot express directly out of Postgres,
  // because `pg` parses a timestamp into a JS `Date` (ms-only) and would
  // therefore hide a `timestamp(6)` column from the assertion above.
  const raw = await database.pool.query<{ created_at: string; updated_at: string }>(
    'SELECT created_at::text AS created_at, updated_at::text AS updated_at FROM research_contributions',
  );
  for (const row of raw.rows) {
    assert.match(row.created_at, /\.\d{1,3}$|[^.]$/, `created_at "${row.created_at}" carries a sub-ms tail`);
    assert.match(row.updated_at, /\.\d{1,3}$|[^.]$/, `updated_at "${row.updated_at}" carries a sub-ms tail`);
  }

  // A version that is not strictly greater is refused, and nothing is written.
  for (const stale of [1, 0.5, -1]) {
    const rejected = await service.request<{ currentVersion?: number; error?: string }>({
      method: 'PUT',
      path: `/v1/sync/contributions/${study.accountId}`,
      accessToken: contributor.accessToken,
      body: {
        pseudonym: PSEUDONYM,
        schemaTier: SCHEMA_TIER,
        body: sampleContributionBody(99, 200),
        contributionVersion: stale,
      },
    });
    assert.ok(rejected.status === 409 || rejected.status === 400, `version ${stale} must be refused`);
  }
  const [unchanged] = await database.db
    .select()
    .from(researchContributions)
    .where(eq(researchContributions.studyAccountId, study.accountId));
  assert.ok(unchanged);
  assert.equal(unchanged.contributionVersion, 1);
  assert.equal(Buffer.from(unchanged.body).toString('base64'), sealed, 'a losing CAS must write nothing');

  // A strictly greater version wins, and it may SKIP: the client recomputes
  // the window and re-pushes it whole, so a version that never left the device
  // must not wedge the lane.
  const resealed = sampleContributionBody(77, 320);
  const accepted = await service.request<ContributionSummary>({
    method: 'PUT',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
    body: { pseudonym: PSEUDONYM, schemaTier: SCHEMA_TIER, body: resealed, contributionVersion: 4 },
  });
  assert.equal(accepted.status, 200);
  assert.equal(accepted.body.contributionVersion, 4);

  // Byte-exact round trip through `bytea`, read back from the study's side.
  const cohort = await service.request<StudyList>({
    method: 'GET',
    path: '/v1/sync/study/contributions',
    accessToken: study.accessToken,
  });
  assert.equal(cohort.status, 200);
  assert.equal(cohort.body.contributions[0]?.body, resealed);
});

test('contribution CAS refuses a version equal to the stored one, reporting the current value', async () => {
  const { contributor, study } = await enrolledPair();

  const conflict = await service.request<{ currentVersion: number }>({
    method: 'PUT',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
    body: {
      pseudonym: PSEUDONYM,
      schemaTier: SCHEMA_TIER,
      body: sampleContributionBody(31, 200),
      contributionVersion: 1,
    },
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.currentVersion, 1);
});

test('the study side carries no account id, in any response, for any row', async () => {
  const { contributor, study } = await enrolledPair();

  // Withdraw a SECOND contributor too, so the withdrawals response has a row
  // to be wrong about as well.
  const other = await signUp('other-contributor', 53);
  const otherPseudonym = 'X4B7QW2ZP9M1N5R8T3V0KJ6CDE';
  const push = await service.request({
    method: 'PUT',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: other.accessToken,
    body: {
      pseudonym: otherPseudonym,
      schemaTier: SCHEMA_TIER,
      body: sampleContributionBody(41, 200),
      contributionVersion: 1,
    },
  });
  assert.equal(push.status, 200);
  const withdraw = await service.request({
    method: 'DELETE',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: other.accessToken,
  });
  assert.equal(withdraw.status, 204);

  const cohort = await service.request<StudyList>({
    method: 'GET',
    path: '/v1/sync/study/contributions',
    accessToken: study.accessToken,
  });
  assert.equal(cohort.status, 200);
  assert.equal(cohort.body.contributions.length, 1);

  // EXACT KEY SETS, NOT A SPOT CHECK. §5.18 freezes the per-row shape, and an
  // exact set is the only assertion that fails when somebody adds a field —
  // which is precisely the mistake this lane is shaped to prevent, because
  // §5.16's grantee read REQUIRES `grantorAccountId` and copying that shape
  // here imports a re-identification leak (ADR-0003 prohibition 2).
  for (const row of cohort.body.contributions) {
    assert.deepEqual(Object.keys(row).toSorted(), [
      'body',
      'contributionVersion',
      'createdAt',
      'pseudonym',
      'schemaTier',
    ]);
  }
  // The only account id in the envelope is the CALLER'S OWN, which it
  // authenticated as and already knows. It must never be a contributor's.
  assert.equal(cohort.body.studyAccountId, study.accountId);
  assert.notEqual(cohort.body.studyAccountId, contributor.accountId);
  assert.deepEqual(Object.keys(cohort.body).toSorted(), ['contributions', 'studyAccountId']);

  const withdrawals = await service.request<WithdrawalList>({
    method: 'GET',
    path: '/v1/sync/study/withdrawals',
    accessToken: study.accessToken,
  });
  assert.equal(withdrawals.status, 200);
  assert.deepEqual(Object.keys(withdrawals.body).toSorted(), ['withdrawals']);
  assert.equal(withdrawals.body.withdrawals.length, 1);
  for (const row of withdrawals.body.withdrawals) {
    assert.deepEqual(Object.keys(row).toSorted(), ['pseudonym', 'withdrawnAt']);
  }

  // A blunt second net over the raw bytes, in case a future response nests
  // something: NO key anywhere in either study-side body may name an account,
  // apart from the caller's own `studyAccountId` at the envelope's top level.
  for (const path of ['/v1/sync/study/contributions', '/v1/sync/study/withdrawals']) {
    const response = await fetch(`${service.baseUrl}${path}`, {
      headers: { authorization: `Bearer ${study.accessToken}` },
    });
    const text = await response.text();
    const keys = [...text.matchAll(/"([^"]+)"\s*:/g)].map((match) => match[1]);
    const offenders = keys.filter((key) => /account/i.test(key ?? '') && key !== 'studyAccountId');
    assert.deepEqual(offenders, [], `${path} must name no contributor account key`);
  }
});

test('withdrawal is atomic: the row and the tombstone land together, or neither does', async () => {
  const { contributor, study } = await enrolledPair();

  const withdrawn = await service.request({
    method: 'DELETE',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
  });
  assert.equal(withdrawn.status, 204);

  // Genuinely erased on this side.
  const rows = await database.db
    .select()
    .from(researchContributions)
    .where(eq(researchContributions.studyAccountId, study.accountId));
  assert.deepEqual(rows, []);
  // And the instruction survives, keyed by pseudonym alone.
  const tombstones = await database.db
    .select()
    .from(researchWithdrawals)
    .where(eq(researchWithdrawals.studyAccountId, study.accountId));
  assert.equal(tombstones.length, 1);
  assert.equal(tombstones[0]?.pseudonym, PSEUDONYM);
  // ADR-0003 prohibition 6: no account id survives on any withdrawal record —
  // and the table has no column to hold one.
  const columns = Object.keys(tombstones[0] ?? {});
  assert.deepEqual(
    columns.filter((column) => /contributor/i.test(column)),
    [],
  );

  // Idempotent: withdrawing again is a 204 and writes no second tombstone.
  const again = await service.request({
    method: 'DELETE',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
  });
  assert.equal(again.status, 204);
  const stillOne = await database.db.select().from(researchWithdrawals);
  assert.equal(stillOne.length, 1);
});

test('withdrawal is atomic under a LATE failure: the delete rolls back with the tombstone', async () => {
  const contributor = await signUp('late-fail', 54);
  const study = await signUp('late-fail-study', 55);

  // Seeded DIRECTLY, bypassing the route's validation, with a pseudonym the
  // TOMBSTONE table refuses (`CHECK length(pseudonym) > 0`). That makes the
  // failure land LATE — inside the transaction, after the contribution row has
  // already been deleted — which is the only shape that can tell an atomic
  // withdrawal from two individually-committing statements. It is the same
  // discipline `rotate-dek.test.ts` uses with a keep list naming a share that
  // is not there.
  await database.db.insert(researchContributions).values({
    contributorAccountId: contributor.accountId,
    studyAccountId: study.accountId,
    pseudonym: '',
    schemaTier: SCHEMA_TIER,
    body: Buffer.alloc(120, 8),
    contributionVersion: 1,
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  const failed = await service.request({
    method: 'DELETE',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: contributor.accessToken,
  });
  assert.equal(failed.status, 500, 'the tombstone constraint must refuse, and the refusal must surface');

  // THE ASSERTION THAT DISCRIMINATES. If the store ever stopped being one
  // transaction, the delete above would have committed and this would be
  // empty — a contribution erased with nobody instructed to purge it, which
  // is ADR-0003 prohibition 6's failure mode exactly.
  const survivors = await database.db
    .select()
    .from(researchContributions)
    .where(eq(researchContributions.studyAccountId, study.accountId));
  assert.equal(survivors.length, 1, 'the contribution must have rolled back with the failed tombstone');
  const tombstones = await database.db.select().from(researchWithdrawals);
  assert.deepEqual(tombstones, []);
});

test('cascade: deleting either account erases the contribution, from either end', async () => {
  const { contributor, study } = await enrolledPair();

  await database.db.delete(accounts).where(eq(accounts.id, contributor.accountId));
  assert.deepEqual(await database.db.select().from(researchContributions), [], 'contributor delete must cascade');

  // Now the study end, with a fresh pair.
  const second = await signUp('second-contributor', 56);
  const push = await service.request({
    method: 'PUT',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: second.accessToken,
    body: {
      pseudonym: PSEUDONYM,
      schemaTier: SCHEMA_TIER,
      body: sampleContributionBody(61, 200),
      contributionVersion: 1,
    },
  });
  assert.equal(push.status, 200);
  const withdrawn = await service.request({
    method: 'DELETE',
    path: `/v1/sync/contributions/${study.accountId}`,
    accessToken: second.accessToken,
  });
  assert.equal(withdrawn.status, 204);
  assert.equal((await database.db.select().from(researchWithdrawals)).length, 1);

  await database.db.delete(accounts).where(eq(accounts.id, study.accountId));
  assert.deepEqual(await database.db.select().from(researchContributions), [], 'study delete must cascade');
  // The tombstone goes too: an instruction to a study that no longer exists
  // instructs nobody.
  assert.deepEqual(await database.db.select().from(researchWithdrawals), [], 'the withdrawal ledger cascades too');
});

test('the request boundary refuses what no row should ever hold', async () => {
  const contributor = await signUp('picky', 57);
  const study = await signUp('picky-study', 58);
  const valid = {
    pseudonym: PSEUDONYM,
    schemaTier: SCHEMA_TIER,
    body: sampleContributionBody(71, 200),
    contributionVersion: 1,
  };

  const cases: readonly { name: string; path: string; body: unknown; status: number }[] = [
    // ADR-0003 prohibition 1: the schema is fixed by protocol revision, never
    // by study configuration. An unclassified tier never reaches a row.
    {
      name: 'an unknown schema tier',
      path: `/v1/sync/contributions/${study.accountId}`,
      body: { ...valid, schemaTier: 'meal-times:v1' },
      status: 400,
    },
    {
      name: 'an empty pseudonym',
      path: `/v1/sync/contributions/${study.accountId}`,
      body: { ...valid, pseudonym: '   ' },
      status: 400,
    },
    {
      name: 'an unbounded pseudonym',
      path: `/v1/sync/contributions/${study.accountId}`,
      body: { ...valid, pseudonym: 'A'.repeat(65) },
      status: 400,
    },
    {
      name: 'a structurally impossible envelope',
      path: `/v1/sync/contributions/${study.accountId}`,
      body: { ...valid, body: Buffer.alloc(8, 1).toString('base64') },
      status: 400,
    },
    {
      name: 'a self-contribution',
      path: `/v1/sync/contributions/${contributor.accountId}`,
      body: valid,
      status: 400,
    },
    // The same 404 the read paths give: naming an account in a URL must not
    // become an existence oracle.
    {
      name: 'a study account that does not exist',
      path: '/v1/sync/contributions/999999',
      body: valid,
      status: 404,
    },
  ];

  for (const testCase of cases) {
    const response = await service.request<{ error: string }>({
      method: 'PUT',
      path: testCase.path,
      accessToken: contributor.accessToken,
      body: testCase.body,
    });
    assert.equal(response.status, testCase.status, testCase.name);
    assert.ok(response.body.error, `${testCase.name} must answer the protocol's error envelope`);
  }
  assert.deepEqual(await database.db.select().from(researchContributions), [], 'no refusal may leave a row behind');
});

test('rotate-dek never touches a contribution — two unrelated key domains', async () => {
  const { contributor, study, sealed } = await enrolledPair();

  const rotated = await service.request<{ newVersion: number }>({
    method: 'POST',
    path: '/v1/sync/rotate-dek',
    accessToken: contributor.accessToken,
    body: {
      blob: { baseVersion: 0, envelopeVersion: 1, ciphertext: sampleCiphertext(29, 128) },
      keyRecords: [
        { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(3), wrappedDek: sampleWrappedDek(53) },
        { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(54) },
      ],
      // Required since the M192 addendum: a rotation always mints a new code.
      newRecoveryAuthHash: sampleAuthHash(71),
      recoveryCode: sampleRecoveryCode(5),
      shares: [],
    },
  });
  assert.equal(rotated.status, 200);

  // ADR-0003 prohibition 7: contributions are never wrapped under the DEK and
  // never ride through `rotate-dek`. The row is byte-identical afterwards —
  // it is sealed to the STUDY's public key and a new DEK means nothing to it.
  const [row] = await database.db
    .select()
    .from(researchContributions)
    .where(eq(researchContributions.studyAccountId, study.accountId));
  assert.ok(row);
  assert.equal(row.contributionVersion, 1);
  assert.equal(Buffer.from(row.body).toString('base64'), sealed);
});
