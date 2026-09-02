/**
 * No admin response carries credential material or ciphertext — checked by
 * walking the whole body, not by reading the code.
 *
 * The prohibitions come from
 * `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`, and each has a
 * reason worth restating: ciphertext is still personal data, and an endpoint
 * that returns it is an exfiltration route whether or not anybody uses it; the
 * verifier is what a login is checked against; the KDF descriptor is what a
 * client needs to derive a key. None has an operational use that justifies
 * putting it where a screenshot, a log line or a paste into a chat window can
 * carry it.
 *
 * TWO ASSERTIONS, BECAUSE ONE OF THEM IS WEAK ON ITS OWN. The field NAMES
 * catch a whole object being spread into a response. The seeded VALUES catch
 * the same material arriving under a different name — a `blobPreview`, a
 * `credential`, a debug field somebody added while chasing a bug. The fixture
 * holds real-looking values for exactly that reason: an absence assertion
 * against a fixture that never had the value is vacuous.
 *
 * The walk is over the raw response TEXT rather than a parsed object, so a
 * value nested at any depth, in any key, in any encoding this service would
 * plausibly use, is still caught.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { asArray, asNumber, asObject, asString, type JsonValue } from '../../src/lib/json.js';
import { startAdminHarness, type AdminHarness } from './admin-harness.js';
import type { AdminSeedSecrets } from './fake-admin-store.js';

/** The two invite values that must never appear in a read response. */
interface InviteSeedSecrets {
  token: string;
  digest: string;
}

const ADMIN_TOKEN = 'admin-token-for-the-unit-suite-0123456789';

/** Names that must not appear as a key — or anywhere else — in an admin body. */
const FORBIDDEN_NAMES = ['ciphertext', 'verifier', 'kdfDescriptor', 'kdf_descriptor', 'wrappedDek', 'tokenHash'];

let harness: AdminHarness;
let secrets: AdminSeedSecrets;
/** A minted invite's raw token and digest — neither may appear in any READ body. */
let inviteSecrets: InviteSeedSecrets;

before(async () => {
  harness = await startAdminHarness({ adminToken: ADMIN_TOKEN });
  // An account with everything: a verified address, a stored blob, and both
  // key-record kinds. If any endpoint could leak, this is the account it
  // would leak.
  secrets = harness.admin.seed({
    id: 3,
    handle: 'has-everything',
    blobSizeBytes: 4096,
    keyRecordKinds: ['passphrase', 'recovery'],
  });

  // An invite exists too, and it is REDEEMED — the state that carries the most
  // to leak, since it links a capability to an account. Its raw token is a
  // secret the mint response legitimately returned once; every read after that
  // must be free of both it and its digest.
  const minted = await harness.invites.mint({ note: 'a person', expiresAt: new Date('2027-01-01T00:00:00.000Z') });
  harness.invites.markRedeemed(minted.invite.id, 3);
  const digest = harness.invites.digestOf(minted.invite.id);
  if (digest === undefined) throw new Error('expected the fake store to hold a digest');
  inviteSecrets = { token: minted.token, digest };
});

after(async () => {
  await harness.close();
});

const READ_ENDPOINTS: readonly string[] = [
  '/v1/admin/accounts',
  '/v1/admin/accounts/3',
  '/v1/admin/stats',
  '/v1/admin/invites',
];

test('no admin response body names a forbidden field', async () => {
  for (const path of READ_ENDPOINTS) {
    const response = await harness.request({ method: 'GET', path, token: ADMIN_TOKEN });
    assert.equal(response.status, 200, path);
    const body = await response.text();

    for (const name of FORBIDDEN_NAMES) {
      assert.ok(!body.includes(name), `${path} response contains "${name}"`);
    }
  }
});

test('no admin response body contains the seeded secret values', async () => {
  const seededValues = [
    secrets.verifier,
    secrets.kdfDescriptorSalt,
    secrets.wrappedDek,
    secrets.ciphertext,
    secrets.tokenHash,
    // The invite carve-out has exactly one exception, and this is what pins it
    // to that one place: the raw token may appear in the MINT response and
    // nowhere else. See ADR-0001.
    inviteSecrets.token,
    inviteSecrets.digest,
  ];

  for (const path of READ_ENDPOINTS) {
    const response = await harness.request({ method: 'GET', path, token: ADMIN_TOKEN });
    const body = await response.text();

    for (const value of seededValues) {
      assert.ok(!body.includes(value), `${path} response contains a seeded secret value`);
    }
  }
});

test('the account body carries exactly the documented metadata fields and nothing else', async () => {
  // A whitelist, not a blacklist: a new field added to the projection fails
  // here and has to be justified against the ADR before it can ship.
  const response = await harness.request({ method: 'GET', path: '/v1/admin/accounts/3', token: ADMIN_TOKEN });
  const body: JsonValue = await response.json();
  const account = asObject(asObject(body)?.account);

  assert.deepEqual(Object.keys(account ?? {}).toSorted(), ['blob', 'createdAt', 'handle', 'id', 'keyRecordKinds']);
  assert.deepEqual(Object.keys(asObject(account?.blob) ?? {}).toSorted(), ['sizeBytes', 'updatedAt']);
});

test('the responses are not empty, so the absence assertions above mean something', async () => {
  // Every check in this file is an absence. Without this, a bug that made all
  // three endpoints return `{}` would turn the whole file green.
  const accountResponse = await harness.request({ method: 'GET', path: '/v1/admin/accounts/3', token: ADMIN_TOKEN });
  const accountBody: JsonValue = await accountResponse.json();
  const account = asObject(asObject(accountBody)?.account);
  assert.equal(asNumber(account?.id), 3);
  assert.equal(asString(account?.handle), 'has-everything');
  assert.deepEqual(asArray(account?.keyRecordKinds), ['passphrase', 'recovery']);

  const statsResponse = await harness.request({ method: 'GET', path: '/v1/admin/stats', token: ADMIN_TOKEN });
  const statsBody: JsonValue = await statsResponse.json();
  const stats = asObject(asObject(statsBody)?.stats);
  assert.equal(asNumber(stats?.accounts), 1);
  assert.equal(asNumber(stats?.blobBytes), 4096);
});
