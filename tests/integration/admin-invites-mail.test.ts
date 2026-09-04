/**
 * The whole mail path, end to end: an operator mints an invite over the admin
 * API and a real HTTP request arrives at a real mail API carrying a link that
 * a real signup then redeems.
 *
 * WHY THIS SUITE EXISTS RATHER THAN MORE UNIT TESTS. `mail-messages.test.ts`
 * proves the letter is right and `mailer.test.ts` proves the POST is right,
 * but neither can prove they are WIRED to each other: an admin route that
 * built a message and forgot to send it, or sent it with the wrong token,
 * passes both. The assertion that closes that gap is the one below — the
 * token in the letter that arrived at the fake mail API creates an account.
 *
 * The fake mail API is a real listening server on an ephemeral port, so the
 * service's `fetch` is the production one and the payload it receives is the
 * payload pigeon would.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/server/create-app.js';
import { createDrizzleAccountStore } from '../../src/db/account-store.js';
import { createDrizzleStorageAdapter } from '../../src/db/storage-adapter.js';
import { createDrizzleAdminStore } from '../../src/db/admin-store.js';
import { createDrizzleInviteStore } from '../../src/db/invite-store.js';
import { createDrizzleRotationStore } from '../../src/db/rotation-store.js';
import { createSilentLogger } from '../../src/logger.js';
import { createThrottleStore } from '../../src/lib/throttle.js';
import { deriveServerSecrets } from '../../src/lib/server-secrets.js';
import { generateFamilyId, generatePasswordResetToken, generateToken } from '../../src/lib/tokens.js';
import { createHttpMailer } from '../../src/mail/mailer.js';
import type { AuthContext } from '../../src/accounts/auth-handlers.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import {
  PERMISSIVE_THROTTLE,
  sampleAuthHash,
  sampleKdfDescriptor,
  sampleRecoveryCode,
  sampleWrappedDek,
} from './service-harness.js';

const ADMIN_TOKEN = 'integration-admin-token-0123456789abcdef';
const CLIENT_BASE_URL = 'https://openplate.de';
const SERVER_PUBLIC_URL = 'https://sync.openplate.de';

interface ReceivedMail {
  authorization: string | undefined;
  from: string;
  to: string[];
  subject: string;
  text: string;
  html: string;
}

let database: TestDatabase;
let mailApi: Server;
let service: Server;
let baseUrl: string;
let received: ReceivedMail[];
/** What the fake mail API answers next. `null` is the ordinary success. */
let failNext: number | null;

before(async () => {
  database = await setupTestDatabase();

  received = [];
  failNext = null;
  mailApi = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      // SAFETY: the only client of this server is the service under test, and
      // `createHttpMailer` posts exactly the Resend-shaped payload declared by
      // `ReceivedMail`.
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Omit<ReceivedMail, 'authorization'>;
      received.push({ ...payload, authorization: req.headers.authorization });
      const status = failNext ?? 200;
      failNext = null;
      res.writeHead(status, { 'content-type': 'application/json' });
      // The echo a real provider sends back on a failure, so the "nothing
      // leaks" assertions below are about material that genuinely arrived.
      res.end(JSON.stringify({ id: 'msg_1', echo: payload }));
    });
  });
  mailApi.listen(0);
  await new Promise<void>((resolve) => mailApi.once('listening', resolve));
  // SAFETY: `listen(0)` binds a TCP port, and Node returns the string form of
  // an address only for a Unix domain socket, which this never opens.
  const { port: mailPort } = mailApi.address() as AddressInfo;

  const secrets = deriveServerSecrets('integration-test-root-secret-long-enough');
  const links = { clientBaseUrl: CLIENT_BASE_URL, serverPublicUrl: SERVER_PUBLIC_URL };
  const logger = createSilentLogger();
  // THE REAL HTTP MAILER, pointed at the fake API. Nothing about the transport
  // is substituted; only the far end is.
  const mailer = createHttpMailer({
    mail: {
      url: `http://127.0.0.1:${mailPort}/v1/emails`,
      apiKey: 'a-pigeon-tenant-key',
      from: 'openplate <openplate@mail.openplate.de>',
    },
    links,
    language: 'en',
    logger,
  });

  const authContext: AuthContext = {
    store: createDrizzleAccountStore(database.db),
    pepper: secrets.verifierPepper,
    enumerationSecret: secrets.enumerationSecret,
    escrowKey: secrets.escrowKey,
    mailer,
    now: () => new Date(),
    mintToken: generateToken,
    mintResetToken: generatePasswordResetToken,
    mintFamilyId: generateFamilyId,
    logger,
  };

  const app = createApp({
    authContext,
    storage: createDrizzleStorageAdapter(database.db),
    rotation: createDrizzleRotationStore(database.db),
    throttle: createThrottleStore(PERMISSIVE_THROTTLE),
    logger,
    trustProxy: false,
    mailer,
    mailConfigured: true,
    instance: { name: 'openplate', language: 'en', mail: true, ai: null },
    admin: {
      token: ADMIN_TOKEN,
      metadata: createDrizzleAdminStore(database.db),
      invites: createDrizzleInviteStore(database.db),
      links,
    },
  });
  service = app.listen(0);
  await new Promise<void>((resolve) => service.once('listening', resolve));
  // SAFETY: as above — an ephemeral TCP port, never a Unix domain socket.
  const { port } = service.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});

after(async () => {
  await new Promise<void>((resolve) => service.close(() => resolve()));
  await new Promise<void>((resolve) => mailApi.close(() => resolve()));
  await database.close();
});

beforeEach(async () => {
  await database.reset();
  received.length = 0;
  failNext = null;
});

interface JsonResponse<T> {
  status: number;
  body: T;
}

async function request<T>(input: {
  method: string;
  path: string;
  token?: string;
  body?: unknown;
}): Promise<JsonResponse<T>> {
  const headers: Record<string, string> = {};
  if (input.token !== undefined) headers.authorization = `Bearer ${input.token}`;
  if (input.body !== undefined) headers['content-type'] = 'application/json';
  const response = await fetch(`${baseUrl}${input.path}`, {
    method: input.method,
    headers,
    body: input.body === undefined ? undefined : JSON.stringify(input.body),
  });
  // SAFETY: the caller names the response type it is asserting against; this
  // helper cannot know it, and a wrong `T` fails the assertion that follows,
  // which is the point of the test. Every endpoint here answers JSON except a
  // 204, which has no body at all.
  const body = (response.status === 204 ? undefined : await response.json()) as T;
  return { status: response.status, body };
}

/** The signup body every case below sends, minus the token that varies. */
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

/** The `si_` token out of a link in a letter, which is what an invited person clicks. */
function tokenFromLink(link: string): string {
  const fragment = link.split('#')[1] ?? '';
  return new URLSearchParams(fragment).get('invite') ?? '';
}

test('minting an invite sends one mail whose text body carries the join link', async () => {
  const created = await request<{ invite: { id: number }; emailed: boolean; link: string | null; token?: string }>({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org', displayName: 'Anna' },
  });
  assert.equal(created.status, 201);

  // EXACTLY ONE POST. A second would mean the route sent twice, and a person
  // with two invitations does not know which link is live.
  assert.equal(received.length, 1);
  const mail = received[0];
  assert.ok(mail);
  assert.equal(mail.authorization, 'Bearer a-pigeon-tenant-key');
  assert.deepEqual(mail.to, ['anna@example.org']);
  assert.equal(mail.from, 'openplate <openplate@mail.openplate.de>');
  assert.equal(mail.subject, 'Your openplate invitation');

  // THE LINK, IN THE TEXT BODY. The plain part is what a lot of people see,
  // and a letter whose link is only in the html is a letter half of its
  // readers cannot act on.
  assert.ok(created.body.link, 'a configured instance must build a link');
  assert.ok(mail.text.includes(created.body.link), 'the text body must carry the join link');
  assert.ok(mail.text.includes(`${CLIENT_BASE_URL}/join#server=`), mail.text);

  // `emailed` is TRUE and the raw token is absent: the capability reached the
  // person, so the operator does not need a copy of it.
  assert.equal(created.body.emailed, true);
  assert.equal(created.body.token, undefined);
});

test('the token in the delivered letter is the one that creates the account', async () => {
  // THE ASSERTION THIS FILE EXISTS FOR. A route that built the right message
  // and sent the wrong token passes every unit test in the repo.
  await request({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org', displayName: 'Anna', role: 'admin', dailyAiLimit: 200 },
  });
  const link = received[0]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '';
  const inviteToken = tokenFromLink(link);
  assert.ok(inviteToken.startsWith('si_'), `expected an si_ token in the letter, got "${inviteToken}"`);

  const signedUp = await request<{ account: { email: string; role: string; dailyAiLimit: number } }>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(inviteToken),
  });
  assert.equal(signedUp.status, 201);
  // The standing the operator granted rode along with the address.
  assert.equal(signedUp.body.account.email, 'anna@example.org');
  assert.equal(signedUp.body.account.role, 'admin');
  assert.equal(signedUp.body.account.dailyAiLimit, 200);
});

test('a resend mails a NEW token and the old link stops working', async () => {
  const created = await request<{ invite: { id: number } }>({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org' },
  });
  const firstLink = received[0]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '';

  const resent = await request<{ emailed: boolean; link: string | null }>({
    method: 'POST',
    path: `/v1/admin/invites/${created.body.invite.id}/resend`,
    token: ADMIN_TOKEN,
  });
  assert.equal(resent.status, 202);
  assert.equal(resent.body.emailed, true);
  assert.equal(received.length, 2, 'a resend sends exactly one more letter');

  const secondLink = received[1]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '';
  assert.notEqual(tokenFromLink(secondLink), tokenFromLink(firstLink));

  // THE OLD LINK IS DEAD. An operator resending is saying the first letter did
  // not arrive, not "invite this person twice", so leaving the first token live
  // would be two capabilities where they believe there is one.
  const withOld = await request({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(tokenFromLink(firstLink)),
  });
  assert.equal(withOld.status, 403);
  const withNew = await request({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(tokenFromLink(secondLink)),
  });
  assert.equal(withNew.status, 201);
});

test('an admin reset-mail sends the reset letter and withholds the link', async () => {
  await request({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org' },
  });
  const inviteToken = tokenFromLink(
    received[0]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '',
  );
  const signedUp = await request<{ account: { id: number } }>({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(inviteToken),
  });
  received.length = 0;

  const sent = await request<{ emailed: boolean; link: string | null }>({
    method: 'POST',
    path: `/v1/admin/accounts/${signedUp.body.account.id}/reset-mail`,
    token: ADMIN_TOKEN,
  });
  assert.equal(sent.status, 202);
  assert.equal(sent.body.emailed, true);
  // THE LINK IS WITHHELD when a letter went. It opens the account's recovery
  // code, and an operator has no business holding that when the person has it.
  assert.equal(sent.body.link, null);

  assert.equal(received.length, 1);
  assert.equal(received[0]?.subject, 'Set a new openplate password');
  assert.ok(received[0]?.text.includes(`${CLIENT_BASE_URL}/reset#server=`));

  // And the token in that letter really does open the escrow.
  const resetToken =
    new URLSearchParams(
      (received[0]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '').split('#')[1] ?? '',
    ).get('token') ?? '';
  const opened = await request<{ email: string; recoveryCode: string }>({
    method: 'POST',
    path: '/v1/auth/reset/open',
    body: { resetToken },
  });
  assert.equal(opened.status, 200);
  assert.equal(opened.body.email, 'anna@example.org');
  assert.equal(opened.body.recoveryCode, sampleRecoveryCode().replaceAll('-', ''));
});

test('a mail API failure does not fail the request, and the invite is still usable', async () => {
  // The row is written before the send, and the link is in the response, so a
  // send failure is a degradation and not an outage. Turning it into a 500
  // would throw away a capability that was successfully minted.
  failNext = 500;

  const created = await request<{ emailed: boolean; link: string | null; token?: string }>({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org' },
  });
  assert.equal(created.status, 201, 'a failed send must not fail the mint');
  assert.equal(created.body.emailed, false, 'and it must be reported honestly');
  assert.ok(created.body.link, 'the operator gets the link to paste instead');

  // The invite the failed letter carried still works.
  const signedUp = await request({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(tokenFromLink(created.body.link)),
  });
  assert.equal(signedUp.status, 201);
});

test('a self-service reset request sends the letter too, and still answers 202', async () => {
  await request({
    method: 'POST',
    path: '/v1/admin/invites',
    token: ADMIN_TOKEN,
    body: { email: 'anna@example.org' },
  });
  const inviteToken = tokenFromLink(
    received[0]?.text.split('\n').find((line) => line.startsWith(CLIENT_BASE_URL)) ?? '',
  );
  await request({
    method: 'POST',
    path: '/v1/auth/signup',
    body: signupBody(inviteToken),
  });
  received.length = 0;

  const requested = await request({
    method: 'POST',
    path: '/v1/auth/reset/request',
    body: { email: 'anna@example.org' },
  });
  assert.equal(requested.status, 202);
  assert.equal(received.length, 1);
  assert.equal(received[0]?.subject, 'Set a new openplate password');

  // AND AN UNKNOWN ADDRESS IS THE SAME 202 WITH NO LETTER. A send failure or a
  // send at all must never be what tells a caller whether an account exists.
  failNext = 500;
  const unknown = await request({
    method: 'POST',
    path: '/v1/auth/reset/request',
    body: { email: 'nobody@example.org' },
  });
  assert.equal(unknown.status, 202);
  assert.equal(received.length, 1, 'an unknown address must send nothing');
});
