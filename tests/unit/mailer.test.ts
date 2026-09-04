/**
 * The HTTP mail adapter: what it posts, and what it refuses to know.
 *
 * IT RUNS AGAINST A REAL LISTENING SERVER on an ephemeral loopback port, not
 * against a stubbed `fetch`. The properties worth testing here are about a
 * real request: the payload shape a Resend-compatible API receives, the
 * `Authorization` header, and the timeout. A stubbed `fetch` would assert that
 * this module called a function, which is not the same claim.
 *
 * THE PRIVACY ASSERTIONS ARE THE POINT OF THE FILE. Both Resend and pigeon
 * echo the request back inside an error body, which means the recipient
 * address, the subject and any html the provider chooses to include — and the
 * html carries a live token. The adapter cancels the body without reading it,
 * so there is no string in scope for a later `${...}` to put into a log. These
 * tests make a failing server return exactly that echo and assert that none of
 * it reaches the thrown error or the logger.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHttpMailer, createMailer, createNoopMailer } from '../../src/mail/mailer.js';
import type { CreateHttpMailerOptions, Mailer } from '../../src/mail/mailer.js';
import type { LogFields, Logger } from '../../src/logger.js';

const servers: Server[] = [];

after(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

interface ReceivedRequest {
  authorization: string | undefined;
  contentType: string | undefined;
  body: string;
}

/** The Resend-shaped payload this adapter posts. Named so a parsed body has a contract. */
interface MailPayload {
  from: string;
  to: string[];
  subject: string;
  text: string;
  html: string;
}

interface FakeMailApi {
  url: string;
  received: ReceivedRequest[];
}

/**
 * A mail API that records what it was sent and answers however the test asks.
 *
 * `respond` returns the status and the body: the failure cases below make it
 * echo the request back, which is what both real providers do.
 */
async function startFakeMailApi(
  respond: (received: ReceivedRequest) => { status: number; body: string } = () => ({
    status: 200,
    body: JSON.stringify({ id: 'msg_1' }),
  }),
): Promise<FakeMailApi> {
  const received: ReceivedRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      const request: ReceivedRequest = {
        authorization: req.headers.authorization,
        contentType: req.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8'),
      };
      received.push(request);
      const answer = respond(request);
      res.writeHead(answer.status, { 'content-type': 'application/json' });
      res.end(answer.body);
    });
  });
  servers.push(server);
  server.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (address === null) throw new Error('expected a listening fake mail API');
  // SAFETY: `listen(0)` binds a TCP port; Node returns the string form only
  // for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;
  return { url: `http://127.0.0.1:${port}/v1/emails`, received };
}

interface CapturedLine {
  message: string;
  fields: LogFields | undefined;
}

/** Every line the adapter emitted, so the absence assertions below have something real to search. */
interface CapturingLogger {
  logger: Logger;
  lines: CapturedLine[];
}

function createCapturingLogger(): CapturingLogger {
  const lines: CapturedLine[] = [];
  const record = (message: string, fields?: LogFields): void => {
    lines.push({ message, fields });
  };
  return { lines, logger: { debug: record, info: record, warn: record, error: record } };
}

const LINKS = { clientBaseUrl: 'https://openplate.de', serverPublicUrl: 'https://sync.openplate.de' };

function mailerFor(url: string, logger: Logger, timeoutMs?: number): Mailer {
  const options: CreateHttpMailerOptions = {
    mail: { url, apiKey: 'a-mail-api-key-nobody-should-see', from: 'openplate <openplate@mail.openplate.de>' },
    links: LINKS,
    language: 'en',
    logger,
  };
  // Set in a statement rather than spread conditionally, so the omission is a
  // line a reader sees instead of a `{}` they have to decode.
  if (timeoutMs !== undefined) options.timeoutMs = timeoutMs;
  return createHttpMailer(options);
}

// ── What it posts ──────────────────────────────────────────────────────────

test('an invite send posts the Resend-shaped payload, with the recipient as an array', async () => {
  const api = await startFakeMailApi();
  const captured = createCapturingLogger();

  await mailerFor(api.url, captured.logger).sendInvite({
    email: 'anna@example.org',
    displayName: 'Anna',
    inviteToken: 'si_a-token',
    expiresAt: '2026-09-11T10:00:00.000Z',
  });

  assert.equal(api.received.length, 1);
  const request = api.received[0];
  assert.ok(request);
  assert.equal(request.authorization, 'Bearer a-mail-api-key-nobody-should-see');
  assert.equal(request.contentType, 'application/json');

  // SAFETY: this test's own fake API received the body this adapter posted, so
  // it is the shape declared above by construction.
  const payload = JSON.parse(request.body) as MailPayload;
  assert.equal(payload.from, 'openplate <openplate@mail.openplate.de>');
  // AN ARRAY EVEN FOR ONE RECIPIENT: Resend accepts it and pigeon requires it,
  // which is the whole compatibility story between the two.
  assert.deepEqual(payload.to, ['anna@example.org']);
  assert.equal(payload.subject, 'Your openplate invitation');
  assert.ok(payload.text.includes('si_a-token'), 'the text part must carry the link');
  assert.ok(payload.html.startsWith('<!doctype html>'));
});

test('a reset send posts the reset letter, in the configured language', async () => {
  const api = await startFakeMailApi();
  const captured = createCapturingLogger();

  const german = createHttpMailer({
    mail: { url: api.url, apiKey: 'k', from: 'f' },
    links: LINKS,
    language: 'de',
    logger: captured.logger,
  });
  await german.sendReset({ email: 'anna@example.org', resetToken: 'sr_a-token', expiresAt: 'x' });

  // SAFETY: as above — our own adapter posted this body.
  const payload = JSON.parse(api.received[0]?.body ?? '{}') as MailPayload;
  assert.equal(payload.subject, 'Neues Passwort für openplate festlegen');
  assert.ok(payload.text.includes('/reset#server='), 'the reset link, not the join link');
});

// ── What it refuses to know ────────────────────────────────────────────────

test('a failing send throws the status code and NOTHING the provider echoed back', async () => {
  // Both real providers echo the request inside an error body. The html in
  // that echo carries a live token, so reading it would put a credential in
  // scope for a later error message or log line to interpolate.
  const echoed = JSON.stringify({ error: 'rejected', echo: { to: ['anna@example.org'], html: 'si_a-secret-token' } });
  const api = await startFakeMailApi(() => ({ status: 422, body: echoed }));
  const captured = createCapturingLogger();

  await assert.rejects(
    () =>
      mailerFor(api.url, captured.logger).sendInvite({
        email: 'anna@example.org',
        displayName: null,
        inviteToken: 'si_a-secret-token',
        expiresAt: '2026-09-11T10:00:00.000Z',
      }),
    (error: Error) => {
      // The status, and only the status.
      assert.equal(error.message, 'mail API responded 422');
      assert.ok(!error.message.includes('anna@example.org'));
      assert.ok(!error.message.includes('si_a-secret-token'));
      assert.ok(!error.message.includes('rejected'));
      return true;
    },
  );
});

test('nothing the adapter logs carries a recipient, a subject, a token or a key', async () => {
  const api = await startFakeMailApi();
  const captured = createCapturingLogger();

  await mailerFor(api.url, captured.logger).sendInvite({
    email: 'anna@example.org',
    displayName: 'Anna',
    inviteToken: 'si_a-secret-token',
    expiresAt: '2026-09-11T10:00:00.000Z',
  });

  const serialized = JSON.stringify(captured.lines);
  // The positive half first, so an adapter that logged nothing at all would
  // not satisfy this file by silence.
  assert.ok(serialized.includes('Invitation mailed'), 'a send must be recorded');
  // ...and the absence half.
  for (const secret of [
    'anna@example.org',
    'si_a-secret-token',
    'a-mail-api-key-nobody-should-see',
    'Your openplate invitation',
    api.url,
  ]) {
    assert.ok(!serialized.includes(secret), `the log carries "${secret}"`);
  }
});

test('the send is bounded by a timeout rather than hanging forever', async () => {
  // A mail API that accepts the connection and never answers. Without the
  // bound this send would hold the admin request open until the client gave
  // up, and an operator would see a hung terminal rather than a link.
  const server = createServer(() => {
    // Deliberately never responds.
  });
  servers.push(server);
  server.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  // SAFETY: `listen(0)` binds a TCP port, and Node returns the string form of
  // an address only for a Unix domain socket, which this never opens.
  const { port } = server.address() as AddressInfo;
  const captured = createCapturingLogger();

  await assert.rejects(() =>
    mailerFor(`http://127.0.0.1:${port}/v1/emails`, captured.logger, 50).sendReset({
      email: 'anna@example.org',
      resetToken: 'sr_x',
      expiresAt: 'x',
    }),
  );
});

// ── Choosing an adapter ────────────────────────────────────────────────────

test('createMailer answers the no-op when mail or the link bases are absent', async () => {
  const captured = createCapturingLogger();
  const send = { email: 'anna@example.org', resetToken: 'sr_x', expiresAt: 'x' };

  // No mail block: the copy-link deployment most self-hosters run.
  await createMailer({ mail: null, links: LINKS, language: 'en', logger: captured.logger }).sendReset(send);
  // Mail but no links, which `config.ts` refuses at boot — the narrowing here
  // is belt and braces rather than a second policy.
  await createMailer({
    mail: { url: 'http://unreachable.invalid', apiKey: 'k', from: 'f' },
    links: null,
    language: 'en',
    logger: captured.logger,
  }).sendReset(send);

  // Neither attempted a request, so neither threw against an unreachable host.
  assert.deepEqual(captured.lines, []);
});

test('the no-op mailer accepts both letters and sends neither', async () => {
  const mailer = createNoopMailer();
  await mailer.sendInvite({ email: 'a@b.test', displayName: null, inviteToken: 'si_x', expiresAt: 'x' });
  await mailer.sendReset({ email: 'a@b.test', resetToken: 'sr_x', expiresAt: 'x' });
  // Nothing to assert but the absence of a throw: an instance without mail must
  // not fail the request that would have sent one.
  assert.ok(true);
});
