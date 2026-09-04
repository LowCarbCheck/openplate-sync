/**
 * The proxy route's BODY LIMIT, and the shape of the refusal when it is hit.
 *
 * WHY THIS FILE EXISTS AS ITS OWN SUITE. `ai-proxy.test.ts` mounts the handler
 * by hand, with its own `express.json({ limit: '8mb' })`, because it is about
 * what the handler decides. That is exactly why it could not catch the defect
 * this file was written for: the shipped route derived its limit from
 * `MAX_BLOB_BYTES`, giving 2.73 MB, and every real plate photograph came back
 * 413 — with 17 green unit tests, a green integration suite, and a green
 * build. The limit is a property of the WIRING, so the test has to use
 * `registerAiRoute` itself.
 *
 * A BLOB AND A PHOTOGRAPH ARE NOT THE SAME BOUND. `MAX_BLOB_BYTES` caps a
 * diary: compressed, encrypted, stored. A completion body carries an image
 * this service only forwards, and a modern phone camera produces 3 to 6 MB of
 * JPEG before base64 inflates it by a third. Deriving one from the other was
 * arithmetic applied to the wrong noun.
 *
 * THE REFUSAL IS OPENAI-SHAPED, not sync-shaped. Everywhere else this service
 * answers `{"error": "<sentence>"}`. The thing calling this path is an
 * OpenAI-compatible client that reads `error.message` off an object, so the
 * sync shape reads as `undefined` and shows the user nothing — a 413 on every
 * photograph then looks like the camera silently doing nothing.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { registerAiRoute, CHAT_COMPLETIONS_PATH } from '../../src/ai/register-ai-route.js';
import { createErrorMiddleware } from '../../src/server/error-middleware.js';
import type { AiQuotaStore, ReserveResult } from '../../src/ai/quota-store.js';
import { createBearerAuthMiddleware } from '../../src/server/bearer-auth.js';
import { createSilentLogger } from '../../src/logger.js';
import { hashToken } from '../../src/lib/tokens.js';
import { MAX_BLOB_BYTES } from '../../src/protocol.js';
import { createAuthFixture } from './auth-context-fixture.js';

/** The production default, transcribed rather than imported: a test that reads the value it checks proves nothing. */
const DEFAULT_AI_MAX_REQUEST_BYTES = 8_000_000;

/** What the shipped route used to compute. Kept so the regression stays named rather than merely fixed. */
const THE_OLD_BLOB_DERIVED_LIMIT = Math.ceil((MAX_BLOB_BYTES * 4) / 3) + 64 * 1024;

const servers: Server[] = [];
after(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

/** A quota that always allows: this file is about the parser in front of the handler, not about spending. */
function createAllowingQuota(): AiQuotaStore {
  let used = 0;
  return {
    async reserve(): Promise<ReserveResult> {
      used += 1;
      return { ok: true, used, limit: 1000 };
    },
    async release(): Promise<void> {
      used -= 1;
    },
    async countRequestsOn(): Promise<number> {
      return used;
    },
  };
}

interface RouteHarness {
  baseUrl: string;
  accessToken: string;
  /** Byte length of the last body the fake upstream received, or null if it was never called. */
  upstreamSawBytes: () => number | null;
}

/** Boots the REAL `registerAiRoute` in front of a real listening upstream. */
async function startRoute(options: { maxRequestBytes?: number } = {}): Promise<RouteHarness> {
  let received: number | null = null;
  const upstream = createServer((request, response) => {
    let bytes = 0;
    request.on('data', (piece: Buffer) => {
      bytes += piece.byteLength;
    });
    request.on('end', () => {
      received = bytes;
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ choices: [{ message: { content: 'a bowl of rice' } }] }));
    });
  });
  upstream.listen(0);
  servers.push(upstream);
  await new Promise<void>((resolve) => upstream.once('listening', resolve));
  // SAFETY: `listen(0)` binds a TCP port; Node returns a string address only
  // for a Unix domain socket, which this never opens.
  const upstreamPort = (upstream.address() as AddressInfo).port;

  const fixture = createAuthFixture();
  const account = await fixture.store.seedAccount({ email: 'anna@example.org', dailyAiLimit: 200 });
  await fixture.store.insertTokens([
    {
      accountId: account.id,
      kind: 'access',
      tokenHash: hashToken('an-access-token'),
      familyId: 'family-1',
      expiresAt: new Date(fixture.now().getTime() + 60_000),
    },
  ]);

  const app = express();
  registerAiRoute(app, {
    upstream: {
      baseUrl: `http://127.0.0.1:${upstreamPort}`,
      apiKey: 'the-operator-provider-key',
      timeoutMs: 10_000,
    },
    quota: createAllowingQuota(),
    accounts: fixture.store,
    logger: createSilentLogger(),
    now: fixture.now,
    requireAuth: createBearerAuthMiddleware(fixture.ctx),
    perMinute: 10_000,
    maxRequestBytes: options.maxRequestBytes ?? DEFAULT_AI_MAX_REQUEST_BYTES,
  });
  // The terminal handler the real app mounts last. Present so a test can see
  // that the route's own handler answered rather than falling through to it.
  app.use(createErrorMiddleware(createSilentLogger()));

  const server = app.listen(0);
  servers.push(server);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  // SAFETY: as above — `listen(0)` binds a TCP port, and Node returns a string
  // address only for a Unix domain socket, which this never opens.
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    accessToken: 'an-access-token',
    upstreamSawBytes: () => received,
  };
}

/**
 * A completion request carrying a base64 image of roughly `imageBytes`.
 *
 * Built from one repeated character rather than random data: the assertion is
 * about SIZE, and a megabytes-long random string costs real time to make.
 */
function photoRequest(imageBytes: number): string {
  return JSON.stringify({
    model: 'a-vision-model',
    messages: [
      {
        role: 'user',
        content: [
          { type: 'text', text: 'what is on this plate?' },
          { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${'A'.repeat(imageBytes)}` } },
        ],
      },
    ],
  });
}

async function post(harness: RouteHarness, body: string): Promise<Response> {
  return fetch(`${harness.baseUrl}${CHAT_COMPLETIONS_PATH}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${harness.accessToken}` },
    body,
  });
}

test('a 6 MB photograph is relayed, which the shipped blob-derived limit refused', async () => {
  // THE REGRESSION, stated as arithmetic: the old limit was smaller than this
  // body, so if someone re-derives the limit from the blob cap this line is
  // what fails.
  const body = photoRequest(6 * 1024 * 1024);
  assert.ok(
    body.length > THE_OLD_BLOB_DERIVED_LIMIT,
    `the fixture must exceed the old ${THE_OLD_BLOB_DERIVED_LIMIT}-byte limit to be a regression test`,
  );
  assert.ok(body.length < DEFAULT_AI_MAX_REQUEST_BYTES, 'and must sit under the new one');

  const harness = await startRoute();
  const response = await post(harness, body);

  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { choices: [{ message: { content: 'a bowl of rice' } }] });
  // It REACHED the provider. A 200 alone would not say so: a handler that
  // answered from a cache would look identical.
  assert.ok((harness.upstreamSawBytes() ?? 0) > THE_OLD_BLOB_DERIVED_LIMIT);
});

test('a body over the limit is a 413 in the OPENAI shape, and never reaches the provider', async () => {
  // A small configured limit rather than a 9 MB fixture: this also proves the
  // route reads `maxRequestBytes` instead of a constant, which is the half a
  // large-body test cannot show.
  const harness = await startRoute({ maxRequestBytes: 1_000_000 });
  const response = await post(harness, photoRequest(2 * 1024 * 1024));

  assert.equal(response.status, 413);
  // SAFETY: this route answers `application/json` on every path, and a body
  // that did not parse would throw here rather than reach the assertions.
  const body = (await response.json()) as { error?: { message?: string; type?: string; code?: string } };

  // AN OBJECT WITH A MESSAGE, not a string. This is the exact read an
  // OpenAI-compatible client performs; handed this service's ordinary
  // `{"error": "<sentence>"}` it resolves to `undefined` and the user is shown
  // nothing at all, which is how a 413 on every photograph looks like the
  // camera silently doing nothing.
  assert.ok((body.error?.message ?? '').length > 0, 'error.message is what the client renders');
  assert.equal(body.error?.type, 'invalid_request_error');
  assert.equal(body.error?.code, 'request_too_large');
  // The message NAMES the knob, because the person who can fix this is the
  // operator reading a screenshot, not the person who took the photograph.
  assert.match(body.error?.message ?? '', /1000000 bytes/);
  assert.match(body.error?.message ?? '', /AI_MAX_REQUEST_BYTES/);

  // Nothing left the host: the parser refused before auth, the limiter, the
  // reservation and the forward.
  assert.equal(harness.upstreamSawBytes(), null);
});

test('the message quotes the LIMIT and never the body', async () => {
  const harness = await startRoute({ maxRequestBytes: 1_000 });
  const secret = 'SGVsbG8tdGhpcy1pcy1hLXBob3RvZ3JhcGg';
  const response = await post(harness, JSON.stringify({ model: 'm', note: secret, pad: 'A'.repeat(4_000) }));

  assert.equal(response.status, 413);
  const text = await response.text();
  // The whole point of not quoting input on this route: the input is a
  // photograph, and an error document is a place people paste into a chat.
  assert.ok(!text.includes(secret), 'a 413 must not echo any part of the body');
});

test('malformed JSON is a 400 in the same shape, and also quotes nothing', async () => {
  const harness = await startRoute();
  const response = await post(harness, '{"model": "m", "messages": [');

  assert.equal(response.status, 400);
  // SAFETY: as above — this route answers JSON on every path.
  const body = (await response.json()) as { error?: { message?: string; code?: string } };
  assert.equal(body.error?.code, 'invalid_json');
  assert.ok(!(body.error?.message ?? '').includes('"model"'), 'the malformed input is not quoted back');
  assert.equal(harness.upstreamSawBytes(), null);
});

test('the default limit is 8 MB, the figure the retired gateway used', async () => {
  // Transcribed against the gateway's own `MAX_REQUEST_BYTES`. The number
  // matters more than it looks: it is the difference between the camera
  // working and the camera appearing to do nothing.
  assert.equal(DEFAULT_AI_MAX_REQUEST_BYTES, 8_000_000);

  // WHAT THAT BUYS, in the unit an operator can check on a phone: base64
  // inflates by 4/3, so 8 MB of body is a raw JPEG of about 5.7 MiB. That
  // covers a modern phone camera at default quality and does NOT cover a
  // 12-megapixel original at maximum quality — which is the right place for
  // the line, because the client downscales before it sends.
  const largestJpegMib = (DEFAULT_AI_MAX_REQUEST_BYTES * 3) / 4 / 1024 / 1024;
  assert.ok(largestJpegMib > 5.5 && largestJpegMib < 6, `a limit of 8 MB carries a ${largestJpegMib} MiB photograph`);
  // And it is comfortably above the old blob-derived figure, which is the
  // whole reason the variable exists.
  assert.ok(DEFAULT_AI_MAX_REQUEST_BYTES > THE_OLD_BLOB_DERIVED_LIMIT * 2);
});
