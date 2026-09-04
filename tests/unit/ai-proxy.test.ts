/**
 * The AI proxy: the money question, the privacy question, and the two headers
 * a client reads.
 *
 * IT RUNS AGAINST A REAL LISTENING UPSTREAM on an ephemeral loopback port, not
 * against a stubbed `fetch`. Every property here is about a real request: which
 * headers arrive at the provider, what a 4xx does to the reservation, whether a
 * body that echoes a photograph back reaches a log. A stubbed `fetch` would
 * assert that this module called a function, which is not the same claim.
 *
 * THE SPEND/RELEASE TABLE IS THE POINT OF THE FILE. Getting it wrong is not a
 * bug that shows up in testing; it is an organization whose allowance is eaten
 * by a misconfiguration, or a free infinite retry loop against a flaky
 * provider. Each row of `proxy.ts`'s table has a case below.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { createChatCompletionsHandler } from '../../src/ai/proxy.js';
import { scrubPayloads, describeError } from '../../src/ai/scrub.js';
import type { AiQuotaStore, ReserveResult } from '../../src/ai/quota-store.js';
import { createBearerAuthMiddleware } from '../../src/server/bearer-auth.js';
import { utcDayKey } from '../../src/lib/utc-day.js';
import type { JsonValue } from '../../src/lib/json.js';
import { hashToken } from '../../src/lib/tokens.js';
import type { LogFields, Logger } from '../../src/logger.js';
import { createAuthFixture, type AuthFixture } from './auth-context-fixture.js';

const servers: Server[] = [];

after(async () => {
  await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
});

/** A base64 run long enough to be a plate photograph as far as the scrubber is concerned. */
const PHOTOGRAPH = 'A'.repeat(120);

interface UpstreamRequest {
  authorization: string | undefined;
  contentType: string | undefined;
  cookie: string | undefined;
  apiKey: string | undefined;
  body: string;
}

interface UpstreamAnswer {
  status: number;
  body: string;
  contentType?: string;
}

interface FakeUpstream {
  baseUrl: string;
  received: UpstreamRequest[];
}

async function startFakeUpstream(
  respond: () => UpstreamAnswer = () => ({ status: 200, body: JSON.stringify({ choices: [] }) }),
): Promise<FakeUpstream> {
  const received: UpstreamRequest[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      received.push({
        authorization: req.headers.authorization,
        contentType: req.headers['content-type'],
        cookie: req.headers.cookie,
        apiKey: req.headers['x-api-key'] === undefined ? undefined : String(req.headers['x-api-key']),
        body: Buffer.concat(chunks).toString('utf8'),
      });
      const answer = respond();
      res.writeHead(answer.status, { 'content-type': answer.contentType ?? 'application/json' });
      res.end(answer.body);
    });
  });
  servers.push(server);
  server.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  // SAFETY: `listen(0)` binds a TCP port, and Node returns the string form of
  // an address only for a Unix domain socket, which this never opens.
  const { port } = server.address() as AddressInfo;
  return { baseUrl: `http://127.0.0.1:${port}/v1`, received };
}

interface CapturedLine {
  message: string;
  fields: LogFields | undefined;
}

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

/**
 * An in-memory quota store that RECORDS every reserve and release, because the
 * spend/release table is a claim about calls rather than about a final number:
 * a reserve followed by a release leaves the same count as no request at all,
 * so counting alone cannot tell "released" from "never reserved".
 */
interface RecordingQuota extends AiQuotaStore {
  reserves: number;
  releases: number;
  count: number;
}

function createRecordingQuota(options: { failAt?: number } = {}): RecordingQuota {
  const store: RecordingQuota = {
    reserves: 0,
    releases: 0,
    count: 0,
    async reserve(input: { accountId: number; day: string; limit: number }): Promise<ReserveResult> {
      store.reserves += 1;
      // The real store's rule, reproduced: the limit is the predicate, and a
      // refusal reports the limit as spent.
      if (store.count >= (options.failAt ?? input.limit)) {
        return { ok: false, used: input.limit, limit: input.limit };
      }
      store.count += 1;
      return { ok: true, used: store.count, limit: input.limit };
    },
    async release(): Promise<void> {
      store.releases += 1;
      // Floored at zero, as the real store's `WHERE count > 0` is.
      store.count = Math.max(0, store.count - 1);
    },
    async countRequestsOn(): Promise<number> {
      return store.count;
    },
  };
  return store;
}

interface Harness {
  baseUrl: string;
  fixture: AuthFixture;
  quota: RecordingQuota;
  logger: CapturingLogger;
  accountId: number;
  accessToken: string;
  close(): Promise<void>;
}

/** Boots the REAL handler behind the REAL bearer middleware, with one seeded account. */
async function startProxy(options: {
  upstreamBaseUrl: string;
  dailyAiLimit?: number;
  quota?: RecordingQuota;
  timeoutMs?: number;
}): Promise<Harness> {
  const fixture = createAuthFixture();
  const account = await fixture.store.seedAccount({
    email: 'anna@example.org',
    dailyAiLimit: options.dailyAiLimit ?? 200,
  });
  await fixture.store.insertTokens([
    {
      accountId: account.id,
      kind: 'access',
      tokenHash: hashToken('an-access-token'),
      familyId: 'family-1',
      expiresAt: new Date(fixture.now().getTime() + 60_000),
    },
  ]);

  const quota = options.quota ?? createRecordingQuota();
  const logger = createCapturingLogger();
  const app = express();
  app.post(
    '/v1/chat/completions',
    express.json({ limit: '8mb' }),
    createBearerAuthMiddleware(fixture.ctx),
    createChatCompletionsHandler({
      upstream: {
        baseUrl: options.upstreamBaseUrl,
        apiKey: 'the-operator-provider-key',
        timeoutMs: options.timeoutMs ?? 5000,
      },
      quota,
      accounts: fixture.store,
      logger: logger.logger,
      now: fixture.now,
    }),
  );

  const server = app.listen(0);
  servers.push(server);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  // SAFETY: as above — an ephemeral TCP port, never a Unix domain socket.
  const { port } = server.address() as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    fixture,
    quota,
    logger,
    accountId: account.id,
    accessToken: 'an-access-token',
    async close() {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function postCompletion(harness: Harness, body: JsonValue = { model: 'm', messages: [] }): Promise<Response> {
  return fetch(`${harness.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: {
      authorization: `Bearer ${harness.accessToken}`,
      'content-type': 'application/json',
      // Two headers a copy-then-overwrite would forward. Neither may reach the
      // provider — see hard rule 3 in `proxy.ts`.
      cookie: 'session=not-yours',
      'x-api-key': 'a-caller-supplied-key',
    },
    body: JSON.stringify(body),
  });
}

// ── The headers, rebuilt rather than copied ────────────────────────────────

test('the upstream sees the operator key and none of the caller headers', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  const response = await postCompletion(harness);
  assert.equal(response.status, 200);

  assert.equal(upstream.received.length, 1);
  const forwarded = upstream.received[0];
  assert.ok(forwarded);
  // THE OPERATOR'S KEY REPLACED THE CALLER'S TOKEN, rather than joining it.
  assert.equal(forwarded.authorization, 'Bearer the-operator-provider-key');
  assert.ok(!forwarded.authorization.includes('an-access-token'), 'the access token must never leave this process');
  // BUILT, NOT COPIED: a copy-then-overwrite forwards cookies, `x-api-key` and
  // whatever the next provider decides to read.
  assert.equal(forwarded.cookie, undefined);
  assert.equal(forwarded.apiKey, undefined);
  assert.equal(forwarded.contentType, 'application/json');
  // The body passed through untouched: this is a proxy, so the only validation
  // it applies is "is it a JSON object".
  assert.deepEqual(JSON.parse(forwarded.body), { model: 'm', messages: [] });

  await harness.close();
});

test('a body that is not a JSON object is refused without an upstream call', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  const response = await fetch(`${harness.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: `Bearer ${harness.accessToken}`, 'content-type': 'application/json' },
    body: JSON.stringify(['not', 'an', 'object']),
  });
  assert.equal(response.status, 400);
  assert.equal(upstream.received.length, 0, 'a malformed body must not cost an upstream call');
  // And no reservation: the refusal is before the spend.
  assert.equal(harness.quota.reserves, 0);

  await harness.close();
});

// ── The quota ──────────────────────────────────────────────────────────────

test('a limit of 0 is 403 ai-not-allowed, before the upstream and before the reserve', async () => {
  // NOT A 429: there is nothing to wait for, so a retry-after would be a lie.
  // And it returns before `reserve`, whose insert branch is unguarded — a limit
  // of zero reaching it would write a row with `count = 1`.
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl, dailyAiLimit: 0 });

  const response = await postCompletion(harness);
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'ai-not-allowed' });
  assert.equal(upstream.received.length, 0);
  assert.equal(harness.quota.reserves, 0, 'a zero limit must never reach the quota store');

  await harness.close();
});

test('a 2xx SPENDS the reservation and reports both quota headers', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl, dailyAiLimit: 3 });

  const response = await postCompletion(harness);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('x-quota-used'), '1');
  assert.equal(response.headers.get('x-quota-limit'), '3');
  assert.equal(harness.quota.releases, 0, 'a served request is not refunded');
  assert.equal(harness.quota.count, 1);

  await harness.close();
});

test('an upstream 4xx RELEASES the reservation: the provider refused, so nobody billed it', async () => {
  // Charging for the operator's own misconfiguration is the worst outcome: a
  // broken proxy would silently eat an organization's whole allowance.
  const upstream = await startFakeUpstream(() => ({ status: 400, body: JSON.stringify({ error: 'unknown model' }) }));
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl, dailyAiLimit: 3 });

  const response = await postCompletion(harness);
  assert.equal(response.status, 400, "the upstream's status passes through");
  assert.equal(harness.quota.reserves, 1);
  assert.equal(harness.quota.releases, 1, 'a 4xx must be refunded');
  assert.equal(harness.quota.count, 0);
  // The headers ride on this response too: a client that only saw them on
  // success could not tell a released reservation from a spent one.
  assert.equal(response.headers.get('x-quota-used'), '1');
  assert.equal(response.headers.get('x-quota-limit'), '3');

  await harness.close();
});

test('an upstream 5xx KEEPS the reservation: the provider ran the request', async () => {
  // Releasing here hands out a free infinite retry loop against a flaky
  // provider, which is exactly when a client retries hardest.
  const upstream = await startFakeUpstream(() => ({ status: 503, body: JSON.stringify({ error: 'overloaded' }) }));
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl, dailyAiLimit: 3 });

  const response = await postCompletion(harness);
  assert.equal(response.status, 503);
  assert.equal(harness.quota.releases, 0, 'a 5xx must NOT be refunded');
  assert.equal(harness.quota.count, 1);

  await harness.close();
});

test('a connect failure RELEASES: the request never left this host', async () => {
  const harness = await startProxy({
    // A port nothing is listening on. `fetch` reports this as an opaque
    // TypeError, which is why `isTimeoutError` has to read the cause chain.
    upstreamBaseUrl: 'http://127.0.0.1:1/v1',
    dailyAiLimit: 3,
  });

  const response = await postCompletion(harness);
  assert.equal(response.status, 502);
  assert.equal(harness.quota.reserves, 1);
  assert.equal(harness.quota.releases, 1, 'nothing was served, so the unit goes back');
  assert.equal(harness.quota.count, 0);

  await harness.close();
});

test('a spent allowance is 429 with a Retry-After to the next UTC midnight', async () => {
  const upstream = await startFakeUpstream();
  const quota = createRecordingQuota();
  quota.count = 2;
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl, dailyAiLimit: 2, quota });

  const response = await postCompletion(harness);
  assert.equal(response.status, 429);
  assert.equal(upstream.received.length, 0, 'a refused reservation must not reach the provider');

  // The fixture clock is 2026-08-04T10:00:00Z, so the reset is 14 hours out.
  const retryAfter = Number(response.headers.get('retry-after'));
  assert.equal(retryAfter, 14 * 60 * 60);
  assert.equal(response.headers.get('x-quota-used'), '2');
  assert.equal(response.headers.get('x-quota-limit'), '2');

  await harness.close();
});

test('the quota is keyed on the UTC day the request arrived in', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });
  const seen: string[] = [];
  // Wrap the store so the day it was asked about is observable.
  const inner = harness.quota.reserve.bind(harness.quota);
  harness.quota.reserve = async (input): Promise<ReserveResult> => {
    seen.push(input.day);
    return inner(input);
  };

  await postCompletion(harness);
  assert.deepEqual(seen, [utcDayKey(harness.fixture.now())]);
  assert.equal(seen[0], '2026-08-04');

  await harness.close();
});

// ── The privacy rules ──────────────────────────────────────────────────────

test('a provider that echoes the photograph back has it scrubbed from the response AND the log', async () => {
  // The single most likely way a photograph escapes this process, and the
  // string a debugging instinct most wants to log verbatim.
  const echoed = JSON.stringify({ error: 'rejected', input: `data:image/jpeg;base64,${PHOTOGRAPH}` });
  const upstream = await startFakeUpstream(() => ({ status: 422, body: echoed }));
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  const response = await postCompletion(harness, {
    model: 'm',
    messages: [{ role: 'user', content: [{ type: 'image_url', image_url: { url: `data:image/jpeg;base64,${PHOTOGRAPH}` } }] }],
  });
  assert.equal(response.status, 422);

  const body = await response.text();
  assert.ok(!body.includes(PHOTOGRAPH), 'the response relayed the photograph back to the caller');
  assert.ok(body.includes('[redacted]'), 'and it must be visibly redacted rather than silently dropped');

  const logged = JSON.stringify(harness.logger.lines);
  assert.ok(!logged.includes(PHOTOGRAPH), 'the log carries the photograph');
  // The positive half, so a handler that logged nothing would not pass by
  // silence: the failure IS recorded, with a status and byte counts.
  assert.ok(logged.includes('Upstream provider returned an error'));

  await harness.close();
});

test('nothing the proxy logs on the happy path carries a body or a key', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  await postCompletion(harness, { model: 'm', messages: [{ role: 'user', content: PHOTOGRAPH }] });

  const logged = JSON.stringify(harness.logger.lines);
  assert.ok(logged.includes('Proxied a completion'), 'a proxied call must be recorded');
  for (const secret of [PHOTOGRAPH, 'the-operator-provider-key', 'an-access-token', 'anna@example.org']) {
    assert.ok(!logged.includes(secret), `the log carries "${secret}"`);
  }
  // What it DOES carry: counts, not bytes.
  const proxied = harness.logger.lines.find((line) => line.message === 'Proxied a completion');
  assert.equal(proxied?.fields?.accountId, harness.accountId);
  assert.equal(proxied?.fields?.quotaUsed, 1);

  await harness.close();
});

test('the scrubber redacts data URIs and long base64 runs, and is idempotent', () => {
  const once = scrubPayloads(`before data:image/png;base64,${PHOTOGRAPH} after`);
  assert.equal(once, 'before [redacted] after');
  assert.equal(scrubPayloads(once), once, 'scrubbing a scrubbed string must not change it');

  // A bare run, without the data-URI prefix. It swallows the `id=` label with
  // it, because `i`, `d` and `=` are all in the base64 alphabet and the run is
  // therefore continuous. That over-reach is the SAFE direction and is left
  // alone: a redaction that eats a label is a log line somebody has to read
  // twice, and a redaction that stops one character short is a photograph.
  assert.equal(scrubPayloads(`id=${PHOTOGRAPH}`), '[redacted]');
  // A separator outside the alphabet ends the run, so a field beside a payload
  // survives.
  assert.equal(scrubPayloads(`id: ${PHOTOGRAPH}`), 'id: [redacted]');
  // ...and short identifiers survive whole, or the scrubber would eat the
  // fields somebody actually wanted to read.
  assert.equal(scrubPayloads('accountId=42 family=abc123'), 'accountId=42 family=abc123');
});

test('describeError never returns a stack, a cause chain or an unscrubbed message', () => {
  const wrapped = new Error(`upstream said ${PHOTOGRAPH}`, { cause: new Error(`inner ${PHOTOGRAPH}`) });
  const described = describeError(wrapped);
  assert.ok(!described.includes(PHOTOGRAPH));
  assert.ok(!described.includes('at '), 'a stack can quote source lines');
  assert.equal(describeError('a thrown string'), 'a thrown string');
  assert.equal(describeError({ weird: true }), 'unknown error');
});

// ── Streaming ──────────────────────────────────────────────────────────────

test('a streaming response is piped through unchanged, with the no-transform header', async () => {
  const chunks = 'data: one\n\ndata: two\n\ndata: [DONE]\n\n';
  const upstream = await startFakeUpstream(() => ({
    status: 200,
    body: chunks,
    contentType: 'text/event-stream',
  }));
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  const response = await postCompletion(harness, { model: 'm', messages: [], stream: true });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get('content-type'), 'text/event-stream');
  // Server-sent events die behind a buffering proxy, so this is said explicitly
  // rather than left to whatever reverse proxy the deployment has.
  assert.equal(response.headers.get('cache-control'), 'no-cache, no-transform');
  assert.equal(await response.text(), chunks, 'the stream must pass through byte for byte');

  await harness.close();
});

// ── The identity gate ──────────────────────────────────────────────────────

test('an unauthenticated caller is 401 and never reaches the quota or the provider', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });

  const response = await fetch(`${harness.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'm', messages: [] }),
  });
  assert.equal(response.status, 401);
  assert.equal(harness.quota.reserves, 0);
  assert.equal(upstream.received.length, 0);

  await harness.close();
});

test('a suspended account is 403 account-suspended, from the bearer gate', async () => {
  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });
  await harness.fixture.store.suspendAccount({ accountId: harness.accountId, suspendedAt: harness.fixture.now() });
  // Suspending revoked the session, so a live token on a suspended account
  // needs minting: that combination is what the gate must catch.
  await harness.fixture.store.insertTokens([
    {
      accountId: harness.accountId,
      kind: 'access',
      tokenHash: hashToken('a-live-token'),
      familyId: 'family-2',
      expiresAt: new Date(harness.fixture.now().getTime() + 60_000),
    },
  ]);

  const response = await fetch(`${harness.baseUrl}/v1/chat/completions`, {
    method: 'POST',
    headers: { authorization: 'Bearer a-live-token', 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'm', messages: [] }),
  });
  assert.equal(response.status, 403);
  assert.deepEqual(await response.json(), { error: 'account-suspended' });
  assert.equal(harness.quota.reserves, 0);
  assert.equal(upstream.received.length, 0);

  await harness.close();
});

test('a successful call stamps last_seen_at, and a failed one does not', async () => {
  const failing = await startFakeUpstream(() => ({ status: 503, body: '{}' }));
  const failed = await startProxy({ upstreamBaseUrl: failing.baseUrl });
  await postCompletion(failed);
  assert.equal(failed.fixture.store.lastSeenFor(failed.accountId), null, 'a failed call is not "seen"');
  await failed.close();

  const upstream = await startFakeUpstream();
  const harness = await startProxy({ upstreamBaseUrl: upstream.baseUrl });
  await postCompletion(harness);
  assert.deepEqual(harness.fixture.store.lastSeenFor(harness.accountId), harness.fixture.now());
  await harness.close();
});
