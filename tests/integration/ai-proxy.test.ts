/**
 * The AI proxy end to end: a real signed-in account, a real HTTP request to a
 * real listening upstream, and a real `ai_usage_days` row counting it.
 *
 * WHY THIS SUITE EXISTS RATHER THAN MORE UNIT TESTS. `tests/unit/ai-proxy.test.ts`
 * proves the handler's own decisions with fakes: what it spends, what it
 * releases, which headers it rebuilds. What it CANNOT prove is that any of it
 * is wired to anything. A proxy that reserved against a quota store nobody
 * mounted, or that mounted behind the wrong auth, or that wrote a row keyed on
 * a column the migration did not add, passes every unit test in the file.
 *
 * The three claims that only survive here:
 *   1. THE ROW EXISTS. The reservation is a real `INSERT ... ON CONFLICT` into
 *      a real table with a real composite key. Migration 0009 is what makes
 *      that statement legal, and nothing but a database can say so.
 *   2. THE LIMIT IS THE ROW'S. The refusal at the limit is the database
 *      declining to update, not a number this test handed the handler.
 *   3. THE ROUTE IS ABSENT WITHOUT A KEY. An instance with no provider key
 *      answers the ordinary unknown-path 404, so the surface does not exist
 *      rather than existing and refusing — the same bargain the admin, share
 *      and research trees make.
 *
 * The upstream is a real server on an ephemeral port, so the service's `fetch`
 * is the production `undici` one and what it sends is what a provider sees.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq } from 'drizzle-orm';
import { aiUsageDays, accounts } from '../../src/db/schema.js';
import { setupTestDatabase, type TestDatabase } from './db-harness.js';
import { startService, sampleCiphertext, DEFAULT_AI_MAX_REQUEST_BYTES, type ServiceHarness } from './service-harness.js';

const UPSTREAM_KEY = 'sk-the-operators-own-provider-key';

/** What the fake upstream did with the request it last received. */
interface ReceivedCall {
  authorization: string | undefined;
  cookie: string | undefined;
  apiKeyHeader: string | undefined;
  path: string;
  body: string;
}

/** What the fake upstream answers next. */
interface UpstreamPlan {
  status: number;
  body: string;
  /** When set, the body is written in these pieces with a gap between them, so the relay must stream. */
  chunks?: string[];
}

let database: TestDatabase;
let upstream: Server;
let upstreamBaseUrl: string;
let received: ReceivedCall[];
let plan: UpstreamPlan;

before(async () => {
  database = await setupTestDatabase();

  upstream = createServer((request: IncomingMessage, response: ServerResponse) => {
    const pieces: Buffer[] = [];
    request.on('data', (piece: Buffer) => pieces.push(piece));
    request.on('end', () => {
      received.push({
        authorization: request.headers.authorization,
        cookie: request.headers.cookie,
        apiKeyHeader: request.headers['x-api-key']?.toString(),
        path: request.url ?? '',
        body: Buffer.concat(pieces).toString('utf8'),
      });

      if (plan.chunks === undefined) {
        response.writeHead(plan.status, { 'content-type': 'application/json' });
        response.end(plan.body);
        return;
      }

      // A streaming answer: headers first, then pieces over time. A proxy that
      // buffered would still pass every byte on, so the assertion that matters
      // is on the reader side (see the streaming case).
      response.writeHead(plan.status, { 'content-type': 'text/event-stream' });
      const chunks = plan.chunks;
      let index = 0;
      const writeNext = (): void => {
        if (index >= chunks.length) {
          response.end();
          return;
        }
        response.write(chunks[index]);
        index += 1;
        setTimeout(writeNext, 10);
      };
      writeNext();
    });
  });
  upstream.listen(0);
  await new Promise<void>((resolve) => upstream.once('listening', resolve));
  const address = upstream.address();
  if (address === null) throw new Error('expected a listening upstream');
  // SAFETY: `listen(0)` binds a TCP port; Node returns the string form only
  // for a Unix domain socket, which this never opens.
  upstreamBaseUrl = `http://127.0.0.1:${(address as AddressInfo).port}`;
});

after(async () => {
  await new Promise<void>((resolve, reject) => upstream.close((error) => (error ? reject(error) : resolve())));
  await database.close();
});

beforeEach(async () => {
  await database.reset();
  received = [];
  plan = { status: 200, body: JSON.stringify({ choices: [{ message: { content: 'a bowl of rice, about 45 g of carbs' } }] }) };
});

async function startWithAi(perMinute?: number): Promise<ServiceHarness> {
  return startService({
    db: database.db,
    ai: { baseUrl: upstreamBaseUrl, apiKey: UPSTREAM_KEY, timeoutMs: 5_000, perMinute },
  });
}

/** The body a client actually posts. Small, but shaped like the real thing. */
interface CompletionRequest {
  model: string;
  messages: { role: string; content: string }[];
}

function completionRequest(): CompletionRequest {
  return {
    model: 'a-vision-model',
    messages: [{ role: 'user', content: 'what is on this plate?' }],
  };
}

/**
 * Waits for `accounts.last_seen_at` to be written, with a bound.
 *
 * THE WRITE IS DELIBERATELY AFTER THE RESPONSE — the proxy relays first and
 * stamps the row afterwards, so a failed request never reports the person as
 * active. That means the client's `fetch` resolves BEFORE the `UPDATE` lands,
 * and a test that read the row once would be racing the service rather than
 * testing it. Polling is the honest shape here; the bound keeps a genuine
 * regression to a few hundred milliseconds instead of a hung suite.
 */
async function waitForLastSeen(accountId: number): Promise<Date | null> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    const [row] = await database.db.select().from(accounts).where(eq(accounts.id, accountId));
    if (row?.lastSeenAt != null) return row.lastSeenAt;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return null;
}

/** The single `ai_usage_days` count for an account, or 0 when no row exists. */
async function usageCount(accountId: number): Promise<number> {
  const rows = await database.db.select().from(aiUsageDays).where(eq(aiUsageDays.accountId, accountId));
  return rows[0]?.count ?? 0;
}

test("a signed-in account's completion is proxied, and the row counts it", async () => {
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });

    const answered = await service.request<{ choices: unknown[] }>({
      method: 'POST',
      path: '/v1/chat/completions',
      accessToken: session.tokens.accessToken,
      body: completionRequest(),
    });

    assert.equal(answered.status, 200);
    assert.equal(answered.body.choices.length, 1);

    // THE ROW. One request, one unit, on a real composite-keyed table.
    assert.equal(await usageCount(session.account.id), 1);
    assert.equal(answered.headers.get('x-quota-used'), '1');
    assert.equal(answered.headers.get('x-quota-limit'), '5');

    // The provider saw the OPERATOR's key and the caller's body, and never the
    // caller's own token.
    assert.equal(received.length, 1);
    assert.equal(received[0]?.authorization, `Bearer ${UPSTREAM_KEY}`);
    assert.ok(!received[0]?.authorization?.includes(session.tokens.accessToken));
    assert.equal(received[0]?.path, '/chat/completions');
    assert.deepEqual(JSON.parse(received[0]?.body ?? 'null'), completionRequest());

    // `last_seen_at` moves on a proxied call, which is what makes the admin
    // list's "last seen" column mean anything on an instance where people use
    // the camera more often than they sign in.
    assert.notEqual(await waitForLastSeen(session.account.id), null);
  } finally {
    await service.close();
  }
});

test('the account is refused at its limit, and the refusal is the DATABASE declining', async () => {
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 2 });
    const send = () =>
      service.request<{ error?: string }>({
        method: 'POST',
        path: '/v1/chat/completions',
        accessToken: session.tokens.accessToken,
        body: completionRequest(),
      });

    assert.equal((await send()).status, 200);
    assert.equal((await send()).status, 200);

    const refused = await send();
    assert.equal(refused.status, 429);
    // A SENTENCE, not a code, and it names both halves: how much of what, and
    // when it comes back. This service answers codes only where a client has
    // to BRANCH on the reason (`ai-not-allowed`, `account-suspended`); being
    // out of allowance is something a person reads.
    assert.match(refused.body.error ?? '', /daily quota spent: 2 of 2 requests used/);
    assert.match(refused.body.error ?? '', /resets at \d{4}-\d{2}-\d{2}T00:00:00\.000Z/);
    // The client is told WHEN in a header too, not merely in prose.
    const retryAfter = Number(refused.headers.get('retry-after'));
    assert.ok(Number.isInteger(retryAfter) && retryAfter > 0 && retryAfter <= 86_400, `retry-after was ${retryAfter}`);

    // THE COUNT DID NOT MOVE and the upstream was never called: the refusal
    // came from the reservation, before any request left this host.
    assert.equal(await usageCount(session.account.id), 2);
    assert.equal(received.length, 2);
  } finally {
    await service.close();
  }
});

test('an account with an allowance of 0 is told it may not, and never reserves', async () => {
  const service = await startWithAi();
  try {
    // Zero is the DEFAULT for a new invite: the AI is opt-in per account, so
    // an operator who mints an ordinary invite has not handed out their
    // provider key by accident.
    const session = await service.signupThroughInvite({ email: 'anna@example.org' });

    const refused = await service.request<{ error?: string }>({
      method: 'POST',
      path: '/v1/chat/completions',
      accessToken: session.tokens.accessToken,
      body: completionRequest(),
    });

    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, 'ai-not-allowed');
    // NO ROW AT ALL, not a row at zero. The guard runs before the reservation
    // precisely because the reservation's insert branch is unguarded.
    const rows = await database.db.select().from(aiUsageDays).where(eq(aiUsageDays.accountId, session.account.id));
    assert.deepEqual(rows, []);
    assert.equal(received.length, 0);
  } finally {
    await service.close();
  }
});

test('a streaming answer arrives in pieces rather than at the end', async () => {
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });
    plan = {
      status: 200,
      body: '',
      chunks: ['data: {"choices":[{"delta":{"content":"a bowl"}}]}\n\n', 'data: {"choices":[{"delta":{"content":" of rice"}}]}\n\n', 'data: [DONE]\n\n'],
    };

    // Raw `fetch` rather than `service.request`, because the harness reads
    // whole JSON bodies and the property under test is that the body is NOT
    // whole when the headers arrive.
    const response = await fetch(`${service.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session.tokens.accessToken}` },
      body: JSON.stringify({ ...completionRequest(), stream: true }),
    });

    assert.equal(response.status, 200);
    // A buffering proxy answers with a `content-length`; a relaying one cannot
    // know it. And `no-transform` is what stops a compressing intermediary
    // from holding the stream until it ends.
    assert.equal(response.headers.get('content-length'), null);
    assert.match(response.headers.get('cache-control') ?? '', /no-transform/);

    const reader = response.body?.getReader();
    assert.ok(reader, 'a streamed response must have a readable body');
    const pieces: string[] = [];
    const decoder = new TextDecoder();
    for (;;) {
      const next = await reader.read();
      if (next.done) break;
      pieces.push(decoder.decode(next.value, { stream: true }));
    }

    // MORE THAN ONE PIECE is the assertion. A proxy that awaited the whole
    // upstream body and then wrote it would deliver exactly one, and every
    // other assertion in this test would still pass.
    assert.ok(pieces.length > 1, `expected several pieces, got ${pieces.length}`);
    assert.equal(pieces.join(''), (plan.chunks ?? []).join(''));
    assert.equal(await usageCount(session.account.id), 1);
  } finally {
    await service.close();
  }
});

test('an upstream refusal releases the unit, so a misconfigured key costs nobody an allowance', async () => {
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 3 });
    // The shape a provider answers with when the operator's key is wrong. It
    // never reached a model, so nobody billed it.
    plan = { status: 401, body: JSON.stringify({ error: { message: 'invalid api key' } }) };

    const answered = await service.request<unknown>({
      method: 'POST',
      path: '/v1/chat/completions',
      accessToken: session.tokens.accessToken,
      body: completionRequest(),
    });

    assert.equal(answered.status, 401);
    // Reserved, then released: back to zero, in the real row, through the real
    // floored `UPDATE`.
    assert.equal(await usageCount(session.account.id), 0);
  } finally {
    await service.close();
  }
});

test('a suspended account cannot spend, and an unsigned request cannot reach the route at all', async () => {
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });
    await database.db.update(accounts).set({ suspendedAt: new Date() }).where(eq(accounts.id, session.account.id));

    const suspended = await service.request<{ error?: string }>({
      method: 'POST',
      path: '/v1/chat/completions',
      accessToken: session.tokens.accessToken,
      body: completionRequest(),
    });
    assert.equal(suspended.status, 403);
    assert.equal(suspended.body.error, 'account-suspended');

    const anonymous = await service.request<unknown>({
      method: 'POST',
      path: '/v1/chat/completions',
      body: completionRequest(),
    });
    assert.equal(anonymous.status, 401);

    assert.equal(await usageCount(session.account.id), 0);
    assert.equal(received.length, 0);
  } finally {
    await service.close();
  }
});

test('the minute limiter is per account: one caller is slowed, another is not', async () => {
  const service = await startWithAi(2);
  try {
    const fast = await service.signupThroughInvite({ email: 'fast@example.org', dailyAiLimit: 50 });
    const other = await service.signupThroughInvite({ email: 'other@example.org', dailyAiLimit: 50 });
    const send = (accessToken: string) =>
      service.request<{ error?: string }>({
        method: 'POST',
        path: '/v1/chat/completions',
        accessToken,
        body: completionRequest(),
      });

    assert.equal((await send(fast.tokens.accessToken)).status, 200);
    assert.equal((await send(fast.tokens.accessToken)).status, 200);
    const slowed = await send(fast.tokens.accessToken);
    assert.equal(slowed.status, 429);
    assert.match(slowed.body.error ?? '', /rate limit reached: 2 requests per minute/);

    // THE OTHER ACCOUNT IS UNAFFECTED. A limiter keyed on the IP would refuse
    // this one too, and on an instance behind one office router that is every
    // account at once.
    assert.equal((await send(other.tokens.accessToken)).status, 200);

    // The refused request never reserved, so the daily allowance is intact.
    assert.equal(await usageCount(fast.account.id), 2);
  } finally {
    await service.close();
  }
});

test('a 3 MB photograph reaches the provider through the real app', async () => {
  // THE DEFECT THIS PINS: the shipped route derived its body limit from
  // `MAX_BLOB_BYTES`, giving 2.73 MB, so every real plate photograph came back
  // 413 — through a green unit suite, a green integration suite and a green
  // build, because nothing in either tier ever sent a body larger than a
  // sentence. `tests/unit/ai-route-limits.test.ts` covers the arithmetic; this
  // covers the wiring, with the app assembled exactly as `main.ts` assembles
  // it.
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });
    const base64Image = 'A'.repeat(3 * 1024 * 1024);

    // Raw `fetch`, because `service.request` serialises through the harness and
    // the property under test is what crosses the wire.
    const response = await fetch(`${service.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session.tokens.accessToken}` },
      body: JSON.stringify({
        model: 'a-vision-model',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: 'what is on this plate?' },
              { type: 'image_url', image_url: { url: `data:image/jpeg;base64,${base64Image}` } },
            ],
          },
        ],
      }),
    });

    assert.equal(response.status, 200);
    // IT REACHED THE PROVIDER, whole. A 200 alone would not say so, and a byte
    // count is what distinguishes "relayed" from "truncated at the parser".
    assert.equal(received.length, 1);
    assert.ok(
      (received[0]?.body.length ?? 0) > 3 * 1024 * 1024,
      `the provider saw ${received[0]?.body.length ?? 0} bytes, so the body did not survive the parser`,
    );
    assert.ok(received[0]?.body.includes(base64Image), 'the image must arrive unmodified');
    assert.equal(await usageCount(session.account.id), 1);
  } finally {
    await service.close();
  }
});

test('a body over AI_MAX_REQUEST_BYTES is refused in the OpenAI shape, before the provider', async () => {
  // A small configured limit rather than a 9 MB fixture: it proves the app
  // reads the variable, which is the half a large body cannot show.
  const service = await startService({
    db: database.db,
    ai: { baseUrl: upstreamBaseUrl, apiKey: UPSTREAM_KEY, maxRequestBytes: 500_000 },
  });
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });

    const response = await fetch(`${service.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session.tokens.accessToken}` },
      body: JSON.stringify({ model: 'a-vision-model', pad: 'A'.repeat(1024 * 1024) }),
    });

    assert.equal(response.status, 413);
    // SAFETY: this route answers `application/json` on every path, and a body
    // that did not parse would throw here rather than reach the assertions.
    const body = (await response.json()) as { error?: { code?: string; type?: string } };
    // An OBJECT, because the caller is an OpenAI-compatible client. The rest of
    // this service answers `{"error": "<sentence>"}` and that shape reads as
    // `undefined` to such a client.
    assert.equal(body.error?.type, 'invalid_request_error');
    assert.equal(body.error?.code, 'request_too_large');

    // Nothing left the host, and no unit was reserved: the parser refused
    // before auth, the limiter and the reservation.
    assert.equal(received.length, 0);
    assert.equal(await usageCount(session.account.id), 0);
  } finally {
    await service.close();
  }
});

test('no other router\'s body parser reaches this route', async () => {
  // THE ACTUAL CAUSE of the 413, and the reason the two tests above were not
  // enough on their own. Every router in this service is mounted with
  // `app.use(router)` at the ROOT, and each mounted its `express.json()` with
  // no path. `express.json()` marks a request as parsed, so the FIRST parser
  // to see a request wins and every later router's declared limit is dead
  // code. In practice the auth router's 64 KB parser applied to the whole
  // service, and after that the sync router's 2.67 MB one did.
  //
  // This case is deliberately sized BETWEEN the two neighbouring limits: over
  // the sync router's, under the AI route's. It passes only if the AI route's
  // own parser is the one that ran.
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });
    const body = JSON.stringify({ model: 'a-vision-model', pad: 'A'.repeat(4 * 1024 * 1024) });
    assert.ok(body.length > 2_800_299, 'the fixture must exceed the sync router JSON_BODY_LIMIT');
    assert.ok(body.length > 64 * 1024, 'and the auth router AUTH_JSON_BODY_LIMIT');
    assert.ok(body.length < DEFAULT_AI_MAX_REQUEST_BYTES, 'and sit under the AI route limit');

    const response = await fetch(`${service.baseUrl}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${session.tokens.accessToken}` },
      body,
    });
    assert.equal(response.status, 200);
    assert.equal(received.length, 1);
  } finally {
    await service.close();
  }
});

test('and the sync tree keeps its own, larger-than-auth limit', async () => {
  // The other half of the same defect: a blob push over 64 KB was answered
  // `413` by the AUTH router's parser even though `MAX_BLOB_BYTES` is 2 MiB.
  // Nothing caught it because every existing fixture pushes 256 bytes.
  const service = await startWithAi();
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org' });
    const pushed = await service.request<{ error?: string }>({
      method: 'POST',
      path: '/v1/sync/blob',
      accessToken: session.tokens.accessToken,
      body: { ciphertext: sampleCiphertext(3, 512 * 1024), envelopeVersion: 1, expectedVersion: null },
    });
    // Whatever the handler decides about the SHAPE, it must be the handler
    // deciding. A 413 here means a parser refused the body before routing.
    assert.notEqual(pushed.status, 413, `a 512 KB blob push answered ${pushed.status} ${JSON.stringify(pushed.body)}`);
  } finally {
    await service.close();
  }
});

test('an instance with no provider key does not have the route', async () => {
  // The default: `UPSTREAM_API_KEY` unset, which is every deployment that has
  // not bought one.
  const service = await startService({ db: database.db });
  try {
    const session = await service.signupThroughInvite({ email: 'anna@example.org', dailyAiLimit: 5 });

    const missing = await service.request<unknown>({
      method: 'POST',
      path: '/v1/chat/completions',
      accessToken: session.tokens.accessToken,
      body: completionRequest(),
    });
    // 404, not 403: the surface is ABSENT, so a scan cannot tell this instance
    // from one that never shipped the feature.
    assert.equal(missing.status, 404);

    const health = await service.request<{ instance: { ai: unknown } }>({ method: 'GET', path: '/health' });
    assert.equal(health.body.instance.ai, null);
  } finally {
    await service.close();
  }
});

test('/health advertises the model an instance WITH a key will use', async () => {
  const service = await startWithAi();
  try {
    const health = await service.request<{ instance: { ai: { model: string | null } | null } }>({
      method: 'GET',
      path: '/health',
    });
    // Present, and it is a capability statement rather than a grant: it says
    // the operator configured an upstream, never that this caller may use it.
    assert.notEqual(health.body.instance.ai, null);
    assert.equal(health.body.instance.ai?.model, null, 'this harness advertises no model name');
  } finally {
    await service.close();
  }
});
