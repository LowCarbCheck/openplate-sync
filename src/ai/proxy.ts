/**
 * `POST /v1/chat/completions` — the proxy itself, and the only place in this
 * service where a plate photograph exists.
 *
 * WHAT IT IS. A signed-in account posts an ordinary OpenAI-compatible request
 * with their OWN access token. This service spends one unit of their daily
 * allowance, swaps their token for the operator's real provider key, forwards
 * the body untouched, and relays the answer back. The account never learns the
 * provider key; the provider never learns the access token.
 *
 * THE BODY IS A PLATE PHOTOGRAPH. It arrives here, it is serialised once, it is
 * handed to `undici`, and it is dropped when the promise settles. Nothing
 * writes it, nothing caches it, and nothing logs it. This is also the one place
 * where the service's zero-knowledge claim genuinely does not hold: the blob
 * store cannot read what it holds, and this route can see everything that
 * passes through it. ADR-0005 says so out loud, and `README.md` repeats it.
 *
 * ORDER OF OPERATIONS, and every step is where it is on purpose:
 *   1. identity   — no session on the request is a WIRING bug; fail closed.
 *   2. allowance  — a `dailyAiLimit` of 0 is refused before an upstream call.
 *   3. RESERVE    — before the call, never after. Counting after the fact has a
 *                   window in which N parallel requests all read the old count.
 *   4. forward    — the caller's `Authorization` is REPLACED, not merged.
 *   5. release?   — only when the provider cannot have billed us. See the
 *                   spent-vs-released table below; it is the money question.
 *   6. relay      — piped, never buffered, so `stream: true` streams.
 *
 * ── WHAT COUNTS AS SPENT ────────────────────────────────────────────────────
 * "Spent" means: keep the reservation, the account has used one of its daily
 * requests. "Released" means: give it back, the money was never at risk.
 *
 *   connect error / DNS / refused   RELEASED — the request never left this host
 *   headers timeout (no bytes yet)  RELEASED — nothing was served to us; our own
 *                                   bound gave up before the provider answered
 *   upstream 4xx                    RELEASED — the provider REFUSED the request
 *                                   (malformed, unknown model, bad key, edge
 *                                   429). It never reached a model, so nobody
 *                                   billed it, and charging the account for the
 *                                   operator's own misconfiguration is the worst
 *                                   outcome: a broken proxy would silently eat
 *                                   an organization's whole allowance in a
 *                                   minute.
 *   upstream 5xx                    SPENT — the provider accepted the request
 *                                   and failed while serving it. Generation may
 *                                   have run and may be billed. Releasing here
 *                                   hands out a free infinite retry loop against
 *                                   a flaky provider, which is exactly when a
 *                                   client retries hardest.
 *   body timeout / stream aborted   SPENT — headers already arrived, so the
 *                                   provider ran the request. That we failed to
 *                                   read the answer is our problem, not a refund.
 *   upstream 2xx                    SPENT — obviously.
 *
 * ── THE THREE HARD RULES ────────────────────────────────────────────────────
 *  1. NEVER LOG A BODY. Not the request, not the response, not a prefix, not a
 *     decoded buffer. What is logged: account id, upstream status, byte COUNTS,
 *     duration. Counts are not bytes.
 *  2. EVERY STRING THAT CAME OFF THE UPSTREAM WIRE GOES THROUGH `scrubPayloads`
 *     / `describeError` before it reaches a log line OR a response. A provider
 *     that rejects a request routinely echoes the request back at you, image and
 *     all, inside its error body. That string is the single most likely way a
 *     photograph escapes this process, and it is also the string a debugging
 *     instinct most wants to log verbatim.
 *  3. THE CALLER'S OWN TOKEN IS NEVER FORWARDED. The upstream headers are BUILT
 *     from scratch rather than copied from `req.headers` and overwritten; a
 *     copy-then-overwrite forwards cookies, `x-api-key`, and whatever the next
 *     provider decides to read.
 *
 * ── THE TWO UNDICI TIMEOUT SITES ────────────────────────────────────────────
 * Node's global `fetch` applies a default `headersTimeout` of 300 s that an
 * `AbortSignal` cannot RAISE — a signal can only add a tighter cap. So an
 * operator who sets `UPSTREAM_TIMEOUT_MS=600000` on a slow provider would still
 * be cut off at 300 s, with an error that names no knob. This module therefore
 * calls `undici`'s own `fetch` with an `Agent` it configures, which is the only
 * way the configured bound is the bound that applies. It is the one runtime
 * dependency this service has beyond express, pg and dotenv.
 *
 * The two bounds surface in DIFFERENT catch blocks, which is why there are two
 * of them below and not one:
 *
 *   headersTimeout ⇒ the `fetch()` call itself rejects
 *   bodyTimeout    ⇒ `fetch()` RESOLVES with a 200, and the failure lands later,
 *                    while reading the body, as `TypeError: terminated`
 *
 * A body timeout reaching the body-read catch reads, wrongly, as "the provider
 * sent a malformed body". It is also the site with the opposite money answer:
 * the header site releases the reservation, the body site keeps it.
 *
 * Ported from `openplate-gateway/src/server/proxy.ts`. The zod schemas are
 * replaced by `lib/json.ts` decoders, which is the same check without the
 * dependency: this is a PROXY, so the only validation a body gets is "is it a
 * JSON object", and a strict schema would reject every field the provider adds
 * next month.
 */
import { Transform, Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { Agent, fetch as undiciFetch, type Response as UpstreamResponse } from 'undici';
import { asBoolean, asObject, asString, type JsonValue } from '../lib/json.js';
import { utcDayKey } from '../lib/utc-day.js';
import type { Logger } from '../logger.js';
import { getRequestSession } from '../server/bearer-auth.js';
import type { AccountStore } from '../accounts/account-store.js';
import { ACCOUNT_SUSPENDED } from '../accounts/auth-handlers.js';
import type { AiQuotaStore } from './quota-store.js';
import { describeError, scrubPayloads } from './scrub.js';

/** The upstream this proxy forwards to, already validated all-or-nothing by `config.ts`. */
export interface AiUpstreamConfig {
  baseUrl: string;
  apiKey: string;
  timeoutMs: number;
}

export interface ChatCompletionsDeps {
  upstream: AiUpstreamConfig;
  quota: AiQuotaStore;
  /** Reads the caller's `dailyAiLimit` and stamps `last_seen_at` on a successful call. */
  accounts: AccountStore;
  logger: Logger;
  /** Injectable so a test can freeze the UTC day boundary the quota keys on. */
  now?: () => Date;
}

/** undici's codes for "the socket was open and nothing arrived in time". */
const TIMEOUT_CODES = new Set(['UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT', 'UND_ERR_CONNECT_TIMEOUT']);

/** How far to follow `.cause`. The observed depth is 1; the rest is defensive. */
const MAX_CAUSE_DEPTH = 5;

const MS_PER_SECOND = 1000;
const MS_PER_DAY = 86_400_000;

/**
 * The longest an upstream error body may be before this stops reading it. A
 * provider that echoes a rejected request sends the whole base64 image back; it
 * is scrubbed, but there is no reason to hold megabytes of it in memory first.
 */
const MAX_UPSTREAM_ERROR_BYTES = 4096;

/**
 * Reads one link of a thrown value's `cause` chain.
 *
 * Deliberately unparsed: these values were produced by `throw`, JS permits
 * throwing anything, and undici hangs its codes off objects nobody typed. A
 * schema here would have to invent a contract that does not exist, and this
 * classifier's only job is to be right about values nobody promised anything
 * about.
 */
function errorCodeOf(cause: unknown): string | undefined {
  if (cause === null || cause === undefined || !(cause instanceof Object) || !('code' in cause)) return undefined;
  // SAFETY: `'code' in cause` was just checked on a non-null object. The
  // assertion claims the property is PRESENT, which was checked, and says
  // nothing about its type — which is why it is read as an unproven value and
  // decoded below.
  const code = (cause as { code?: JsonValue }).code;
  // Decoded through `lib/json.ts` rather than a bare `typeof`: this is exactly
  // the "unproven representation" boundary that module owns, and undici's codes
  // are values nobody typed.
  return asString(code) ?? undefined;
}

/**
 * `fetch` reports every transport failure as an opaque `TypeError` (`fetch
 * failed` / `terminated`) and hangs the real reason off `cause`. That chain is
 * the ONLY thing separating a two-minute timeout from an instant connection
 * refusal — same words, opposite remedies, and here opposite answers to "did
 * the account just spend a request?".
 */
export function isTimeoutError(cause: unknown): boolean {
  const seen = new Set<unknown>();
  let current: unknown = cause;

  for (let depth = 0; depth <= MAX_CAUSE_DEPTH; depth += 1) {
    if (current === null || current === undefined || seen.has(current)) return false;
    seen.add(current);

    const code = errorCodeOf(current);
    if (code !== undefined && TIMEOUT_CODES.has(code)) return true;

    if (!(current instanceof Error)) return false;
    current = current.cause;
  }
  return false;
}

/** Only ever used as a LOG FIELD. The relay path never branches on it — it always pipes. */
function requestsStreaming(body: JsonValue | undefined): boolean {
  return asBoolean(asObject(body)?.stream) ?? false;
}

/** Next UTC midnight after `now` — when a spent daily allowance comes back. */
export function nextUtcMidnight(now: Date): Date {
  return new Date(Math.floor(now.getTime() / MS_PER_DAY) * MS_PER_DAY + MS_PER_DAY);
}

function secondsUntil(input: { target: Date; now: Date }): number {
  return Math.max(1, Math.ceil((input.target.getTime() - input.now.getTime()) / MS_PER_SECOND));
}

/**
 * A pass-through that knows how many bytes went past it, and nothing about what
 * they were. Named so the log line's `responseBytes` has a contract.
 */
interface ByteCounter {
  stream: Transform;
  total: () => number;
}

/** Counts bytes as they flow past, so a log line can report a size without ever holding the payload. */
function createByteCounter(): ByteCounter {
  let total = 0;
  const stream = new Transform({
    transform(chunk: Buffer, _encoding, callback): void {
      total += chunk.byteLength;
      callback(null, chunk);
    },
  });
  return { stream, total: (): number => total };
}

export function createChatCompletionsHandler(deps: ChatCompletionsDeps): RequestHandler {
  const { accounts, logger, quota, upstream: upstreamConfig } = deps;
  const now = deps.now ?? ((): Date => new Date());
  const upstreamUrl = `${upstreamConfig.baseUrl.replace(/\/+$/, '')}/chat/completions`;

  /**
   * ONE dispatcher for the life of the handler, not one per request: an `Agent`
   * owns the connection pool, so building it per call would throw away
   * keep-alive and leak a pool per plate photograph.
   */
  const dispatcher = new Agent({
    headersTimeout: upstreamConfig.timeoutMs,
    bodyTimeout: upstreamConfig.timeoutMs,
  });

  /**
   * A refund must never become the client's error. If the store cannot be
   * written the account has been over-charged by one request — annoying, and
   * strictly better than replacing the real upstream failure with a 500 that
   * points at the quota table.
   */
  async function releaseQuietly(input: { accountId: number; day: string }): Promise<void> {
    try {
      await quota.release(input);
    } catch (cause) {
      logger.warn('Could not release a quota reservation', {
        accountId: input.accountId,
        day: input.day,
        error: describeError(cause),
      });
    }
  }

  async function proxy(req: Request, res: Response): Promise<void> {
    const startedAt = performance.now();

    // 1. Identity. `null` here means the bearer middleware did not run on this
    // route — a wiring bug, not a caller mistake. Fail CLOSED: the alternative
    // is a spend endpoint open to the internet because somebody reordered two
    // `app.use` calls.
    const session = getRequestSession(req);
    if (session === null) {
      res.status(401).json({ error: 'authentication required' });
      return;
    }

    const account = await accounts.findAccountById(session.accountId);
    if (account === null) {
      res.status(401).json({ error: 'account no longer exists' });
      return;
    }
    // Defence in depth: the bearer middleware already refuses a suspended
    // account, so reaching here means it was suspended between the two reads.
    if (account.suspendedAt !== null) {
      res.status(403).json({ error: ACCOUNT_SUSPENDED });
      return;
    }

    // 2. NO ALLOWANCE IS NOT A QUOTA REFUSAL, and the distinction matters twice.
    // It answers 403 rather than 429 because there is nothing to wait for, and
    // it returns BEFORE the reservation, because `reserve`'s insert branch is
    // unguarded (see `quota-store.ts`) and a limit of zero reaching it would
    // write a row with `count = 1`.
    if (account.dailyAiLimit <= 0) {
      res.status(403).json({ error: 'ai-not-allowed' });
      return;
    }

    // A proxy validates that there IS a body and nothing else: a strict schema
    // would reject every field the provider adds next month.
    // SAFETY: `express.json()` on this router has already parsed the body, so
    // it is JSON-shaped by construction; `asObject` re-establishes that at the
    // type level and yields `null` for anything that is not an object.
    const body = req.body as JsonValue | undefined;
    if (asObject(body) === null) {
      // The parse failure is NOT quoted: the message would carry the input.
      res.status(400).json({ error: 'request body must be a JSON object' });
      return;
    }
    const forwardedBody = Buffer.from(JSON.stringify(body), 'utf8');

    // 3. Reserve BEFORE the upstream call. A refusal is a 429 with the reset
    // instant named, never a 500: being out of allowance is the system working.
    const requestedAt = now();
    const day = utcDayKey(requestedAt);
    const reservation = await quota.reserve({ accountId: account.id, day, limit: account.dailyAiLimit });
    if (!reservation.ok) {
      const resetAt = nextUtcMidnight(requestedAt);
      res.setHeader('Retry-After', String(secondsUntil({ target: resetAt, now: requestedAt })));
      res.setHeader('X-Quota-Used', String(reservation.used));
      res.setHeader('X-Quota-Limit', String(reservation.limit));
      res.status(429).json({
        error:
          `daily quota spent: ${reservation.used} of ${reservation.limit} requests used. ` +
          `It resets at ${resetAt.toISOString()}.`,
      });
      return;
    }

    // 4. Forward. Headers are BUILT, never copied — see hard rule 3.
    let upstream: UpstreamResponse;
    try {
      upstream = await undiciFetch(upstreamUrl, {
        method: 'POST',
        headers: {
          'Content-Type': req.header('content-type') ?? 'application/json',
          // The operator's key replaces the caller's token. The access token
          // never leaves this process, and the provider key never leaves this
          // line.
          Authorization: `Bearer ${upstreamConfig.apiKey}`,
        },
        body: forwardedBody,
        dispatcher,
      });
    } catch (cause) {
      // TIMEOUT SITE 1 of 2 — `headersTimeout` lands HERE, together with every
      // connect-level failure. Nothing was served to us in either case, so the
      // reservation goes back.
      await releaseQuietly({ accountId: account.id, day });
      const timedOut = isTimeoutError(cause);
      logger.warn('Upstream call failed before any response', {
        accountId: account.id,
        timedOut,
        requestBytes: forwardedBody.byteLength,
        durationMs: Math.round(performance.now() - startedAt),
        // Scrubbed: a transport error can quote the request it failed to send.
        error: describeError(cause),
      });
      res
        .status(timedOut ? 504 : 502)
        .json({
          error: timedOut
            ? `the upstream provider did not answer within ${upstreamConfig.timeoutMs} ms`
            : 'the upstream provider could not be reached',
        });
      return;
    }

    // 5. The provider answered. A 4xx means it REFUSED the request, so nothing
    // was billed and the account gets its unit back. A 5xx means it accepted
    // the request and then failed — the money may already be gone, so it stays
    // spent. See the table in the module header.
    if (upstream.status >= 400 && upstream.status < 500) {
      await releaseQuietly({ accountId: account.id, day });
    }

    if (!upstream.ok) {
      await relayUpstreamError({
        upstream,
        res,
        accountId: account.id,
        startedAt,
        requestBytes: forwardedBody.byteLength,
        reservation: { used: reservation.used, limit: reservation.limit },
      });
      return;
    }

    // 6. Relay, piped. `stream: true` works because nothing here buffers: the
    // upstream body is a stream and it goes straight out through a byte
    // counter. It is never inspected, so a streaming format nobody has heard of
    // still passes through unchanged.
    res.status(upstream.status);
    const contentType = upstream.headers.get('content-type');
    if (contentType) res.setHeader('Content-Type', contentType);
    // Server-sent events die behind a buffering proxy; say so explicitly rather
    // than hoping the deployment's reverse proxy guesses right.
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('X-Quota-Used', String(reservation.used));
    res.setHeader('X-Quota-Limit', String(reservation.limit));

    const counter = createByteCounter();
    // The two states this relay can end in, named rather than widened: an
    // `unknown` here discards the fact that a caught throw is the ONLY thing
    // that can put a value in it.
    let relayFailure: { cause: unknown } | null = null;
    try {
      // `upstream.body` is non-null for any response undici returns from a POST
      // that reached the network; the guard keeps the type honest and turns the
      // impossible case into a destroyed socket rather than a TypeError.
      if (!upstream.body) throw new Error('upstream response had no body');
      await pipeline(Readable.fromWeb(upstream.body), counter.stream, res);
    } catch (cause) {
      // TIMEOUT SITE 2 of 2 — `bodyTimeout` lands HERE, not in the catch above:
      // `fetch()` already resolved 200 by the time the stream stalls, and undici
      // surfaces the stall as `TypeError: terminated`. Read naively that says
      // "the provider sent a malformed body", which is a confident wrong
      // diagnosis that names no knob.
      //
      // NO RELEASE. Headers arrived, so the provider ran the request and is
      // billing for it. Our failure to read the answer is not a refund.
      relayFailure = { cause };
    }

    const durationMs = Math.round(performance.now() - startedAt);
    if (relayFailure !== null) {
      logger.error('Relay of the upstream response failed', {
        accountId: account.id,
        upstreamStatus: upstream.status,
        timedOut: isTimeoutError(relayFailure.cause),
        responseBytes: counter.total(),
        durationMs,
        error: describeError(relayFailure.cause),
      });
      // The status line and some bytes are already on the wire, so there is no
      // error document to send. Destroying the socket is the only signal left,
      // and it is the correct one: a truncated stream must not look complete.
      res.destroy();
      return;
    }

    // The one write this route makes to the account row, and the only writer of
    // `accounts.last_seen_at` in the service. Operator diagnostics: never a
    // rate limit, never an authorization input. It is deliberately AFTER the
    // relay, so a failed request does not report the person as active.
    await accounts.touchLastSeen({ accountId: account.id, seenAt: requestedAt });

    logger.info('Proxied a completion', {
      accountId: account.id,
      upstreamStatus: upstream.status,
      streaming: requestsStreaming(body),
      requestBytes: forwardedBody.byteLength,
      responseBytes: counter.total(),
      quotaUsed: reservation.used,
      quotaLimit: reservation.limit,
      durationMs,
    });
  }

  /**
   * A non-2xx upstream answer, relayed with its status and a SCRUBBED body.
   *
   * The status passes through untouched — a client needs to tell "your request
   * was wrong" from "the provider is down". The body does not: this is the
   * exact string in which a provider echoes the request it rejected, plate
   * photograph included. It is scrubbed before it reaches the caller and before
   * it reaches the log, and it is read through its own try/catch because
   * reading a body is the second place an undici timeout can land.
   */
  async function relayUpstreamError(context: {
    upstream: UpstreamResponse;
    res: Response;
    accountId: number;
    startedAt: number;
    requestBytes: number;
    reservation: { used: number; limit: number };
  }): Promise<void> {
    const { upstream, res } = context;

    let rawBody: string;
    try {
      rawBody = (await upstream.text()).slice(0, MAX_UPSTREAM_ERROR_BYTES);
    } catch (cause) {
      // Same two-site rule as the success path: a stalled error body arrives
      // here, not in the `fetch` catch.
      rawBody = isTimeoutError(cause)
        ? 'the provider stopped sending its error body'
        : 'the provider sent an unreadable error body';
    }
    const scrubbed = scrubPayloads(rawBody);

    logger.warn('Upstream provider returned an error', {
      accountId: context.accountId,
      upstreamStatus: upstream.status,
      requestBytes: context.requestBytes,
      responseBytes: Buffer.byteLength(rawBody, 'utf8'),
      durationMs: Math.round(performance.now() - context.startedAt),
      upstreamError: scrubbed,
    });

    // The quota headers ride on EVERY proxied response, including this one: a
    // client that only sees them on success cannot tell a released reservation
    // from a spent one.
    res.setHeader('X-Quota-Used', String(context.reservation.used));
    res.setHeader('X-Quota-Limit', String(context.reservation.limit));
    // The UPSTREAM's status, which is the one thing a caller needs to tell
    // "your request was wrong" from "the provider is down".
    res.status(upstream.status).json({ error: `the upstream provider answered ${upstream.status}: ${scrubbed}` });
  }

  /**
   * Express 4 does not catch a rejected promise from a handler — an async
   * handler that threw would hang the request until the client gave up, which
   * is a worse failure than any error it was trying to report. Every path out
   * of `proxy` therefore goes through this one wrapper.
   */
  return function handleChatCompletions(req: Request, res: Response, next: NextFunction): void {
    void (async (): Promise<void> => {
      try {
        await proxy(req, res);
      } catch (cause) {
        next(cause);
      }
    })();
  };
}
