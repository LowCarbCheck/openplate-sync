/**
 * A per-account sliding-window burst limit, sitting on top of the daily quota.
 *
 * WHY BOTH. The daily quota is the spend control: it decides how much of the
 * shared provider key an account may burn in a UTC day. It says nothing about
 * WHEN. Without a burst guard, a loop in a client — or a script that retries on
 * every error — spends the whole day's allowance in ten seconds, and the first
 * thing anybody notices is a person who is inexplicably out of requests at
 * 09:00. This limiter turns that into a visible `429` while the allowance is
 * still there.
 *
 * SLIDING WINDOW, NOT FIXED WINDOWS. A fixed window lets a caller spend a full
 * minute's budget in the last second of one window and the whole next budget in
 * the first second of the next: twice the intended burst, at the one moment the
 * guard was supposed to be watching. Keeping the timestamps and counting only
 * the ones inside the trailing 60 seconds costs a short array per account and
 * has no such seam.
 *
 * KEYED ON THE RESOLVED ACCOUNT, SO ORDER OF WIRING MATTERS: this must run
 * AFTER the bearer middleware. Keying on the IP instead would put a whole
 * household behind one NAT into a single bucket, which is the opposite of the
 * fairness this wants, and it would let an unauthenticated caller consume a
 * real account's budget.
 *
 * IN-MEMORY AND SINGLE-PROCESS, deliberately: one container, no Redis in a
 * self-hoster's compose file, exactly as `lib/throttle.ts` argues for the auth
 * throttle. The durable counter — the one that guards money — is
 * `ai_usage_days`, and that one persists.
 *
 * Ported from `openplate-gateway/src/server/rate-limit.ts`, with the member
 * identity replaced by this service's account id and the error path replaced by
 * a direct response rather than the gateway's error envelope.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { getRequestSession } from '../server/bearer-auth.js';

const WINDOW_MS = 60_000;

/**
 * How often the whole map is swept for accounts that have gone quiet.
 * Amortised across requests rather than run on a timer: a `setInterval` would
 * keep a handle alive, need unref-ing, and make the module untestable without a
 * real clock. The injected `now` drives this too.
 */
const SWEEP_INTERVAL_MS = WINDOW_MS;

export interface CreateAiRateLimitOptions {
  /** Requests allowed per account in any trailing 60-second window. */
  perMinute: number;
  /** Injectable clock so tests do not sleep. Defaults to `Date.now`. */
  now?: () => number;
}

/** Drops timestamps that have fallen out of the trailing window. Mutates in place — this is the hot path. */
function pruneExpired(timestamps: number[], windowStartMs: number): void {
  let firstLive = 0;
  while (firstLive < timestamps.length && (timestamps[firstLive] ?? 0) <= windowStartMs) {
    firstLive += 1;
  }
  if (firstLive > 0) timestamps.splice(0, firstLive);
}

/**
 * Seconds until the oldest in-window request ages out, i.e. until one slot
 * frees. Floored at 1: a `Retry-After: 0` invites an immediate retry that is
 * guaranteed to fail again.
 */
function secondsUntilSlotFrees(input: { oldestMs: number; currentMs: number }): number {
  return Math.max(1, Math.ceil((input.oldestMs + WINDOW_MS - input.currentMs) / 1000));
}

export function createAiRateLimit(options: CreateAiRateLimitOptions): RequestHandler {
  const limit = options.perMinute;
  const now = options.now ?? ((): number => Date.now());
  /** account id -> timestamps of its in-window requests, oldest first. */
  const windows = new Map<number, number[]>();
  let lastSweepMs = now();

  /**
   * Bounded memory. Without this, one entry per account that ever called
   * survives for the life of the process: small per entry, unbounded in
   * aggregate, and it never shows up in testing because a test has three
   * accounts. The sweep exists so the map's size tracks ACTIVE accounts rather
   * than every account since boot.
   */
  function sweep(currentMs: number): void {
    if (currentMs - lastSweepMs < SWEEP_INTERVAL_MS) return;
    lastSweepMs = currentMs;
    const windowStartMs = currentMs - WINDOW_MS;
    for (const [key, timestamps] of windows) {
      pruneExpired(timestamps, windowStartMs);
      if (timestamps.length === 0) windows.delete(key);
    }
  }

  return function enforceAiRateLimit(req: Request, res: Response, next: NextFunction): void {
    const session = getRequestSession(req);
    if (session === null) {
      // FAIL CLOSED. Reaching here means this limiter was mounted before (or
      // without) the bearer middleware — a wiring bug, not a client error.
      // Letting the request through "because we cannot key it" would silently
      // disable both the burst guard and, since the quota layer keys on the
      // same identity, the spend control behind it.
      res.status(401).json({ error: 'authentication required' });
      return;
    }

    const currentMs = now();
    sweep(currentMs);

    const windowStartMs = currentMs - WINDOW_MS;
    const timestamps = windows.get(session.accountId) ?? [];
    pruneExpired(timestamps, windowStartMs);

    if (timestamps.length >= limit) {
      // Non-null in practice: the branch is only reachable with `limit >= 1`
      // and at least one live timestamp. The fallback keeps the type honest.
      const oldestMs = timestamps[0] ?? currentMs;
      windows.set(session.accountId, timestamps);
      const retryAfterSeconds = secondsUntilSlotFrees({ oldestMs, currentMs });
      res.setHeader('Retry-After', String(retryAfterSeconds));
      // Says "for this account" and names no identifier: putting the account id
      // in a response body would echo a value back to whoever holds the token.
      res.status(429).json({
        error: `rate limit reached: ${limit} requests per minute for this account`,
      });
      return;
    }

    timestamps.push(currentMs);
    windows.set(session.accountId, timestamps);
    next();
  };
}
