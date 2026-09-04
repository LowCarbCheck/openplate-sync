/**
 * Express glue for the `/v1/auth/*` endpoints — mapping only. Every decision
 * lives in `auth-handlers.ts`; this file turns a typed `AuthOutcome` into a
 * status code and wires the per-IP throttle, which is the one concern that
 * genuinely needs the request object (`req.ip`).
 *
 * `express.json()` is applied to the `/v1/auth` PREFIX only, with a small
 * limit. Other routers mount their own, far larger ones
 * (`server/register-routes.ts`, `ai/register-ai-route.ts`) — a multi-megabyte
 * body limit has no business anywhere near a login endpoint.
 *
 * THE PREFIX ON THAT `use` IS LOAD-BEARING, and its absence was a live defect
 * until M192/03. This router is mounted with `app.use(router)` — at the ROOT,
 * with no path — so a `router.use(parser)` with no path of its own ran the
 * 64 KB parser on EVERY request to EVERY path in the service, before routing.
 * `express.json()` marks a request as parsed, so the second parser on the
 * blob, share, research and AI routers found the work already done and their
 * own declared limits were unreachable. The observable effect: a blob push
 * over 64 KB answered `413` even though `MAX_BLOB_BYTES` is 2 MiB, and every
 * plate photograph posted to `/v1/chat/completions` did too. Nothing caught
 * it because no test in either tier ever sent a body larger than a sentence.
 *
 * THROTTLE POLICY, per route and deliberately different:
 *  - **login** — keyed by IP **and** email, cleared on success. Slows a
 *    single-source brute force without letting anyone lock a victim out of
 *    their own account from a different IP.
 *  - **recover** and **recover-rotate** — keyed by IP **and** email, exactly
 *    like login and for the same reason, but they matter more: both accept a
 *    guess at the ONE authenticator left to a user who has lost their
 *    passphrase, and a success on either hands over the account. Neither is
 *    cleared on success — a legitimate recovery happens once, so there is no
 *    honest client that needs its allowance back.
 *  - **reset/request** — keyed by IP **and** email, never cleared, for the
 *    same reason. It does not accept a guess at anything, but it is the one
 *    endpoint whose two branches do measurably different work (one INSERT and
 *    one mail send on the known branch), and a residual timing signal that
 *    small only emerges from many samples per address. It is also what a
 *    caller would use to fill somebody's mailbox.
 *  - **signup**, **kdf**, **invite-lookup** and **reset/open** — keyed by IP
 *    ALONE, and every attempt counts, successful or not. These are volume
 *    controls (account-farming, bulk address probing, token guessing), not
 *    credential guards, and keying them by a submitted value would let an
 *    attacker evade them by simply rotating it — which is precisely the
 *    attack, in the `kdf` case.
 *
 * `kdf` is throttled for two reasons that are easy to miss because its
 * RESPONSE already gives nothing away (unknown addresses get a real-shaped
 * dummy). First, it is an unauthenticated endpoint that hits the database on
 * every call, so without a bound it is free amplification. Second, the
 * indistinguishability is statistical, not absolute: `handleGetKdfDescriptor`
 * equalises the work both branches do, but no server-side measure makes two
 * paths bit-identical in wall-clock terms, and a timing signal that small only
 * emerges from many samples per address. Denying the samples is what closes
 * the gap. Its traffic is genuinely low — a client fetches a descriptor on a
 * fresh login, and refresh tokens last 30 days — so the shared allowance is
 * not a burden on a household behind one NAT.
 */
import express from 'express';
import type { Express, Request, RequestHandler, Response } from 'express';
import type { AuthContext, AuthOutcome } from './auth-handlers.js';
import {
  handleChangePassphrase,
  handleDeleteAccount,
  handleGetAccount,
  handleGetKdfDescriptor,
  handleInviteLookup,
  handleLogin,
  handleLogout,
  handleRecover,
  handleRecoverRotate,
  handleRefresh,
  handleResetOpen,
  handleResetRequest,
  handleSignup,
  handleUpdateAccount,
} from './auth-handlers.js';
import { getRequestSession } from '../server/bearer-auth.js';
import { throttleKey, type ThrottleStore } from '../lib/throttle.js';
import { asFields } from './auth-input.js';
import { asString } from '../lib/json.js';

/** Mount prefix for the account endpoints. The sync endpoints live beside it under `/v1/sync`. */
export const AUTH_API_PREFIX = '/v1/auth';

/** Auth bodies are small; only the blob endpoint has any business being large. */
const AUTH_JSON_BODY_LIMIT = 64 * 1024;

export interface AuthRoutesOptions {
  ctx: AuthContext;
  throttle: ThrottleStore;
  /** The bearer middleware — injected so this module never reaches for a singleton. */
  requireAuth: RequestHandler;
}

/** Maps a handler outcome onto the wire. The only place status codes are chosen. */
function sendOutcome<T>(res: Response, outcome: AuthOutcome<T>): void {
  switch (outcome.status) {
    case 'ok':
      res.status(200).json(outcome.body);
      return;
    case 'created':
      res.status(201).json(outcome.body);
      return;
    case 'accepted':
      res.status(202).json(outcome.body);
      return;
    case 'no-content':
      res.status(204).end();
      return;
    case 'invalid':
      res.status(400).json({ error: outcome.reason });
      return;
    case 'unauthorized':
      res.status(401).json({ error: outcome.reason });
      return;
    case 'forbidden':
      res.status(403).json({ error: outcome.reason });
      return;
    case 'not-found':
      res.status(404).json({ error: outcome.reason });
      return;
    case 'conflict':
      res.status(409).json({ error: outcome.reason });
      return;
  }
}

/** `429` with a `Retry-After` in whole seconds, rounded up so a client never retries a millisecond too early. */
function sendThrottled(res: Response, retryAfterMs: number): void {
  const retryAfterSeconds = Math.max(1, Math.ceil(retryAfterMs / 1000));
  res.setHeader('Retry-After', String(retryAfterSeconds));
  res.status(429).json({ error: `too many attempts; try again in ${retryAfterSeconds}s` });
}

/**
 * `req.ip` is `undefined` only when Express cannot determine it at all; the
 * literal fallback keeps every such request in ONE bucket rather than
 * silently exempting them from the throttle.
 */
function clientIp(req: Request): string {
  return req.ip ?? 'unknown';
}

export function registerAuthRoutes(app: Express, options: AuthRoutesOptions): void {
  const { ctx, throttle, requireAuth } = options;
  const router = express.Router();
  // SCOPED TO THE PREFIX. See the module header: unscoped, this parser applies
  // to every path in the service and silently caps them all at 64 KB.
  router.use(AUTH_API_PREFIX, express.json({ limit: AUTH_JSON_BODY_LIMIT }));

  router.post(`${AUTH_API_PREFIX}/kdf`, async (req, res, next) => {
    try {
      const key = throttleKey({ namespace: 'kdf', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      // Counts every attempt. Keying this by the submitted address would be
      // worse than useless: probing many addresses is the attack, so a
      // per-address bucket would hand the attacker a fresh allowance for each
      // one he wants to test.
      throttle.recordFailure(key);
      sendOutcome(res, await handleGetKdfDescriptor({ email: asFields(req.body).email }, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/invite-lookup`, async (req, res, next) => {
    try {
      // By IP alone, and every attempt counts. Guessing invite tokens is the
      // attack, so a bucket keyed by the submitted token would hand out a fresh
      // allowance for every guess.
      const key = throttleKey({ namespace: 'invite-lookup', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      throttle.recordFailure(key);
      sendOutcome(res, await handleInviteLookup(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/signup`, async (req, res, next) => {
    try {
      const key = throttleKey({ namespace: 'signup', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      // Counts every attempt: this is a volume control, not a credential guard.
      throttle.recordFailure(key);
      sendOutcome(res, await handleSignup(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/login`, async (req, res, next) => {
    try {
      const submittedEmail = asString(asFields(req.body).email);
      const key = throttleKey({
        namespace: 'login',
        ip: clientIp(req),
        identifier: submittedEmail ?? undefined,
      });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }

      const outcome = await handleLogin(req.body, ctx);
      if (outcome.status === 'unauthorized') {
        throttle.recordFailure(key);
      } else if (outcome.status === 'ok') {
        throttle.clear(key);
      }
      sendOutcome(res, outcome);
    } catch (error) {
      next(error);
    }
  });

  // Both recovery routes share ONE throttle bucket per (IP, email), on
  // purpose: they authenticate the same secret, so letting an attacker spend a
  // fresh allowance on each would halve the cost of guessing it.
  const recoveryThrottleKey = (req: Request): string =>
    throttleKey({
      namespace: 'recover',
      ip: clientIp(req),
      identifier: asString(asFields(req.body).email) ?? undefined,
    });

  router.post(`${AUTH_API_PREFIX}/recover`, async (req, res, next) => {
    try {
      const key = recoveryThrottleKey(req);
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }

      const outcome = await handleRecover(req.body, ctx);
      // Counts every attempt, successful or not, and is never cleared. A
      // recovery is a once-in-an-account's-life event; a caller making a
      // second one within the window is far more likely to be guessing than
      // to be the owner.
      throttle.recordFailure(key);
      sendOutcome(res, outcome);
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/recover-rotate`, async (req, res, next) => {
    try {
      const key = recoveryThrottleKey(req);
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }

      const outcome = await handleRecoverRotate(req.body, ctx);
      throttle.recordFailure(key);
      sendOutcome(res, outcome);
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/reset/request`, async (req, res, next) => {
    try {
      // Per (IP, email), and NEVER cleared. A person forgets their password
      // once; a caller measuring the difference between a known and an unknown
      // address, or filling somebody's mailbox, does it thousands of times.
      const key = throttleKey({
        namespace: 'reset-request',
        ip: clientIp(req),
        identifier: asString(asFields(req.body).email) ?? undefined,
      });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      throttle.recordFailure(key);
      sendOutcome(res, await handleResetRequest(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/reset/open`, async (req, res, next) => {
    try {
      // By IP alone: the submitted value IS the secret being guessed, so a
      // bucket keyed by it would reset on every guess.
      const key = throttleKey({ namespace: 'reset-open', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      throttle.recordFailure(key);
      sendOutcome(res, await handleResetOpen(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/refresh`, async (req, res, next) => {
    try {
      sendOutcome(res, await handleRefresh(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/logout`, requireAuth, async (req, res, next) => {
    try {
      const session = getRequestSession(req);
      if (session === null) {
        res.status(401).json({ error: 'authentication required' });
        return;
      }
      sendOutcome(res, await handleLogout(session, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/change-passphrase`, requireAuth, async (req, res, next) => {
    try {
      const session = getRequestSession(req);
      if (session === null) {
        res.status(401).json({ error: 'authentication required' });
        return;
      }
      sendOutcome(res, await handleChangePassphrase({ accountId: session.accountId, body: req.body }, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.get(`${AUTH_API_PREFIX}/account`, requireAuth, async (req, res, next) => {
    try {
      const session = getRequestSession(req);
      if (session === null) {
        res.status(401).json({ error: 'authentication required' });
        return;
      }
      sendOutcome(res, await handleGetAccount({ accountId: session.accountId }, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.patch(`${AUTH_API_PREFIX}/account`, requireAuth, async (req, res, next) => {
    try {
      const session = getRequestSession(req);
      if (session === null) {
        res.status(401).json({ error: 'authentication required' });
        return;
      }
      sendOutcome(res, await handleUpdateAccount({ accountId: session.accountId, body: req.body }, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/delete`, requireAuth, async (req, res, next) => {
    try {
      const session = getRequestSession(req);
      if (session === null) {
        res.status(401).json({ error: 'authentication required' });
        return;
      }
      sendOutcome(res, await handleDeleteAccount({ accountId: session.accountId, body: req.body }, ctx));
    } catch (error) {
      next(error);
    }
  });

  app.use(router);
}
