/**
 * Express glue for the `/v1/auth/*` endpoints — mapping only. Every decision
 * lives in `auth-handlers.ts`; this file turns a typed `AuthOutcome` into a
 * status code and wires the per-IP throttle, which is the one concern that
 * genuinely needs the request object (`req.ip`).
 *
 * `express.json()` is applied to THIS router only, with a small limit. The
 * blob router mounts its own, far larger one (`server/register-routes.ts`) —
 * a 2 MiB body limit has no business anywhere near a login endpoint.
 *
 * THROTTLE POLICY, per route and deliberately different:
 *  - **login** — keyed by IP **and** email, cleared on success. Slows a
 *    single-source brute force without letting anyone lock a victim out of
 *    their own account from a different IP.
 *  - **signup**, **request-reset** and **kdf** — keyed by IP ALONE, and every
 *    attempt counts, successful or not. These are volume controls
 *    (account-farming, mail-bombing a third party's inbox, bulk address
 *    probing), not credential guards, and keying them by the submitted email
 *    would let an attacker evade them by simply rotating addresses — which is
 *    precisely the attack, in the `kdf` case.
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
  handleLogin,
  handleLogout,
  handleRefresh,
  handleRequestReset,
  handleResetCredential,
  handleSignup,
  handleVerifyEmail,
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
      res.status(202).json({});
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
  router.use(express.json({ limit: AUTH_JSON_BODY_LIMIT }));

  router.post(`${AUTH_API_PREFIX}/kdf`, async (req, res, next) => {
    try {
      const key = throttleKey({ namespace: 'kdf', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      // Counts every attempt. Keying this by the submitted email would be
      // worse than useless: probing many addresses is the attack, so a
      // per-email bucket would hand the attacker a fresh allowance for each
      // one he wants to test.
      throttle.recordFailure(key);
      sendOutcome(res, await handleGetKdfDescriptor({ email: asFields(req.body).email }, ctx));
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

  router.post(`${AUTH_API_PREFIX}/verify-email`, async (req, res, next) => {
    try {
      sendOutcome(res, await handleVerifyEmail(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/request-reset`, async (req, res, next) => {
    try {
      const key = throttleKey({ namespace: 'reset', ip: clientIp(req) });
      const decision = throttle.check(key);
      if (decision.locked) {
        sendThrottled(res, decision.retryAfterMs);
        return;
      }
      // Counts every attempt: this endpoint sends mail to an address the
      // caller chose, so its abuse case is a third party's inbox.
      throttle.recordFailure(key);
      sendOutcome(res, await handleRequestReset(req.body, ctx));
    } catch (error) {
      next(error);
    }
  });

  router.post(`${AUTH_API_PREFIX}/reset`, async (req, res, next) => {
    try {
      sendOutcome(res, await handleResetCredential(req.body, ctx));
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
