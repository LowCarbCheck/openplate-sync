/**
 * Bearer-token authentication middleware, and the bridge from this service's
 * accounts to the sync handler cores' `resolveEntitledUser` contract.
 *
 * NO COOKIES, ANYWHERE. The token travels in `Authorization: Bearer <token>`
 * so that any openplate client — ours, or a self-hoster's on a completely
 * different origin — can talk to any instance of this service. That is what
 * makes `Access-Control-Allow-Origin: *` safe here: with no ambient
 * credential attached to the request, a hostile page can issue a cross-origin
 * call but has nothing to authenticate it with, so CSRF has no purchase.
 *
 * The resolved session hangs off a `WeakMap` keyed by the request rather than
 * a mutated `req.session` property. Declaration-merging Express's `Request`
 * would make the field appear on EVERY request in the type system, including
 * unauthenticated ones, which is exactly the confusion this middleware
 * exists to prevent.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { parseBearerHeader } from '../lib/tokens.js';
import {
  ACCOUNT_SUSPENDED,
  resolveAccessToken,
  type AuthContext,
  type ResolvedSession,
} from '../accounts/auth-handlers.js';
import type { SyncEntitledUser } from '../contract-types.js';

const sessionsByRequest = new WeakMap<Request, ResolvedSession>();

/** The session attached by `createBearerAuthMiddleware`, or `null` on an unauthenticated request. */
export function getRequestSession(req: Request): ResolvedSession | null {
  return sessionsByRequest.get(req) ?? null;
}

/**
 * Rejects with `401` unless the request carries a live access token. Absent,
 * malformed, unknown, expired and revoked tokens are all the same `401` with
 * the same message — telling them apart tells an attacker which guesses were
 * close.
 *
 * A SUSPENDED ACCOUNT IS A `403`, NOT A `401`, and the distinction is the
 * whole reason `resolveAccessToken` returns three answers instead of two. A
 * `401` means "sign in again", and a client that got one for a suspension
 * would try, fail at the login door with a different status, and have learned
 * nothing it could show the person. `403 account-suspended` is the one answer
 * that lets a client say what happened.
 */
export function createBearerAuthMiddleware(ctx: AuthContext): RequestHandler {
  return function requireAuth(req: Request, res: Response, next: NextFunction): void {
    const rawToken = parseBearerHeader(req.header('authorization') ?? undefined);
    if (rawToken === null) {
      res.status(401).json({ error: 'authentication required' });
      return;
    }

    // Express 4 does not await a handler, so the async work is wrapped here
    // and every rejection is handed to `next` explicitly.
    void (async () => {
      try {
        const resolution = await resolveAccessToken(rawToken, ctx);
        if (resolution.status === 'suspended') {
          res.status(403).json({ error: ACCOUNT_SUSPENDED });
          return;
        }
        if (resolution.status !== 'valid') {
          res.status(401).json({ error: 'authentication required' });
          return;
        }
        sessionsByRequest.set(req, resolution.session);
        next();
      } catch (cause) {
        next(cause);
      }
    })();
  };
}

/**
 * The `SyncHostContext.resolveEntitledUser` implementation for the standalone
 * service.
 *
 * It reads the session the middleware already attached rather than
 * re-resolving the token — the sync routes are mounted BEHIND
 * `createBearerAuthMiddleware`, so an unauthenticated caller never reaches
 * them and gets a `401` instead of the `403` this function's `null` would
 * produce. The `null` branch stays because the handler cores' contract
 * demands it, and because a future entitlement rule (a paid tier, a
 * per-account quota) is exactly what it is for.
 */
export function createEntitledUserResolver(): (req: Request) => Promise<SyncEntitledUser | null> {
  return async (req: Request): Promise<SyncEntitledUser | null> => {
    const session = getRequestSession(req);
    return session === null ? null : { userId: session.accountId };
  };
}
