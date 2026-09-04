/**
 * Authentication for the admin API — TWO credentials, one gate.
 *
 * 1. **The static `ADMIN_TOKEN`**, the operator's break-glass credential. It
 *    belongs to whoever runs the container, is not an account, and works when
 *    every account on the instance is locked out. Unchanged since M166 except
 *    that it is now optional in a stronger sense: see the 404 rule below.
 * 2. **An admin ACCOUNT's own access token** (M192). The admin console lives
 *    in the client at `/admin`, behind the same sign-in as everything else, so
 *    the person using it holds a session and not a shell variable. `role` is
 *    `'admin'` and the account is not suspended, or it is not a credential.
 *
 * SAME TIMING DISCIPLINE AS `bearer-auth.ts`, FOR A BIGGER PRIZE. One admin
 * credential lists every account on the instance and erases any of them, so it
 * is worth more to an attacker than any single user's session. `===` returns
 * at the first differing character, which is a prefix oracle; `timingSafeEqual`
 * on the raw strings throws on unequal lengths, which is a length oracle.
 * Hashing both sides first makes every candidate exactly 32 bytes, so neither
 * is observable.
 *
 * ONE SENTENCE FOR ABSENT, MALFORMED AND WRONG ALIKE. A distinct "malformed"
 * would describe the shape of a valid credential; a distinct "unknown token"
 * would confirm that what was presented parsed as one, which lets a guessing
 * loop tell "close" from "wrong". The three cases are told apart in the LOG,
 * where the operator debugging their own paste can see it, and never in the
 * response.
 *
 * WHY ADMIN FAILURES ARE LOGGED WHEN USER `401`s ARE NOT. A user 401 is
 * routine — a stale access token in a phone that has been asleep. An admin 401
 * is not: nobody but an administrator has any business calling `/v1/admin`, so
 * every failure is either a fumbled paste or somebody probing. The line
 * carries the method, the path and the caller's address. It NEVER carries the
 * presented value, nor a prefix of it, nor its length.
 *
 * ── 404 WHEN NOTHING IS CONFIGURED, 401 WHEN SOMETHING IS ───────────────────
 * The tree is now MOUNTED ALWAYS, because an admin account may exist and no
 * mount-time branch can know that. The indistinguishability ADR-0001 bought is
 * preserved here instead:
 *
 *  - No `ADMIN_TOKEN` configured, and the bearer is not an admin account →
 *    the ordinary unknown-path 404, exactly as an unmounted tree answered.
 *    A prober on a fresh deployment cannot tell this service has an admin
 *    surface at all.
 *  - `ADMIN_TOKEN` configured, and the credential is wrong → 401, exactly as
 *    a mounted tree answered before. The operator who set the variable already
 *    knows the surface is there.
 *  - A suspended admin account → `403 account-suspended`, not 401 and not 404.
 *    They have proved who they are; the honest answer is why the door is shut.
 *
 * ── WHICH PRINCIPAL AUTHENTICATED, AND WHY THE ROUTES NEED TO KNOW ──────────
 * The self-change guard (`400 self-change`) stops an admin suspending,
 * demoting or deleting THEMSELVES: an organization with one administrator who
 * demotes their own account has locked everybody out of `/v1/admin`, and the
 * remedy is a shell on the container. The static `ADMIN_TOKEN` has no self, so
 * it is exempt by construction rather than by an exception — it is the
 * break-glass credential that exists for exactly the situation the guard
 * prevents.
 *
 * The principal hangs off a `WeakMap` keyed by the request, for the same reason
 * `bearer-auth.ts` does it: declaration-merging Express's `Request` would make
 * the field appear on EVERY request in the type system, including the ones that
 * never went through this middleware.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { parseBearerHeader } from '../lib/tokens.js';
import { ACCOUNT_SUSPENDED, resolveAccessToken, type AuthContext } from '../accounts/auth-handlers.js';
import { handleNotFound } from './error-middleware.js';
import type { Logger } from '../logger.js';

/** The one sentence every rejection gets. Deliberately identical across all three failure modes. */
const REJECTION_MESSAGE = 'admin authentication required';

/**
 * Who is holding the admin credential on this request.
 *
 * `static` is the operator's break-glass token, which belongs to whoever runs
 * the container and is not an account: it has no self, so no self-change guard
 * applies to it.
 */
export type AdminPrincipal = { kind: 'static' } | { kind: 'account'; accountId: number };

const principalsByRequest = new WeakMap<Request, AdminPrincipal>();

/** The principal `createAdminAuthMiddleware` attached, or `null` on a request that never passed it. */
export function getAdminPrincipal(req: Request): AdminPrincipal | null {
  return principalsByRequest.get(req) ?? null;
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export interface CreateAdminAuthOptions {
  /**
   * The operator's static break-glass credential, already length-validated by
   * `parseConfig`, or `null` when this instance has none — which is the
   * default and what every deployment gets until somebody sets the variable.
   */
  adminToken: string | null;
  /** Resolves a presented bearer as an account, so an admin's own session can authenticate. */
  authContext: AuthContext;
  logger: Logger;
}

export function createAdminAuthMiddleware(options: CreateAdminAuthOptions): RequestHandler {
  // Hashed once, at construction. The per-request cost is one hash and one
  // fixed-size comparison.
  const expectedDigest = options.adminToken === null ? null : digest(options.adminToken);
  const { authContext, logger } = options;

  /**
   * The refusal, chosen by whether this instance admits to having an admin
   * surface at all. See the module header for why the two differ.
   *
   * THE LOG FOLLOWS THE SAME BRANCH AS THE STATUS, and that is not a detail.
   * An instance with no static token answers the ordinary 404 and writes
   * NOTHING, exactly as an unmounted tree did before M192: there is no admin
   * surface here to protect, so a probe is not a security event, and logging
   * one would let anybody fill an unconfigured operator's log by curling a
   * path. An instance that HAS configured a credential logs every failure,
   * because nobody but the operator has business calling `/v1/admin` there.
   */
  function refuse(req: Request, res: Response, reason: string): void {
    if (expectedDigest === null) {
      handleNotFound(req, res);
      return;
    }
    logger.warn('Admin request rejected', {
      method: req.method,
      path: req.path,
      remoteAddress: req.ip ?? null,
      reason,
    });
    res.status(401).json({ error: REJECTION_MESSAGE });
  }

  return function requireAdmin(req: Request, res: Response, next: NextFunction): void {
    const presented = parseBearerHeader(req.header('authorization') ?? undefined);
    if (presented === null) {
      refuse(req, res, 'no bearer token');
      return;
    }

    // The static token first, and without a database round trip: it is the
    // credential that must keep working when Postgres is the thing that is
    // broken.
    if (expectedDigest !== null && timingSafeEqual(digest(presented), expectedDigest)) {
      principalsByRequest.set(req, { kind: 'static' });
      next();
      return;
    }

    // Express 4 does not await a handler, so the async work is wrapped here
    // and every rejection is handed to `next` explicitly.
    void (async () => {
      try {
        const resolution = await resolveAccessToken(presented, authContext);
        if (resolution.status === 'suspended') {
          logger.warn('Admin request rejected', {
            method: req.method,
            path: req.path,
            remoteAddress: req.ip ?? null,
            reason: 'account suspended',
          });
          res.status(403).json({ error: ACCOUNT_SUSPENDED });
          return;
        }
        if (resolution.status !== 'valid') {
          refuse(req, res, 'token mismatch');
          return;
        }

        const account = await authContext.store.findAccountById(resolution.session.accountId);
        // A MEMBER'S VALID SESSION IS NOT A CREDENTIAL HERE, and it gets the
        // same answer a garbage token gets. Saying "you are signed in but not
        // an admin" would confirm to any account holder that the surface
        // exists and is worth attacking from a different angle.
        if (account === null || account.role !== 'admin') {
          refuse(req, res, 'account is not an admin');
          return;
        }

        principalsByRequest.set(req, { kind: 'account', accountId: account.id });
        next();
      } catch (cause) {
        next(cause);
      }
    })();
  };
}
