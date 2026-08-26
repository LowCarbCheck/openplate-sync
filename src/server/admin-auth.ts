/**
 * Bearer authentication for the admin API — the operator's credential, not a
 * user's. Ported in substance from `openplate-gateway/src/server/admin-auth.ts`,
 * because the reasoning is the same and two divergent implementations of one
 * timing discipline would be two chances to get it wrong.
 *
 * SAME TIMING DISCIPLINE AS `bearer-auth.ts`, FOR A BIGGER PRIZE. One admin
 * token lists every account on the instance and erases any of them, so it is
 * worth more to an attacker than any single user's session. `===` returns at
 * the first differing character, which is a prefix oracle; `timingSafeEqual`
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
 * is not: nobody but the operator has any business calling `/v1/admin`, so
 * every failure is either a fumbled paste or somebody probing. The line
 * carries the method, the path and the caller's address. It NEVER carries the
 * presented value, nor a prefix of it, nor its length.
 *
 * IT IS NEVER MOUNTED WHEN THERE IS NO TOKEN. `create-app.ts` answers 404 for
 * the whole `/v1/admin` tree in that case, so this middleware always has
 * something to compare against and never has to decide what "no configured
 * token" means.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { parseBearerHeader } from '../lib/tokens.js';
import type { Logger } from '../logger.js';

/** The one sentence every rejection gets. Deliberately identical across all three failure modes. */
const REJECTION_MESSAGE = 'admin authentication required';

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export interface CreateAdminAuthOptions {
  adminToken: string;
  logger: Logger;
}

export function createAdminAuthMiddleware(options: CreateAdminAuthOptions): RequestHandler {
  // Hashed once, at construction. The per-request cost is one hash and one
  // fixed-size comparison.
  const expectedDigest = digest(options.adminToken);
  const { logger } = options;

  return function requireAdminToken(req: Request, res: Response, next: NextFunction): void {
    const presented = parseBearerHeader(req.header('authorization') ?? undefined);
    if (presented === null) {
      logger.warn('Admin request rejected', {
        method: req.method,
        path: req.path,
        remoteAddress: req.ip ?? null,
        reason: 'no bearer token',
      });
      res.status(401).json({ error: REJECTION_MESSAGE });
      return;
    }

    if (!timingSafeEqual(digest(presented), expectedDigest)) {
      logger.warn('Admin request rejected', {
        method: req.method,
        path: req.path,
        remoteAddress: req.ip ?? null,
        reason: 'token mismatch',
      });
      res.status(401).json({ error: REJECTION_MESSAGE });
      return;
    }

    next();
  };
}
