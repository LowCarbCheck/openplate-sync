/**
 * CORS — wide open by design, and safe for exactly one reason.
 *
 * `Access-Control-Allow-Origin: *` is normally a smell. Here it is the point:
 * an openplate client is a separately deployed artifact, and any client
 * (ours, or a self-hoster's on their own domain, or a third-party
 * implementation written from PROTOCOL.md) must be able to talk to any
 * instance of this service. An origin allowlist would mean every self-hoster
 * editing server config to use their own client.
 *
 * What makes it safe is the absence of ambient credentials. This service
 * issues NO cookies and reads none; authentication is a bearer token the
 * client must attach deliberately. A hostile page can therefore issue a
 * cross-origin request and get an unauthenticated `401` — it has nothing to
 * authenticate with, because the browser has nothing to attach automatically.
 * That is precisely the CSRF property cookies lack.
 *
 * `Access-Control-Allow-Credentials` is deliberately NEVER sent. Adding it
 * would both be rejected by browsers alongside `*` and signal an intent
 * (cookie auth) this service must not develop.
 *
 * Hand-rolled rather than the `cors` package: eleven lines against a
 * dependency every self-hoster would have to trust.
 */
import type { NextFunction, Request, RequestHandler, Response } from 'express';

const ALLOWED_METHODS = 'GET, POST, PUT, DELETE, OPTIONS';
const ALLOWED_HEADERS = 'Authorization, Content-Type';
/** How long a browser may cache the preflight. 24h — the policy is static, so re-asking is pure latency. */
const PREFLIGHT_MAX_AGE_SECONDS = 86_400;

export function createCorsMiddleware(): RequestHandler {
  return function applyCors(req: Request, res: Response, next: NextFunction): void {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', ALLOWED_METHODS);
    res.setHeader('Access-Control-Allow-Headers', ALLOWED_HEADERS);
    res.setHeader('Access-Control-Max-Age', String(PREFLIGHT_MAX_AGE_SECONDS));

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  };
}
