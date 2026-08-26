/**
 * Express 4 does not catch a rejected promise from a route handler.
 *
 * It does not log it, does not answer, and does not time out: the request hangs
 * until the client gives up, and the only trace is an unhandled-rejection
 * warning on stderr that nobody is watching. Every handler that awaits anything
 * must therefore hand its rejection to `next` explicitly, so a failed store read
 * becomes an ordinary 500 through `error-middleware.ts` — the one path that
 * scrubs before it logs.
 *
 * The routers written before this helper existed (`register-routes.ts`,
 * `register-auth-routes.ts`) do the same thing inline, one try/catch per route.
 * This is that pattern named once, and it is what `admin-routes.ts` uses;
 * borrowed from `openplate-gateway/src/server/async-handler.ts`, where it has
 * the same job.
 *
 * `void` plus try/catch rather than `.catch(next)`, because calling a callback
 * from inside a promise callback is exactly the shape that swallows a second
 * throw: if `next` itself threw, the rejection would vanish into the chain.
 */
import type { Request, RequestHandler, Response } from 'express';

export function asyncHandler(handler: (req: Request, res: Response) => Promise<void>): RequestHandler {
  return (req, res, next) => {
    void (async (): Promise<void> => {
      try {
        await handler(req, res);
      } catch (error) {
        next(error);
      }
    })();
  };
}
