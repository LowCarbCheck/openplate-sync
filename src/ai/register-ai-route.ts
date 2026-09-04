/**
 * Express glue for `POST /v1/chat/completions`.
 *
 * MOUNTED ONLY WHEN AN UPSTREAM IS CONFIGURED, and absent means the ordinary
 * unknown-path 404 rather than a 401 or a 503. The bargain is the one
 * `create-app.ts` already makes for the admin, share and research trees, for
 * the same reason: this service auto-deploys on push, so the commit that adds
 * the route is the commit that puts it in production, and an instance that
 * never configured an upstream must be indistinguishable from one where the
 * feature was never written.
 *
 * ORDER OF MIDDLEWARE IS LOAD-BEARING, and it is the reverse of the intuitive
 * one in one place:
 *
 *  1. `express.json()` with a body limit sized for a PHOTOGRAPH
 *     (`AI_MAX_REQUEST_BYTES`, default 8 MB). A plate scan is a base64 data
 *     URI, so this limit is the one that decides whether the feature works at
 *     all — the first version derived it from `MAX_BLOB_BYTES` and every real
 *     photograph got a 413.
 *  2. The BEARER GATE, before the limiter. The limiter keys on the resolved
 *     account (`ai/rate-limit.ts`), so mounting it first would leave it nothing
 *     to key on and it would fail closed on every request.
 *  3. The MINUTE LIMITER, before the handler. It is a burst guard in front of
 *     the daily quota: the quota decides how much of the operator's key an
 *     account may burn in a day, and this decides how fast. A client loop that
 *     retried on error would otherwise spend a whole day's allowance in ten
 *     seconds, and the first anybody would notice is somebody inexplicably out
 *     of requests at 09:00.
 */
import express from 'express';
import type { ErrorRequestHandler, Express, NextFunction, Request, Response } from 'express';
import { asString } from '../lib/json.js';
import { createChatCompletionsHandler, type ChatCompletionsDeps } from './proxy.js';
import { createAiRateLimit } from './rate-limit.js';

/** The one path this module owns. Outside `SYNC_API_PREFIX` on purpose: it is an OpenAI-compatible surface. */
export const CHAT_COMPLETIONS_PATH = '/v1/chat/completions';

export interface AiRouteOptions extends ChatCompletionsDeps {
  /** The bearer middleware, injected so this module never reaches for a singleton. */
  requireAuth: express.RequestHandler;
  /** Requests per account in any trailing 60 seconds (`AI_RATE_LIMIT_PER_MINUTE`). */
  perMinute: number;
  /**
   * The largest body this route accepts, in bytes (`AI_MAX_REQUEST_BYTES`,
   * default 8 MB). Sized for a camera photograph after base64, and DELIBERATELY
   * unrelated to `MAX_BLOB_BYTES`: see `Config.aiMaxRequestBytes` for the
   * regression that taught the difference.
   */
  maxRequestBytes: number;
}

/** `body-parser` marks its own failures with this `type`. */
const BODY_PARSER_TOO_LARGE = 'entity.too.large';
const BODY_PARSER_PARSE_FAILED = 'entity.parse.failed';

/** The one property this module reads off a `body-parser` failure. */
interface BodyParserError {
  readonly type?: string;
}

function bodyParserType(cause: unknown): string | null {
  // `Object()` boxes rather than narrows, so a non-object error simply has no
  // `type` and reads as `null`.
  const candidate: BodyParserError = Object(cause);
  return asString(candidate.type);
}

/** The OpenAI error envelope. */
interface OpenAiErrorBody {
  error: { message: string; type: string; code: string };
}

function openAiError(input: { message: string; code: string }): OpenAiErrorBody {
  return { error: { message: input.message, type: 'invalid_request_error', code: input.code } };
}

/**
 * The route's own error handler, and the reason it exists rather than leaning
 * on `server/error-middleware.ts`.
 *
 * EVERYWHERE ELSE IN THIS SERVICE AN ERROR IS `{"error": "<sentence>"}`, which
 * is what PROTOCOL.md §4 promises a sync client. This path is not a sync path:
 * it is an OpenAI-compatible surface, and the thing calling it is an
 * OpenAI-compatible client that reads `error.message` off an OBJECT. Handed
 * the sync shape, such a client reads `undefined` and shows the user nothing
 * at all — which is how a 413 on every plate photograph looks like the camera
 * silently doing nothing rather than like a limit being hit.
 *
 * Mounted on this router only, so the sync tree's shape is untouched. Anything
 * that is not a body-parser failure is passed along to the terminal handler,
 * which logs it and answers 500.
 */
function createAiErrorMiddleware(maxRequestBytes: number): ErrorRequestHandler {
  return function handleAiError(cause: unknown, _req: Request, res: Response, next: NextFunction): void {
    if (res.headersSent) {
      next(cause);
      return;
    }
    const type = bodyParserType(cause);
    if (type === BODY_PARSER_TOO_LARGE) {
      // The limit is NAMED. An operator reading a user's screenshot needs to
      // know which knob to turn, and `AI_MAX_REQUEST_BYTES` is the only one
      // that moves this.
      res.status(413).json(
        openAiError({
          message: `Request body exceeds the maximum accepted size of ${maxRequestBytes} bytes. The operator can raise AI_MAX_REQUEST_BYTES.`,
          code: 'request_too_large',
        }),
      );
      return;
    }
    if (type === BODY_PARSER_PARSE_FAILED) {
      // The input is NOT quoted back: it is a photograph.
      res.status(400).json(openAiError({ message: 'Request body is not valid JSON.', code: 'invalid_json' }));
      return;
    }
    next(cause);
  };
}

export function registerAiRoute(app: Express, options: AiRouteOptions): void {
  const router = express.Router();
  router.post(
    CHAT_COMPLETIONS_PATH,
    express.json({ limit: options.maxRequestBytes }),
    options.requireAuth,
    createAiRateLimit({ perMinute: options.perMinute }),
    createChatCompletionsHandler(options),
  );
  // AFTER the route, on the same router: Express only routes to a
  // four-argument handler once everything before it has passed an error along.
  router.use(createAiErrorMiddleware(options.maxRequestBytes));
  app.use(router);
}
