/**
 * The terminal error handler — and the reason it is not optional.
 *
 * PROTOCOL.md §4 promises that EVERY non-2xx body is `{"error": "..."}`.
 * Express's default handler does not honour that: an oversize body raised by
 * `body-parser` produces an HTML error page with a stack trace in
 * development, and a bare status line otherwise. A third-party client written
 * against the spec would receive HTML where it was told to expect JSON, on
 * precisely the two failure paths (`413`, `400` parse) that a client is most
 * likely to hit in the field.
 *
 * The oversize case matters twice over, because `register-routes.ts`
 * deliberately sets `JSON_BODY_LIMIT` ABOVE `MAX_BLOB_BYTES` — base64 inflates
 * by 4/3, so a body limit set at the raw cap would reject legitimate
 * maximum-size blobs before any handler saw them. That means a `413` can
 * arrive from two different places (body-parser for a genuinely enormous
 * body, the push handler for a decoded blob over the cap) and both must look
 * identical on the wire. This middleware is what makes that true.
 *
 * Nothing internal is ever echoed to the client: unexpected errors are logged
 * server-side with a scrubbed message and answered with a fixed sentence.
 */
import type { ErrorRequestHandler, NextFunction, Request, Response } from 'express';
import type { Logger } from '../logger.js';
import { asString } from '../lib/json.js';

/** `body-parser` marks its own failures with a `type` field; these are the two that carry protocol meaning. */
const BODY_PARSER_TOO_LARGE = 'entity.too.large';
const BODY_PARSER_PARSE_FAILED = 'entity.parse.failed';

/** The one property this module reads off a `body-parser` failure. */
interface BodyParserError {
  readonly type?: string;
}

/**
 * The `type` discriminator `body-parser` puts on its own failures, or `null`
 * for anything else. `Object()` boxes rather than narrows, so a non-object
 * error simply has no `type` and reads as `null`.
 */
function bodyParserType(cause: unknown): string | null {
  const candidate: BodyParserError = Object(cause);
  return asString(candidate.type);
}

/**
 * Terminal error middleware. Must be registered LAST, after every router —
 * Express only routes to a four-argument handler once everything before it
 * has passed the error along.
 */
export function createErrorMiddleware(logger: Logger): ErrorRequestHandler {
  return function handleError(cause: unknown, req: Request, res: Response, next: NextFunction): void {
    // Headers already flushed means a handler partially responded and then
    // failed; there is no valid JSON to send, so hand it back to Express to
    // destroy the socket.
    if (res.headersSent) {
      next(cause);
      return;
    }

    const type = bodyParserType(cause);
    if (type === BODY_PARSER_TOO_LARGE) {
      res.status(413).json({ error: 'request body exceeds the maximum accepted size' });
      return;
    }
    if (type === BODY_PARSER_PARSE_FAILED) {
      res.status(400).json({ error: 'request body is not valid JSON' });
      return;
    }

    logger.error('Unhandled request error', {
      method: req.method,
      path: req.path,
      error: cause instanceof Error ? cause.message : 'unknown error',
    });
    res.status(500).json({ error: 'internal server error' });
  };
}

/** 404 in the documented shape, so an unknown path does not fall through to Express's HTML default either. */
export function handleNotFound(_req: Request, res: Response): void {
  res.status(404).json({ error: 'no such endpoint' });
}
