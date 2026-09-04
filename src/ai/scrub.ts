/**
 * The last line of defence for the privacy promise: a scrubber every string
 * that could have touched a request runs through before it is logged or
 * returned.
 *
 * WHY THIS EXISTS EVEN THOUGH NO CALL SITE LOGS A BODY. Our own call sites are
 * disciplined — `logger.ts`'s field type will not even accept a Buffer. The gap
 * is somebody ELSE's string: a dependency that helpfully includes the input it
 * choked on in its `Error.message`, an upstream provider that echoes the
 * request it rejected, a future contributor who adds one `${error}`. On the
 * happy path none of that fires, which is precisely why the happy path passing
 * proves nothing.
 *
 * A PROXY MAKES THIS SHARPER THAN IT IS IN A NORMAL SERVICE. The body being
 * protected is a plate photograph this service did not produce and does not
 * keep, and the component most likely to quote it back is the upstream
 * provider — the exact string a debugging instinct most wants to log verbatim
 * when a call fails.
 *
 * So: scrub at the boundary, and let a test prove it by throwing an error that
 * DOES carry the base64 and asserting the bytes appear in neither the log lines
 * nor the response body.
 *
 * Ported from `openplate-gateway/src/scrub.ts` with its zod `safeParse`
 * replaced by this repo's `asString` (`lib/json.ts`), which is the same check
 * without the dependency.
 */
import { asString, type JsonValue } from '../lib/json.js';

const REDACTED = '[redacted]';

/**
 * A data URI of any media type. The payload class deliberately excludes
 * whitespace: a real data URI contains none, and including `\s` here made the
 * match run past the URI and eat the rest of the sentence, which destroys the
 * message a human is meant to read.
 */
const DATA_URI = /data:[a-zA-Z0-9.+/-]+;base64,[A-Za-z0-9+/=]+/g;

/**
 * A bare base64-ish run. 48 characters is well below any real image payload and
 * well above any identifier this service logs (a family id is 32 hex, a UUID is
 * 36), so this cannot eat a field somebody wanted to read.
 */
const LONG_BASE64_RUN = /[A-Za-z0-9+/=]{48,}/g;

/** Replaces data URIs and long base64 runs with a marker. Idempotent. */
export function scrubPayloads(text: string): string {
  return text.replace(DATA_URI, REDACTED).replace(LONG_BASE64_RUN, REDACTED);
}

/**
 * A scrubbed one-line description of an unknown thrown value, safe to log.
 *
 * Never includes a stack (a stack can quote source lines) and never the `cause`
 * chain (which is where a wrapped library error's echoed input hides).
 *
 * `cause: unknown` is the honest annotation and it is what forces the two
 * checks below: the value reaching here was produced by `throw`, JS permits
 * throwing anything, and this function's whole job is to be right about values
 * nobody promised anything about. The parameter is named `cause` for the same
 * reason `lib/storage-conflict.ts` and `server/error-middleware.ts` name theirs
 * that way: it is a caught throw, not a parsed input.
 */
export function describeError(cause: unknown): string {
  if (cause instanceof Error) return scrubPayloads(cause.message);
  // SAFETY: a thrown value is `unknown` and this widens it to the boundary type
  // `lib/json.ts` decodes. `asString` is TOTAL over that type — it answers
  // `null` for anything that is not a string, which is the fallback below — so
  // the assertion cannot make the decoder wrong, only let it run.
  const asText = asString(cause as JsonValue);
  return asText === null ? 'unknown error' : scrubPayloads(asText);
}
