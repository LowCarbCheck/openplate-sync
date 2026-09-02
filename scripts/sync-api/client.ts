/**
 * The `sync-api` transport: one `fetch` per command, and a deliberately deaf
 * ear for what comes back on a failure.
 *
 * ── IT READS NOTHING FROM DISK, AND THAT IS ENFORCED ────────────────────────
 * No config module, no store, no `pg`, no `drizzle-orm`, no `node:fs`. The
 * whole client is a base URL and a bearer token handed in by the caller, so
 * `sync-api` runs from a laptop that has never seen the database — which is
 * the property `shw-api`, `np-api` and `lcc-api` have and the reason an
 * operator can act on production without production credentials.
 * `tests/unit/sync-api-no-db-imports.test.ts` walks the static import graph
 * from the entrypoint and fails if that ever stops being true. The one
 * exception is `src/lib/json.ts`, which is a pure decoder module with no
 * dependencies at all.
 *
 * ── A FAILURE RESPONSE BODY IS NEVER READ, LET ALONE PRINTED ────────────────
 * This service's own error bodies are scrubbed sentences, but `--url` points
 * wherever the operator says: a reverse proxy, a captive portal, a typo that
 * lands on something else entirely. Those quote the request they rejected, and
 * on THIS API a quoted request or response can carry an account handle. An
 * operator pastes a CLI error into a chat window without thinking about it.
 *
 * So the status code is the only thing taken from a non-2xx response. The body
 * is not read at all rather than read-and-discarded: a value that was never in
 * a variable cannot be added to a message by a later edit.
 *
 * ── THE ADMIN TOKEN NEVER APPEARS IN ANY STRING BUILT HERE ──────────────────
 * It goes into one `Authorization` header and nowhere else. Not in an error,
 * not echoed back on a 401, not in the "could not reach" message. A CLI that
 * quoted the credential it just sent would put it in the operator's scrollback
 * and, from there, in the issue they open.
 */
import type { JsonValue } from '../../src/lib/json.js';

/** Everything `sync-api` reports to the operator is one of these. */
export class CliError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CliError';
  }
}

/** The verbs the admin API actually uses. Anything else is a typo, not a feature. */
export type HttpMethod = 'GET' | 'POST' | 'DELETE';

/** The body of a mint request. The only request in this CLI that sends one. */
export interface MintInviteRequestBody {
  note: string | null;
  expiresInDays?: number;
}

export interface AdminRequest {
  readonly method: HttpMethod;
  /** Absolute path on the service, e.g. `/v1/admin/accounts`. */
  readonly path: string;
  /** Sent as JSON on a `POST`. Never carries a credential — the token stays in the header. */
  readonly body?: MintInviteRequestBody;
}

export interface AdminClientOptions {
  readonly baseUrl: string;
  readonly adminToken: string;
  /** Injected in tests; the entrypoint passes the global. */
  readonly fetchImpl?: typeof fetch;
}

/**
 * A status the operator can act on, without quoting anything the far end said.
 *
 * 401 names the environment variable, because that is the one thing they can
 * change. It does not say whether the token was absent, stale or simply wrong
 * — that is the same indistinguishability the server-side auth keeps, and
 * undoing it on the client would be a strange place to give it back.
 *
 * 404 has TWO meanings here and the message says both: either the account id
 * does not exist, or this instance has no admin API at all, because
 * `/v1/admin` answers 404 when `ADMIN_TOKEN` is unset ON THE SERVER. That
 * ambiguity is the feature, not a gap in the message.
 */
function describeStatus(status: number, method: HttpMethod, path: string): string {
  const where = `${method} ${path}`;
  if (status === 401) {
    return `The service rejected the admin token (401 on ${where}). Check ADMIN_TOKEN — it must be the same value the service was started with.`;
  }
  if (status === 404) {
    // The subject differs per resource, and on the invite tree 404 carries a
    // third meaning worth naming: a REDEEMED invite refuses revocation,
    // because the row is the audit record of where an account came from.
    const subject = path.startsWith('/v1/admin/invites')
      ? 'that invite does not exist or has already been redeemed (a redeemed invite is kept, and cannot be revoked)'
      : 'that account does not exist';
    return `The service answered 404 for ${where}. Either ${subject}, or this instance has no admin API — /v1/admin answers 404 when ADMIN_TOKEN is unset on the server.`;
  }
  if (status === 400) {
    return `The service rejected ${where} as invalid (400). Check --limit and --offset (a limit is 0–200, an offset a whole number) and --expires-in-days (1–365).`;
  }
  if (status === 429) {
    return `The service rate-limited ${where} (429). Wait a minute and try again.`;
  }
  return `The service answered ${status} for ${where}. Its own log has the reason — this message deliberately does not quote the response body.`;
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, '')}${path}`;
}

export class AdminClient {
  private readonly baseUrl: string;
  private readonly adminToken: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: AdminClientOptions) {
    this.baseUrl = options.baseUrl;
    this.adminToken = options.adminToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  /**
   * One request, one decoded JSON answer. `204` (the shape a deletion
   * returns) decodes as `null`.
   */
  async request(request: AdminRequest): Promise<JsonValue> {
    const url = joinUrl(this.baseUrl, request.path);
    const response = await this.send(url, request.method, request.body);

    if (!response.ok) {
      // The body is NOT read. See the module header — this is the whole point.
      throw new CliError(describeStatus(response.status, request.method, request.path));
    }
    return this.readJson(response, url);
  }

  private async send(url: string, method: HttpMethod, body?: MintInviteRequestBody): Promise<Response> {
    // Named rather than an open dictionary, so the one header that carries the
    // credential is part of a fixed shape and cannot be joined by a key some
    // later edit computes.
    const headers = {
      // THE ONLY PLACE THE ADMIN TOKEN IS EVER WRITTEN. See the module header.
      Authorization: `Bearer ${this.adminToken}`,
      Accept: 'application/json',
      ...(body === undefined ? undefined : { 'Content-Type': 'application/json' }),
    } satisfies HeadersInit;

    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      // The transport error is discarded rather than quoted: undici's message
      // is "fetch failed" plus a cause chain that has, on occasion, carried
      // the request headers — which here would be the admin token. The
      // address is ours and is worth naming; nothing else from that error is.
      throw new CliError(
        `Could not reach the service at ${url}. Is it running, and is --url (or SYNC_SERVER_URL) right?`,
      );
    }
  }

  private async readJson(response: Response, url: string): Promise<JsonValue> {
    const raw = await response.text();
    if (raw === '') return null;
    try {
      // SAFETY: `JSON.parse` returns exactly the `JsonValue` union by
      // definition; the shape underneath is unproven and is decoded by
      // `views.ts` before anything reads a field.
      return JSON.parse(raw) as JsonValue;
    } catch {
      // A 2xx that is not JSON means the URL reached something that is not
      // this service — an HTML login page from a reverse proxy is the usual
      // one. The text is not quoted, for the same reason an error body is not.
      throw new CliError(
        `${url} answered with something that is not JSON. That address is probably not an openplate-sync instance.`,
      );
    }
  }
}
