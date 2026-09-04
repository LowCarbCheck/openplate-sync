/**
 * Environment → typed config, with a PURE parser (`parseConfig`) so the
 * validation rules are unit-testable without touching `process.env`.
 *
 * FAIL FAST, ALWAYS. Every misconfiguration below throws at boot rather than
 * degrading: a service that starts with a weak `SERVER_SECRET` or an absent
 * `DATABASE_URL` would take real accounts before anyone noticed. A container
 * that refuses to start is a five-minute incident; one that silently accepts
 * signups it can't authenticate later is not.
 *
 * `.env.example` is the operator-facing counterpart to this file and must be
 * kept in step with it.
 */
import { isLogLevel, type LogLevel } from './logger.js';
import { INSTANCE_LANGUAGES, isInstanceLanguage, type InstanceLanguage, type OperatorNotice } from './protocol.js';
import type { HttpMailConfig } from './mail/mailer.js';
import type { AiUpstreamConfig } from './ai/proxy.js';

/**
 * Minimum accepted `SERVER_SECRET` length. 32 characters is the shortest
 * value that carries ~128 bits when generated the way `.env.example` tells
 * operators to (`openssl rand -hex 32` gives 64). This is a real gate: the
 * verifier pepper derived from it is the only thing standing between a
 * stolen `accounts` table and offline verification of guessed auth-hashes.
 */
export const MIN_SERVER_SECRET_LENGTH = 32;

/**
 * Minimum accepted `ADMIN_TOKEN` length, matching `openplate-gateway`'s
 * `MIN_ADMIN_TOKEN_LENGTH`. This credential lists every account on the
 * instance and erases any of them, so it is worth more to an attacker than
 * any single user's session: it must be GENERATED, not chosen, and 24
 * characters is the shortest length at which a generated value is not worth
 * guessing. A too-short value is a boot failure rather than a warning — see
 * the module header.
 */
export const MIN_ADMIN_TOKEN_LENGTH = 24;

/**
 * Longest accepted `SYNC_NOTICE`, in characters.
 *
 * THE CAP IS NOT TIDINESS. The notice is published on `GET /health`, which is
 * this container's own HEALTHCHECK path (`bay-sprqvntrs` sets
 * `healthcheck_path: /health`) and is therefore polled continuously, forever.
 * An unbounded string there is a payload the operator inflicts on their own
 * instance. 280 characters is enough for "we are moving on 1 March, details at
 * the link" and short enough that nobody is tempted to publish a changelog.
 *
 * Over-long is a BOOT FAILURE, not a truncation: silently cutting a shutdown
 * notice in half would ship a sentence the operator never wrote.
 */
export const MAX_SYNC_NOTICE_LENGTH = 280;

/** Schemes a `SYNC_NOTICE_URL` may use. Anything else (`javascript:`, `data:`) is a boot failure, never a rendered link. */
const NOTICE_URL_SCHEMES = ['https:', 'http:'];

export interface ServiceConfig {
  port: number;
  databaseUrl: string;
  databaseSsl: boolean;
  /** Root secret; `lib/server-secrets.ts` derives the domain-separated subkeys from it. Never used directly. */
  serverSecret: string;
  /** What this instance calls itself on the handshake and in its mail. `INSTANCE_NAME`, default `openplate`. */
  instanceName: string;
  /** Which language its two letters are written in. `INSTANCE_LANGUAGE`, `en` or `de`, default `en`. */
  instanceLanguage: InstanceLanguage;
  /**
   * This service's own public base URL, or `null`. It goes into the `server=`
   * fragment of a join or reset link, so a person who clicks one lands on a
   * client already pointed at the right instance.
   *
   * Optional because a self-hosted instance reached only over a tailnet has no
   * public URL, and inventing one would produce a link that goes nowhere. A
   * link is then simply not built and the raw token is returned instead.
   */
  serverPublicUrl: string | null;
  /**
   * Where the openplate client lives, or `null`. The other half of a link.
   *
   * IT CAME BACK FROM THE DEAD, AND THAT IS DELIBERATE. M181 made this name a
   * BOOT FAILURE, because with the mailer deleted nothing in this service
   * linked into a client and the variable had become required and unread. M192
   * mails invitations and resets again, so it is read again. `SIGNUP_MODE`
   * takes its place on the fatal list.
   */
  clientBaseUrl: string | null;
  /**
   * Mail configuration, or `null` for an instance that sends none — the
   * default, and what every deployment gets until an operator points it at a
   * relay.
   *
   * ALL THREE OR NONE, and any of them requires
   * {@link ServiceConfig.serverPublicUrl} and {@link ServiceConfig.clientBaseUrl}:
   * a letter with no link in it is not worth sending, and a half-configured
   * block is an operator who believes mail works. See `parseMail`.
   */
  mail: HttpMailConfig | null;
  /**
   * The AI proxy's upstream, or `null` for an instance that offers no AI —
   * the default, and what every deployment gets until an operator sets a key.
   *
   * `null` is not "mounted but refusing": `POST /v1/chat/completions` answers
   * the ordinary unknown-path 404, to everybody, for the same reason the admin
   * and share trees do (`server/create-app.ts`).
   */
  ai: AiUpstreamConfig | null;
  /** What `/health` advertises as the model behind the proxy, or `null`. Descriptive, never a routing decision. */
  aiAdvertisedModel: string | null;
  /** Requests per account in any trailing 60 seconds on the proxy route. `AI_RATE_LIMIT_PER_MINUTE`, default 20. */
  aiRateLimitPerMinute: number;
  /**
   * The largest request body the proxy route accepts, in bytes.
   * `AI_MAX_REQUEST_BYTES`, default 8 MB.
   *
   * IT IS NOT THE BLOB LIMIT, and the first version of this route wrongly
   * derived it from one. `MAX_BLOB_BYTES` bounds a diary — a compressed,
   * encrypted document this service stores. A completion body carries a
   * PHOTOGRAPH this service only forwards: a modern phone camera produces 3
   * to 6 MB of JPEG, base64 inflates it by 4/3, and the blob-derived figure
   * (2.73 MB) rejected every real plate scan with a 413 before the handler ran.
   * 8 MB is the bound the retired gateway used, for the same reason.
   */
  aiMaxRequestBytes: number;
  /**
   * Express `trust proxy` setting. MUST be enabled behind a reverse proxy or
   * `req.ip` is the proxy's address and the per-IP throttle collapses into
   * one global bucket that any single attacker can lock for everyone.
   */
  trustProxy: boolean | number;
  /**
   * The operator's admin credential, or `null` when the admin API is not
   * enabled on this instance — which is the default, and the state every
   * deployment is in until somebody deliberately sets the variable.
   *
   * `null` does not mean "mounted but locked". It means the entire
   * `/v1/admin` tree answers the ordinary unknown-path `404`, to everybody
   * (`server/create-app.ts`). See
   * `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`: this
   * service auto-deploys on push, so the commit that adds a route is the
   * commit that puts it in production, and an unconfigured deployment has to
   * be indistinguishable from one where the feature was never written.
   */
  adminToken: string | null;
  /**
   * Whether this instance implements ADR-0002's clinician sharing.
   *
   * `false` — the default, and what every deployment gets until an operator
   * deliberately turns it on — is not "mounted but refusing". Both share
   * subtrees answer the ordinary unknown-path 404, to everybody
   * (`server/create-app.ts`), for the same reason the admin API does: this
   * service auto-deploys on push, so the commit that adds a route is the
   * commit that puts it in production, and an instance that has not opted in
   * must be indistinguishable from one where the feature was never written.
   */
  sharingEnabled: boolean;
  /**
   * Whether this instance implements ADR-0003's research contributions.
   *
   * INDEPENDENT OF {@link ServiceConfig.sharingEnabled} — neither flag implies
   * the other. A clinic instance may want sharing and no cohort graph; a study
   * host may want the reverse. `false`, the default, is not "mounted but
   * refusing": both contribution subtrees answer the ordinary unknown-path 404
   * to everybody (`server/create-app.ts`), because this service auto-deploys
   * on push and an instance that has not opted in must be indistinguishable
   * from one where the feature was never written.
   */
  researchEnabled: boolean;
  /**
   * The operator's message to every client, or `null` — the default, and what
   * an instance with nothing to say has.
   *
   * This is the whole of M181's notice channel, and it is deliberately static
   * config rather than a table with an admin endpoint. Both deliver the same
   * string to the same banner; only one of them needs a migration, a store, a
   * route, its own authorisation and its own tests. An operator who wants to
   * change it redeploys, exactly as they do for every other setting here.
   *
   * It is not a notification system: nobody who does not open the app will
   * ever see it, and the service cannot know who did. See `README.md` — an
   * operator who needs to be able to REACH their users keeps that list
   * themselves, outside this service.
   */
  notice: OperatorNotice | null;
  logLevel: LogLevel;
}

/**
 * `ADMIN_TOKEN` is optional; when present it must be long enough to be worth
 * having. An absent value is not a misconfiguration — it is the default, and
 * it leaves the admin API unmounted.
 */
function parseAdminToken(env: NodeJS.ProcessEnv): string | null {
  const raw = env.ADMIN_TOKEN?.trim();
  if (raw === undefined || raw === '') return null;
  if (raw.length < MIN_ADMIN_TOKEN_LENGTH) {
    throw new Error(
      `ADMIN_TOKEN must be at least ${MIN_ADMIN_TOKEN_LENGTH} characters — generate it, do not choose it (see .env.example)`,
    );
  }
  return raw;
}

/** `INSTANCE_NAME` — what an instance calls itself in its mail and on the handshake. */
const DEFAULT_INSTANCE_NAME = 'openplate';

/**
 * A ceiling on `INSTANCE_NAME`, for the reason {@link MAX_SYNC_NOTICE_LENGTH}
 * exists: this value is published on `/health`, which the container's own
 * healthcheck polls continuously.
 */
export const MAX_INSTANCE_NAME_LENGTH = 64;

function parseInstanceName(env: NodeJS.ProcessEnv): string {
  const raw = env.INSTANCE_NAME?.trim();
  if (raw === undefined || raw === '') return DEFAULT_INSTANCE_NAME;
  if (raw.length > MAX_INSTANCE_NAME_LENGTH) {
    throw new Error(`INSTANCE_NAME must be at most ${MAX_INSTANCE_NAME_LENGTH} characters (got ${raw.length})`);
  }
  return raw;
}

/** `INSTANCE_LANGUAGE` — which of the two languages the invite and reset mails are written in. */
function parseInstanceLanguage(env: NodeJS.ProcessEnv): InstanceLanguage {
  const raw = env.INSTANCE_LANGUAGE?.trim().toLowerCase();
  if (raw === undefined || raw === '') return 'en';
  if (!isInstanceLanguage(raw)) {
    throw new Error(`Invalid INSTANCE_LANGUAGE: expected ${INSTANCE_LANGUAGES.join('/')}, got "${raw}"`);
  }
  return raw;
}

/**
 * An absolute `http(s)` base URL, or `null` when the variable is unset.
 *
 * A RELATIVE OR MISSPELLED VALUE IS A BOOT FAILURE, not a link that goes
 * nowhere. These two values end up in a letter somebody clicks, and a broken
 * one is discovered by the invited person rather than by the operator.
 */
function parseOptionalBaseUrl(env: NodeJS.ProcessEnv, key: string): string | null {
  const raw = env[key]?.trim();
  if (raw === undefined || raw === '') return null;

  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`Invalid ${key}: expected an absolute http(s) URL, got "${raw}"`);
  }
  if (!NOTICE_URL_SCHEMES.includes(parsed.protocol)) {
    throw new Error(`Invalid ${key} scheme "${parsed.protocol}": only ${NOTICE_URL_SCHEMES.join('/')} are accepted`);
  }
  // Trailing slashes are stripped once, here, so every caller can concatenate
  // a path without deciding whether to.
  return raw.replace(/\/+$/, '');
}

/**
 * `SYNC_NOTICE` (and the optional `SYNC_NOTICE_URL` beside it) — the message
 * every client shows on connect. Absent, which is the default, means the
 * handshake carries no notice field at all and an older client is unaffected.
 *
 * Three things are refused at boot rather than shipped:
 *  - a notice longer than {@link MAX_SYNC_NOTICE_LENGTH} — see that constant;
 *  - a URL whose scheme is not `https:`/`http:`, because the client will not
 *    render it either and a `javascript:` value in an operator's env is worth
 *    saying out loud;
 *  - a URL with no notice, which is a link with nothing to say and is far more
 *    likely a typo in the variable name than an intention.
 */
function parseNotice(env: NodeJS.ProcessEnv): OperatorNotice | null {
  const text = env.SYNC_NOTICE?.trim() ?? '';
  const url = env.SYNC_NOTICE_URL?.trim() ?? '';

  if (text === '') {
    if (url === '') return null;
    throw new Error('SYNC_NOTICE_URL is set without SYNC_NOTICE: a link with no message is never published');
  }
  if (text.length > MAX_SYNC_NOTICE_LENGTH) {
    throw new Error(
      `SYNC_NOTICE must be at most ${MAX_SYNC_NOTICE_LENGTH} characters (got ${text.length}) — it is published on /health, which the container healthcheck polls continuously`,
    );
  }
  if (url === '') return { text };

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Invalid SYNC_NOTICE_URL: expected an absolute https:// URL, got "${url}"`);
  }
  if (!NOTICE_URL_SCHEMES.includes(parsed.protocol)) {
    throw new Error(
      `Invalid SYNC_NOTICE_URL scheme "${parsed.protocol}": only ${NOTICE_URL_SCHEMES.join('/')} are published`,
    );
  }
  return { text, url };
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

/** Parses a boolean env var. Anything other than the two accepted spellings is a config error, never a silent `false`. */
function parseBoolean(env: NodeJS.ProcessEnv, key: string, fallback: boolean): boolean {
  const raw = env[key]?.trim().toLowerCase();
  if (raw === undefined || raw === '') return fallback;
  if (raw === 'true' || raw === '1') return true;
  if (raw === 'false' || raw === '0') return false;
  throw new Error(`Invalid boolean for ${key}: expected true/false, got "${raw}"`);
}

function parsePositiveInteger(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key]?.trim();
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`Invalid integer for ${key}: expected a positive integer, got "${raw}"`);
  }
  return parsed;
}

/**
 * `TRUST_PROXY` accepts `true`/`false` or a hop count (`1` = one reverse
 * proxy in front). A hop count is the correct value behind Traefik/nginx;
 * bare `true` trusts every hop and lets a client spoof `X-Forwarded-For`.
 */
function parseTrustProxy(env: NodeJS.ProcessEnv): boolean | number {
  const raw = env.TRUST_PROXY?.trim().toLowerCase();
  if (raw === undefined || raw === '') return false;
  if (raw === 'true') return true;
  if (raw === 'false') return false;
  const hops = Number(raw);
  if (!Number.isInteger(hops) || hops < 0) {
    throw new Error(`Invalid TRUST_PROXY: expected true/false or a hop count, got "${raw}"`);
  }
  return hops;
}

/** The three names that make up the mail block. Listed once so every message below can name them all. */
const MAIL_VARIABLES = ['MAIL_API_URL', 'MAIL_API_KEY', 'MAIL_API_FROM'] as const;

/**
 * `MAIL_API_URL` + `MAIL_API_KEY` + `MAIL_API_FROM`, all or none, and only
 * alongside the two base URLs a link is built from.
 *
 * A HALF-CONFIGURED BLOCK IS A BOOT FAILURE THAT NAMES THE MISSING VARIABLE,
 * and never a value: a key or a URL in a startup log is a credential in a log.
 * The alternative — starting with mail half-configured — is an operator who
 * believes invitations are being delivered while every one of them silently
 * comes back as a link nobody looks at.
 *
 * REQUIRING THE LINK BASES IS THE SAME ARGUMENT ONE STEP OUT. Both letters
 * exist to carry a link. Configured mail with no `CLIENT_BASE_URL` would send
 * a letter with nothing in it to click.
 */
function parseMail(
  env: NodeJS.ProcessEnv,
  urls: { serverPublicUrl: string | null; clientBaseUrl: string | null },
): HttpMailConfig | null {
  const present = MAIL_VARIABLES.filter((name) => (env[name]?.trim() ?? '') !== '');
  if (present.length === 0) return null;

  const missing = MAIL_VARIABLES.filter((name) => !present.includes(name));
  if (missing.length > 0) {
    throw new Error(
      `Incomplete mail configuration: ${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} not set. ` +
        `${MAIL_VARIABLES.join(', ')} are all-or-nothing — set all three, or none and hand out links yourself.`,
    );
  }

  const missingUrls = [
    urls.serverPublicUrl === null ? 'SERVER_PUBLIC_URL' : null,
    urls.clientBaseUrl === null ? 'CLIENT_BASE_URL' : null,
  ].filter((name): name is string => name !== null);
  if (missingUrls.length > 0) {
    throw new Error(
      `Mail is configured but ${missingUrls.join(' and ')} ${missingUrls.length === 1 ? 'is' : 'are'} not set. ` +
        'Both letters this service sends exist to carry a link, and a link needs both values.',
    );
  }

  // SAFETY: `present.length === 3` above, so every name has a non-empty value.
  return {
    url: env.MAIL_API_URL?.trim() ?? '',
    apiKey: env.MAIL_API_KEY?.trim() ?? '',
    from: env.MAIL_API_FROM?.trim() ?? '',
  };
}

/** The two names that make up the upstream block. Listed once so every message below can name both. */
const AI_VARIABLES = ['UPSTREAM_BASE_URL', 'UPSTREAM_API_KEY'] as const;

/** How long the proxy waits for headers, and then between chunks. See `ai/proxy.ts` on why undici and not global fetch. */
const DEFAULT_UPSTREAM_TIMEOUT_MS = 120_000;

/**
 * 8 MB, the figure the retired `openplate-gateway` used (`MAX_REQUEST_BYTES`).
 * Sized for a camera photograph after base64, not for anything this service
 * stores. See `Config.aiMaxRequestBytes`.
 */
const DEFAULT_AI_MAX_REQUEST_BYTES = 8_000_000;

/**
 * `UPSTREAM_BASE_URL` + `UPSTREAM_API_KEY`, both or neither.
 *
 * A HALF-CONFIGURED BLOCK IS A BOOT FAILURE THAT NAMES THE MISSING VARIABLE,
 * and never a value: a provider key in a startup log is a provider key in a
 * log. The alternative is an instance that mounts an AI route it cannot
 * authenticate, so every scan fails with a 502 the operator reads as a provider
 * outage.
 */
function parseAi(env: NodeJS.ProcessEnv): AiUpstreamConfig | null {
  const present = AI_VARIABLES.filter((name) => (env[name]?.trim() ?? '') !== '');
  if (present.length === 0) return null;

  const missing = AI_VARIABLES.filter((name) => !present.includes(name));
  if (missing.length > 0) {
    throw new Error(
      `Incomplete AI configuration: ${missing.join(', ')} is not set. ` +
        `${AI_VARIABLES.join(' and ')} are all-or-nothing — set both, or neither and this instance offers no AI.`,
    );
  }

  const baseUrl = env.UPSTREAM_BASE_URL?.trim() ?? '';
  let parsed: URL;
  try {
    parsed = new URL(baseUrl);
  } catch {
    throw new Error(`Invalid UPSTREAM_BASE_URL: expected an absolute http(s) URL, got "${baseUrl}"`);
  }
  if (!NOTICE_URL_SCHEMES.includes(parsed.protocol)) {
    throw new Error(`Invalid UPSTREAM_BASE_URL scheme "${parsed.protocol}": only ${NOTICE_URL_SCHEMES.join('/')} work`);
  }

  return {
    // Trailing slashes stripped once, here, so `proxy.ts` can concatenate a
    // path without deciding whether to.
    baseUrl: baseUrl.replace(/\/+$/, ''),
    apiKey: env.UPSTREAM_API_KEY?.trim() ?? '',
    timeoutMs: parsePositiveInteger(env, 'UPSTREAM_TIMEOUT_MS', DEFAULT_UPSTREAM_TIMEOUT_MS),
  };
}

function parseLogLevel(env: NodeJS.ProcessEnv): LogLevel {
  const raw = env.LOG_LEVEL?.trim().toLowerCase() ?? 'info';
  if (!isLogLevel(raw)) throw new Error(`Invalid LOG_LEVEL: expected debug/info/warn/error, got "${raw}"`);
  return raw;
}

/**
 * A variable this service used to read and no longer does. Present in the
 * environment, it is a BOOT FAILURE naming what happened, never a silent
 * no-op.
 *
 * THE ASYMMETRY IS THE ARGUMENT, and it is the one M166 first wrote down for
 * `SIGNUPS_OPEN`. A container that refuses to boot is loud and costs one
 * deploy. A variable that is quietly ignored lets an operator believe a door
 * is shut when it is open, or that mail is configured when it is not — a false
 * belief discovered by whoever needs it most, on the day they need it.
 */
function throwIfRemoved(env: NodeJS.ProcessEnv, name: string, because: string): void {
  if (env[name] === undefined) return;
  throw new Error(
    `${name} is no longer read and is rejected rather than ignored: ${because}. Delete it from the environment.`,
  );
}

/** Why the SMTP and pigeon-shaped variables went: M181 deleted those transports and M192 did not bring them back. */
const MAILER_DELETED =
  "openplate-sync speaks only pigeon's HTTP API, configured as MAIL_API_URL, MAIL_API_KEY and MAIL_API_FROM — SMTP is a non-goal";

/**
 * Every variable this service refuses, one by one.
 *
 * `SIGNUP_MODE` JOINED THE LIST IN M192, and `CLIENT_BASE_URL` left it. Signup
 * is invite-only, always: an account is created by redeeming an addressed
 * invite an operator minted, and there is no other door. An instance that
 * booted with a stale `SIGNUP_MODE=open` in its environment would be an
 * operator believing public registration is on, on a service where it is not
 * implemented at all — and, worse, an operator believing they had turned it
 * OFF with `closed` when the variable is simply unread.
 */
function rejectRemovedEnvVars(env: NodeJS.ProcessEnv): void {
  throwIfRemoved(
    env,
    'SIGNUP_MODE',
    'signup is invite-only on every instance, always: mint an addressed invite with POST /v1/admin/invites (there is no open or closed mode any more)',
  );
  throwIfRemoved(
    env,
    'SIGNUPS_OPEN',
    'it was replaced by SIGNUP_MODE in M166, which M192 removed in turn: signup is invite-only, always',
  );
  throwIfRemoved(
    env,
    'REQUIRE_EMAIL_VERIFICATION',
    'the invitation IS the verification — an account is created by redeeming an invite addressed to that mailbox, so there is nothing left to confirm afterwards',
  );
  throwIfRemoved(env, 'EMAIL_FROM', 'the sending address is MAIL_API_FROM');
  throwIfRemoved(env, 'SMTP_HOST', MAILER_DELETED);
  throwIfRemoved(env, 'SMTP_PORT', MAILER_DELETED);
  throwIfRemoved(env, 'SMTP_USER', MAILER_DELETED);
  throwIfRemoved(env, 'SMTP_PASSWORD', MAILER_DELETED);
  throwIfRemoved(env, 'SMTP_SECURE', MAILER_DELETED);
  throwIfRemoved(env, 'PIGEON_API_KEY', 'the mail credential is MAIL_API_KEY');
  throwIfRemoved(env, 'PIGEON_BASE_URL', 'the mail endpoint is MAIL_API_URL');
}

/** Pure: builds the config from an arbitrary env bag. Throws on anything invalid — see the module header. */
export function parseConfig(env: NodeJS.ProcessEnv): ServiceConfig {
  rejectRemovedEnvVars(env);

  const serverSecret = required(env, 'SERVER_SECRET');
  if (serverSecret.length < MIN_SERVER_SECRET_LENGTH) {
    throw new Error(`SERVER_SECRET must be at least ${MIN_SERVER_SECRET_LENGTH} characters (see .env.example)`);
  }

  // Read before the block below, because `parseMail` refuses a mail
  // configuration that has no link to put in a letter.
  const serverPublicUrl = parseOptionalBaseUrl(env, 'SERVER_PUBLIC_URL');
  const clientBaseUrl = parseOptionalBaseUrl(env, 'CLIENT_BASE_URL');

  return {
    port: parsePositiveInteger(env, 'PORT', 3000),
    databaseUrl: required(env, 'DATABASE_URL'),
    databaseSsl: parseBoolean(env, 'DATABASE_SSL', false),
    serverSecret,
    instanceName: parseInstanceName(env),
    instanceLanguage: parseInstanceLanguage(env),
    serverPublicUrl,
    clientBaseUrl,
    mail: parseMail(env, { serverPublicUrl, clientBaseUrl }),
    ai: parseAi(env),
    aiAdvertisedModel: env.AI_ADVERTISED_MODEL?.trim() || null,
    aiRateLimitPerMinute: parsePositiveInteger(env, 'AI_RATE_LIMIT_PER_MINUTE', 20),
    aiMaxRequestBytes: parsePositiveInteger(env, 'AI_MAX_REQUEST_BYTES', DEFAULT_AI_MAX_REQUEST_BYTES),
    trustProxy: parseTrustProxy(env),
    adminToken: parseAdminToken(env),
    sharingEnabled: parseBoolean(env, 'SYNC_SHARING', false),
    researchEnabled: parseBoolean(env, 'SYNC_RESEARCH', false),
    notice: parseNotice(env),
    logLevel: parseLogLevel(env),
  };
}
