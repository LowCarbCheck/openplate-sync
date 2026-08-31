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
import { isSignupMode, SIGNUP_MODES, type SignupMode } from './protocol.js';

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

export interface SmtpSettings {
  host: string;
  port: number;
  user: string;
  password: string;
  secure: boolean;
}

export interface PigeonSettings {
  apiKey: string;
  baseUrl: string;
}

export interface EmailSettings {
  from: string;
  smtp: SmtpSettings;
  pigeon: PigeonSettings;
}

export interface ServiceConfig {
  port: number;
  databaseUrl: string;
  databaseSsl: boolean;
  /** Root secret; `lib/server-secrets.ts` derives the domain-separated subkeys from it. Never used directly. */
  serverSecret: string;
  /**
   * Whether this instance accepts new accounts, and on what terms — see
   * {@link SignupMode}. Replaced the `SIGNUPS_OPEN` boolean in M166, which is
   * now a boot-time error rather than a silently ignored name (see
   * `parseSignupMode`).
   */
  signupMode: SignupMode;
  requireEmailVerification: boolean;
  /**
   * Where the CLIENT app lives — verification and reset links point here, not
   * at this service. A sync service has no UI; the token in the link is
   * redeemed by the client calling back into `/v1/auth/*`.
   */
  clientBaseUrl: string;
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
  logLevel: LogLevel;
  email: EmailSettings;
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

/**
 * `SIGNUP_MODE` is `open`, `invite` or `closed`, defaulting to `open` — a
 * self-hosted family instance should work with no signup configuration at all.
 *
 * THE OLD NAME IS FATAL, AND THE ASYMMETRY IS THE ARGUMENT. `SIGNUPS_OPEN` also
 * defaulted to open, and on the hosted instance it is the only thing that has
 * been holding registration shut. If it were merely ignored, a deploy that
 * shipped this binary before the environment was updated would silently reopen
 * public registration on a zero-knowledge service — a door quietly unlocked,
 * discovered by whoever walks through it first. Refusing to boot is loud, is
 * fixed by one deploy, and cannot be missed. So the removed name throws.
 */
function parseSignupMode(env: NodeJS.ProcessEnv): SignupMode {
  if (env.SIGNUPS_OPEN !== undefined) {
    throw new Error(
      'SIGNUPS_OPEN was replaced by SIGNUP_MODE (open|invite|closed). ' +
        'It is rejected rather than ignored because it defaults to OPEN: ' +
        'ignoring it would silently reopen registration on an instance that set it to false.',
    );
  }
  const raw = env.SIGNUP_MODE?.trim().toLowerCase();
  if (raw === undefined || raw === '') return 'open';
  if (!isSignupMode(raw)) {
    throw new Error(`Invalid SIGNUP_MODE: expected ${SIGNUP_MODES.join('/')}, got "${raw}"`);
  }
  return raw;
}

function required(env: NodeJS.ProcessEnv, key: string): string {
  const value = env[key]?.trim();
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

function optional(env: NodeJS.ProcessEnv, key: string, fallback = ''): string {
  return env[key]?.trim() ?? fallback;
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

function parseLogLevel(env: NodeJS.ProcessEnv): LogLevel {
  const raw = env.LOG_LEVEL?.trim().toLowerCase() ?? 'info';
  if (!isLogLevel(raw)) throw new Error(`Invalid LOG_LEVEL: expected debug/info/warn/error, got "${raw}"`);
  return raw;
}

/** Strips trailing slashes so link building never produces a doubled separator. */
function normalizeBaseUrl(value: string): string {
  return value.replace(/\/+$/, '');
}

/** Pure: builds the config from an arbitrary env bag. Throws on anything invalid — see the module header. */
export function parseConfig(env: NodeJS.ProcessEnv): ServiceConfig {
  const serverSecret = required(env, 'SERVER_SECRET');
  if (serverSecret.length < MIN_SERVER_SECRET_LENGTH) {
    throw new Error(`SERVER_SECRET must be at least ${MIN_SERVER_SECRET_LENGTH} characters (see .env.example)`);
  }

  return {
    port: parsePositiveInteger(env, 'PORT', 3000),
    databaseUrl: required(env, 'DATABASE_URL'),
    databaseSsl: parseBoolean(env, 'DATABASE_SSL', false),
    serverSecret,
    signupMode: parseSignupMode(env),
    requireEmailVerification: parseBoolean(env, 'REQUIRE_EMAIL_VERIFICATION', false),
    clientBaseUrl: normalizeBaseUrl(required(env, 'CLIENT_BASE_URL')),
    trustProxy: parseTrustProxy(env),
    adminToken: parseAdminToken(env),
    sharingEnabled: parseBoolean(env, 'SYNC_SHARING', false),
    researchEnabled: parseBoolean(env, 'SYNC_RESEARCH', false),
    logLevel: parseLogLevel(env),
    email: {
      from: optional(env, 'EMAIL_FROM', 'openplate-sync <noreply@localhost>'),
      smtp: {
        host: optional(env, 'SMTP_HOST'),
        port: parsePositiveInteger(env, 'SMTP_PORT', 587),
        user: optional(env, 'SMTP_USER'),
        password: optional(env, 'SMTP_PASSWORD'),
        secure: parseBoolean(env, 'SMTP_SECURE', false),
      },
      pigeon: {
        apiKey: optional(env, 'PIGEON_API_KEY'),
        baseUrl: normalizeBaseUrl(optional(env, 'PIGEON_BASE_URL')),
      },
    },
  };
}
