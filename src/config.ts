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

/**
 * Minimum accepted `SERVER_SECRET` length. 32 characters is the shortest
 * value that carries ~128 bits when generated the way `.env.example` tells
 * operators to (`openssl rand -hex 32` gives 64). This is a real gate: the
 * verifier pepper derived from it is the only thing standing between a
 * stolen `accounts` table and offline verification of guessed auth-hashes.
 */
export const MIN_SERVER_SECRET_LENGTH = 32;

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
  signupsOpen: boolean;
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
  logLevel: LogLevel;
  email: EmailSettings;
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
    signupsOpen: parseBoolean(env, 'SIGNUPS_OPEN', true),
    requireEmailVerification: parseBoolean(env, 'REQUIRE_EMAIL_VERIFICATION', false),
    clientBaseUrl: normalizeBaseUrl(required(env, 'CLIENT_BASE_URL')),
    trustProxy: parseTrustProxy(env),
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
