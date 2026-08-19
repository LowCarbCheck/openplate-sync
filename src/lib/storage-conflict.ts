/**
 * Pure Postgres unique-violation detection — the signal every compare-and-swap
 * write in this service uses to distinguish "lost a race" from "something is
 * actually broken".
 *
 * Kept in its own DB-free module (ported from the openplate app, where it was
 * extracted for security-review finding #4) so the conflict-mapping rule is
 * unit-testable without a live database: `db/storage-adapter.ts` imports the
 * connection pool at module load, and a plain `node --test` run has no
 * Postgres to give it.
 */
import { asString } from './json.js';

/** Postgres SQLSTATE for a unique-constraint violation; the `pg` driver surfaces it as `error.code`. */
export const POSTGRES_UNIQUE_VIOLATION_CODE = '23505';

/** The single property this module reads off a driver error: the five-character SQLSTATE. */
interface SqlstateCarrier {
  readonly code?: string;
}

/**
 * The SQLSTATE of a caught value, or `null` when it carries none.
 *
 * `Object()` boxes primitives instead of narrowing them, so a thrown string or
 * number simply has no `code` property and reads as `null` — the same answer a
 * non-Postgres `Error` gives, which is exactly what callers want.
 */
export function sqlstate(cause: unknown): string | null {
  const carrier: SqlstateCarrier = Object(cause);
  return asString(carrier.code);
}

/**
 * Whether `error` is a Postgres unique-constraint violation. Both the blob
 * CAS (`UNIQUE (account_id, blob_version)`) and the key-record CAS
 * (`UNIQUE (account_id, kind)`) rely on this to re-read the real current
 * value and return a clean conflict instead of throwing.
 */
export function isUniqueViolation(cause: unknown): boolean {
  return sqlstate(cause) === POSTGRES_UNIQUE_VIOLATION_CODE;
}
