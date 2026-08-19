/**
 * The Bitwarden-model authentication verifier — and the reason it is a FAST
 * keyed hash rather than another slow KDF.
 *
 * What the client sends as its "password" is already the output of
 * Argon2id → HKDF over the user's passphrase (PROTOCOL.md §3.1, the `auth`
 * branch). The expensive, memory-hard work has therefore already been paid,
 * on the client, once per login. Running a second slow hash here would add
 * **zero** brute-force resistance — an attacker who has the auth-hash has
 * already skipped Argon2id — while handing anyone a login-flood DoS: N
 * concurrent login attempts would each pin 64 MiB and a CPU core on the
 * server.
 *
 * So the stored verifier is `HMAC-SHA-256(pepper, authHash)`. That still
 * defeats the attack peppering is for: with the pepper held outside the
 * database (`SERVER_SECRET` in the environment), a dumped `accounts` table
 * cannot be replayed pass-the-hash style against a live instance, and its
 * verifiers cannot be checked offline against guessed auth-hashes.
 *
 * The server never sees, and cannot derive, anything that decrypts a blob:
 * the auth-hash and the passphrase-KEK are two independent HKDF branches off
 * the same Argon2id output, with different `info` labels.
 *
 * Pure module — no config, no DB, no env. Unit-tested directly.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import { asString, type JsonValue } from './json.js';

/** HKDF-SHA-256 output length for the auth branch, in bytes. A client sending anything else is malformed. */
export const AUTH_HASH_BYTES = 32;

/**
 * Canonical account-identity form: trimmed and lowercased. Applied on EVERY
 * path that touches an email (signup, login, descriptor lookup, reset
 * request) — an account must not be reachable under one casing and invisible
 * under another, and the deterministic dummy descriptor must be stable for
 * `A@B.com` and `a@b.com` alike or the casing itself becomes an oracle.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Deliberately permissive structural check — one `@`, something either side,
 * a dot in the domain, no whitespace. Email validity is decided by delivery,
 * not by a regex; this only rejects input that cannot possibly be an address
 * so it never reaches the mail transport.
 */
export function isPlausibleEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/.test(email);
}

/**
 * Decodes and validates the client's base64 auth-hash. Returns `null` for
 * anything that is not exactly {@link AUTH_HASH_BYTES} bytes — including
 * base64 that decodes to a shorter buffer, which `Buffer.from` would
 * otherwise accept silently.
 */
export function parseAuthHash(value: JsonValue | undefined): Buffer | null {
  const encoded = asString(value);
  if (encoded === null || encoded.length === 0) return null;
  const decoded = Buffer.from(encoded, 'base64');
  if (decoded.byteLength !== AUTH_HASH_BYTES) return null;
  return decoded;
}

/** The value stored in `accounts.verifier`: a hex HMAC-SHA-256 of the client's auth-hash under the server pepper. */
export function computeVerifier(input: { authHash: string; pepper: string }): string {
  return createHmac('sha256', input.pepper).update(input.authHash).digest('hex');
}

/**
 * Constant-time verifier comparison. Length is checked first because
 * `timingSafeEqual` throws on a length mismatch — and a length mismatch here
 * means a malformed stored value, not a near-miss guess, so leaking that one
 * bit costs nothing.
 */
export function verifierMatches(input: { candidate: string; stored: string }): boolean {
  const candidate = Buffer.from(input.candidate, 'utf8');
  const stored = Buffer.from(input.stored, 'utf8');
  if (candidate.byteLength !== stored.byteLength) return false;
  return timingSafeEqual(candidate, stored);
}
