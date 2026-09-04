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
 * Canonical account-identity form: NFKC, then trimmed, then lowercased.
 *
 * Applied on EVERY path that touches an address (signup, login, descriptor
 * lookup, invite minting, reset request) — an account must not be reachable
 * under one spelling and invisible under another, and the deterministic dummy
 * descriptor must be stable for `Anna@Example.org` and `anna@example.org`
 * alike or the spelling itself becomes an oracle.
 *
 * NFKC comes FIRST because compatibility composition is what folds the
 * look-alike forms Unicode offers for the same characters (fullwidth Latin,
 * ligatures, the non-breaking spaces a paste can carry). Trimming afterwards
 * catches the ASCII spaces NFKC produces from those; lowercasing last is what
 * makes the unique index a true case-insensitive guarantee.
 *
 * LOWERCASING THE LOCAL PART IS A DELIBERATE OVER-REACH. RFC 5321 makes the
 * part left of the `@` case-SENSITIVE, so `Anna@` and `anna@` are two
 * mailboxes in theory. In practice every mail provider a person is invited
 * from folds them, and treating them as two accounts would let one employee
 * hold two diaries and one invite arrive at an address the account cannot be
 * found under. Folding is the behaviour a user expects; the standard's
 * latitude here is one nobody uses.
 *
 * This is the whole opinion the server has about the CANONICAL FORM. The
 * structural rules — one `@`, a non-empty local part, a dotted domain, at most
 * 254 characters — live in `accounts/auth-input.ts`'s `parseEmail`, which is
 * the only email rule in the repo.
 */
export function normalizeEmail(email: string): string {
  return email.normalize('NFKC').trim().toLowerCase();
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
