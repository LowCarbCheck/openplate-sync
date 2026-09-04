/**
 * Request-body parsers for the `/v1/auth/*` endpoints — pure, total, and
 * returning a discriminated result instead of throwing.
 *
 * Split out of `auth-handlers.ts` so the validation rules can be unit-tested
 * exhaustively without constructing a whole `AuthContext`, and so the
 * handlers read as policy rather than as a wall of `typeof` checks.
 *
 * Every parser is strict about SHAPE and silent about WHY beyond a short
 * reason string. Reasons are diagnostic text for a developer reading a `400`;
 * clients branch on the status code (PROTOCOL.md §4).
 *
 * Input arrives as {@link JsonValue} — the named boundary type from
 * `lib/json.ts` — and leaves as a domain value. The primitive decoding lives
 * in that module; nothing here re-inspects a representation.
 */
import { isSyncKeyRecordKind, type SyncKeyRecordKind } from '../protocol.js';
import { normalizeEmail, parseAuthHash } from '../lib/verifier.js';
import { parseKdfDescriptor, type KdfDescriptor } from '../lib/kdf-descriptor.js';
import { asArray, asObject, asString, asTrimmedString, type JsonObject, type JsonValue } from '../lib/json.js';
import type { KeyRecordSubmission } from './account-store.js';

export type ParseResult<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Bounded so a display name can never be used as free storage on a service that stores nothing else in the clear. */
export const MAX_DISPLAY_NAME_LENGTH = 64;
/** RFC 5321's ceiling on a whole address. A longer string is not an address anybody has. */
export const MAX_EMAIL_LENGTH = 254;

/**
 * The Crockford-style base32 alphabet the recovery code is rendered in
 * (PROTOCOL.md §3.1). `O`, `I`, `L` and `U` are absent so a code survives
 * being read aloud and typed back.
 */
export const RECOVERY_CODE_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
/**
 * 32 base32 characters, which is exactly the 160 bits of §3.1's 20-byte code.
 * A code of any other length is not one this client ever generated.
 */
export const RECOVERY_CODE_LENGTH = 32;

function fail(reason: string): ParseResult<never> {
  return { ok: false, reason };
}

/**
 * Normalizes and structurally validates an email address. The normalized form
 * ({@link normalizeEmail}: NFKC, trim, lowercase) is what every store lookup
 * uses, so two spellings of one address collide on the unique index.
 *
 * THIS IS THE ONLY EMAIL RULE IN THE REPO, and it replaced `parseHandle` —
 * including its `'@'` REJECTION, which M181 made load-bearing and M192
 * inverts on purpose (ADR-0005 supersedes ADR-0004 prohibition 1). The
 * reversal is not a drift: it is the decision that an organization's people
 * are identified by the address their invitation arrived at, because that is
 * the one identifier they will still know in a month.
 *
 * THE RULE IS DELIBERATELY STRUCTURAL AND NOT RFC-COMPLETE. Exactly one `@`, a
 * non-empty local part, a domain that contains a dot with non-empty labels,
 * and at most {@link MAX_EMAIL_LENGTH} characters. A full RFC 5322 grammar
 * would accept quoted strings, comments and bracketed literals that no
 * organization's directory contains, and it would still not tell us whether
 * the mailbox exists. What proves that is the invitation arriving, which is
 * why the invite is the address verification and this function is only a
 * typo gate.
 */
export function parseEmail(value: JsonValue | undefined): ParseResult<string> {
  const raw = asString(value);
  if (raw === null) return fail('email must be a string');
  const email = normalizeEmail(raw);
  if (email.length === 0 || email.length > MAX_EMAIL_LENGTH) return fail('email has an implausible length');

  const parts = email.split('@');
  // Exactly two parts means exactly one `@`. Splitting is total, so this
  // covers "no @" and "several @" with one comparison.
  if (parts.length !== 2) return fail('email must contain exactly one "@"');
  const [local, domain] = parts;
  if (local === undefined || local.length === 0) return fail('email must have a local part before the "@"');
  if (domain === undefined) return fail('email must have a domain after the "@"');

  const labels = domain.split('.');
  if (labels.length < 2 || labels.some((label) => label.length === 0)) {
    return fail('email domain must contain a dot and no empty labels');
  }
  // Whitespace anywhere else survives `trim`, and an address with a space in
  // it is a paste accident rather than a mailbox.
  if (/\s/.test(email)) return fail('email must not contain whitespace');

  return { ok: true, value: email };
}

/**
 * Canonicalizes and validates a recovery code as it arrives at signup or at a
 * rotation — the value the server then SEALS into `accounts.recovery_code_escrow`.
 *
 * CANONICAL FORM FIRST, VALIDATION SECOND. The client shows the code in groups
 * of five, and a person or a client may send it back with the spaces or the
 * hyphens still in it. Stripping both and uppercasing before the check means
 * one code has one sealed form, so a re-escrow after a rotation is comparable
 * with what was there before.
 *
 * THE CODE IS NEVER IN A REASON STRING. Every rejection below describes the
 * SHAPE and quotes nothing, because a `400` body ends up in a log and this
 * value opens a diary.
 */
export function parseRecoveryCode(value: JsonValue | undefined): ParseResult<string> {
  const raw = asString(value);
  if (raw === null) return fail('recoveryCode must be a string');

  const canonical = raw
    .normalize('NFKC')
    .replace(/[\s-]+/g, '')
    .toUpperCase();
  if (canonical.length !== RECOVERY_CODE_LENGTH) {
    return fail(`recoveryCode must be ${RECOVERY_CODE_LENGTH} base32 characters once spaces and hyphens are removed`);
  }
  for (const character of canonical) {
    if (!RECOVERY_CODE_ALPHABET.includes(character)) {
      return fail('recoveryCode must use only the Crockford base32 alphabet (no O, I, L or U)');
    }
  }
  return { ok: true, value: canonical };
}

/** The client's base64 auth-hash, kept as the ORIGINAL string: it is the HMAC input, so re-encoding it would change the verifier. */
export function parseAuthHashField(value: JsonValue | undefined, field = 'authHash'): ParseResult<string> {
  const encoded = asString(value);
  if (encoded === null || parseAuthHash(encoded) === null) {
    return fail(`${field} must be a base64-encoded 32-byte value`);
  }
  return { ok: true, value: encoded };
}

/**
 * The recovery-code auth proof, or the absence of one.
 *
 * OPTIONAL AT SIGNUP AND WHEN ROTATING, REQUIRED WHEN RECOVERING. An account
 * may exist with no second authenticator, and `null` is how a client says so
 * — the alternative, inferring it from a missing key, would make a typo in
 * the field name silently create an account that can never be recovered.
 *
 * Structurally identical to {@link parseAuthHashField}: the value is a 32-byte
 * HKDF output, base64, kept as the ORIGINAL string because it is the HMAC
 * input. What differs is only the client-side label it was derived under
 * (`openplate-sync:recovery-auth:v1`), which this service never sees and
 * cannot check — the separation is a client property, asserted by the frozen
 * label test in the openplate repo.
 */
export function parseOptionalRecoveryAuthHash(
  value: JsonValue | undefined,
  field = 'recoveryAuthHash',
): ParseResult<string | null> {
  if (value === undefined || value === null) return { ok: true, value: null };
  return parseAuthHashField(value, field);
}

export function parseKdfDescriptorField(value: JsonValue | undefined): ParseResult<KdfDescriptor> {
  const descriptor = parseKdfDescriptor(value);
  if (descriptor === null) return fail('kdfDescriptor must contain a 16-byte base64 salt and positive Argon2id params');
  return { ok: true, value: descriptor };
}

/** Optional, cosmetic, and trimmed to `null` when blank — an empty string is not a name. */
export function parseDisplayName(value: JsonValue | undefined): ParseResult<string | null> {
  if (value === undefined || value === null) return { ok: true, value: null };
  const raw = asString(value);
  if (raw === null) return fail('displayName must be a string or null');
  const trimmed = raw.trim();
  if (trimmed.length === 0) return { ok: true, value: null };
  if (trimmed.length > MAX_DISPLAY_NAME_LENGTH)
    return fail(`displayName must be at most ${MAX_DISPLAY_NAME_LENGTH} characters`);
  return { ok: true, value: trimmed };
}

/** A raw opaque token as it arrives in a request body — a refresh token, or an invite. */
export function parseTokenField(value: JsonValue | undefined, field = 'token'): ParseResult<string> {
  const token = asTrimmedString(value);
  if (token === null) return fail(`${field} is required`);
  return { ok: true, value: token };
}

function parseKeyRecordSubmission(value: JsonValue | undefined): ParseResult<KeyRecordSubmission> {
  const candidate = asObject(value);
  if (candidate === null) return fail('each key record must be an object');

  const kind = candidate.kind;
  if (!isSyncKeyRecordKind(kind)) return fail('key record kind must be "passphrase" or "recovery"');

  const encodedDek = asString(candidate.wrappedDek);
  if (encodedDek === null) return fail('wrappedDek must be a base64 string');
  const wrappedDek = new Uint8Array(Buffer.from(encodedDek, 'base64'));
  if (wrappedDek.byteLength === 0) return fail('wrappedDek must not be empty');

  // Same rule as PROTOCOL.md §5.4: the recovery path is HKDF-only, so it has
  // no parameters to record, and the passphrase path is useless without them.
  const submitted = candidate.kdfDescriptor ?? null;
  if (kind === 'recovery' && submitted !== null) {
    return fail('recovery key records must have a null kdfDescriptor');
  }
  if (kind === 'passphrase' && submitted === null) {
    return fail('passphrase key records require a kdfDescriptor');
  }
  const kdfDescriptor = submitted === null ? null : asObject(submitted);
  if (submitted !== null && kdfDescriptor === null) {
    return fail('kdfDescriptor must be an object or null');
  }

  return { ok: true, value: { kind, kdfDescriptor, wrappedDek } };
}

/**
 * The re-wrapped DEKs submitted alongside a credential rotation. An ABSENT
 * key is rejected the same way `expectedUpdatedAt` is on the key-record
 * endpoint: a caller must state its intent explicitly, including "I am
 * changing nothing" as an empty array. Silence must never be read as consent
 * on a path that can strand an account's data.
 */
export function parseKeyRecordSubmissions(value: JsonValue | undefined): ParseResult<KeyRecordSubmission[]> {
  const entries = asArray(value);
  if (entries === null) return fail('keyRecords must be an array (use [] to submit none)');
  if (entries.length > 2) return fail('keyRecords may contain at most one record per kind');

  const seen = new Set<SyncKeyRecordKind>();
  const records: KeyRecordSubmission[] = [];
  for (const entry of entries) {
    const parsed = parseKeyRecordSubmission(entry);
    if (!parsed.ok) return parsed;
    if (seen.has(parsed.value.kind)) return fail(`duplicate key record kind: ${parsed.value.kind}`);
    seen.add(parsed.value.kind);
    records.push(parsed.value);
  }
  return { ok: true, value: records };
}

/**
 * Narrows a request body to a field bag so the parsers above can read from it.
 * A body that is not an object yields an EMPTY bag rather than an error: every
 * field parser already rejects `undefined` with its own reason, which is a
 * better `400` than "body must be an object".
 */
export function asFields(body: JsonValue | undefined): JsonObject {
  return asObject(body) ?? {};
}
