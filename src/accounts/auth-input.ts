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
import { normalizeHandle, parseAuthHash } from '../lib/verifier.js';
import { parseKdfDescriptor, type KdfDescriptor } from '../lib/kdf-descriptor.js';
import { asArray, asObject, asString, asTrimmedString, type JsonObject, type JsonValue } from '../lib/json.js';
import type { KeyRecordSubmission } from './account-store.js';

export type ParseResult<T> = { ok: true; value: T } | { ok: false; reason: string };

/** Bounded so a display name can never be used as free storage on a service that stores nothing else in the clear. */
export const MAX_DISPLAY_NAME_LENGTH = 64;
/**
 * Bounded to keep a malformed client from posting a megabyte of identifier.
 * 64 characters is far more than the client's generated handle needs and
 * still leaves room for a name somebody chose.
 */
export const MAX_HANDLE_LENGTH = 64;

function fail(reason: string): ParseResult<never> {
  return { ok: false, reason };
}

/**
 * Normalizes and structurally validates a handle. The normalized form
 * ({@link normalizeHandle}: NFKC, trim, lowercase) is what every store lookup
 * uses, so two spellings of the same handle collide on the unique index.
 *
 * THE `'@'` REJECTION IS LOAD BEARING, AND THIS IS THE ONLY PLACE IT LIVES.
 * It is what stops the handle column drifting back into being an address
 * register. A user who types their email into the handle box gets a `400` that
 * names the rule, and this service never stores a mailbox — which is the whole
 * point of M181, and is impossible to add later once the column holds
 * addresses. The service has no other opinion about the shape of a handle:
 * non-empty, no `'@'`, length-bounded, and unique. Handles are minted by the
 * client (never here), and the user may edit them.
 */
export function parseHandle(value: JsonValue | undefined): ParseResult<string> {
  const raw = asString(value);
  if (raw === null) return fail('handle must be a string');
  const handle = normalizeHandle(raw);
  if (handle.length === 0 || handle.length > MAX_HANDLE_LENGTH) return fail('handle has an implausible length');
  if (handle.includes('@')) {
    return fail('handle must not contain "@": this service identifies accounts by handle, never by email address');
  }
  return { ok: true, value: handle };
}

/** The client's base64 auth-hash, kept as the ORIGINAL string: it is the HMAC input, so re-encoding it would change the verifier. */
export function parseAuthHashField(value: JsonValue | undefined, field = 'authHash'): ParseResult<string> {
  const encoded = asString(value);
  if (encoded === null || parseAuthHash(encoded) === null) {
    return fail(`${field} must be a base64-encoded 32-byte value`);
  }
  return { ok: true, value: encoded };
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
