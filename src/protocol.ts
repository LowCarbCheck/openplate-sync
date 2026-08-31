/**
 * The E2EE sync WIRE CONTRACT — the entire shared surface between an openplate
 * client and a sync service (M128 spec 01).
 *
 * THIS FILE IS MAINTAINED IN TWO REPOS AND MUST STAY IDENTICAL IN SUBSTANCE:
 *  - `openplate/app/lib/sync/engine/protocol.ts`   (the client half)
 *  - `openplate-sync/src/protocol.ts`              (this file — the service half)
 *
 * They are deliberately NOT a shared package: the two repos ship and version
 * independently, and a third party must be able to implement either side from
 * `openplate-sync/PROTOCOL.md` alone without depending on our code. The price
 * of that independence is hand-maintained duplication, so each repo carries a
 * unit test that asserts its local `PROTOCOL_VERSION` (and the size/retention
 * limits) against TRANSCRIBED literals — there is no shared CI, so drift has
 * to fail a test rather than rely on a promise in a doc comment
 * (`tests/unit/protocol.test.ts` here,
 * `tests/unit/sync-engine/protocol.test.ts` there).
 *
 * The service stores OPAQUE BYTES. It never sees a key, never parses an
 * envelope, and never learns anything about the plaintext beyond its length.
 * Everything below is therefore either transport framing or non-secret
 * metadata the service legitimately needs (versions, sizes, CAS tokens).
 */
import { asNumber, asObject, asString, type JsonObject, type JsonValue } from './lib/json.js';

/**
 * The wire-protocol version a client and service must agree on before any
 * sync traffic flows (see {@link checkProtocolCompatibility}).
 *
 * Bump this for ANY breaking change to the endpoints, request/response
 * shapes, auth scheme, or CAS semantics documented in `PROTOCOL.md`.
 * Purely additive changes (a new optional response field, a new endpoint that
 * older clients simply never call) do not require a bump.
 */
export const PROTOCOL_VERSION = 1;

/**
 * The encrypted-blob wire format version — INDEPENDENT of
 * {@link PROTOCOL_VERSION}. This one describes what is inside
 * `ciphertext`: `gzip(JSON(payload))` sealed with AES-256-GCM, the 12-byte IV
 * packed as the leading bytes (`openplate`'s `app/lib/sync/engine/envelope/build-envelope.ts`).
 *
 * Bump ONLY for a genuine crypto/framing change (a different cipher, a
 * different compression codec, a different IV packing). Never bump it for a
 * payload SCHEMA change — that is the local store's own
 * `payloadSchemaVersion`, which travels through this protocol as an opaque
 * number bound into the AAD.
 */
export const ENVELOPE_VERSION = 1;

/**
 * Hard cap on one account's encrypted blob, enforced by the service and
 * mirrored by the client so it can fail early with a useful message instead
 * of eating a 413.
 *
 * CAPACITY PLAN (counsel, 2026-08-03): food-log JSON runs ~400–700 bytes per
 * entry BEFORE compression, so an un-gzipped whole-store blob would reach
 * this cap within 2–4 years of daily use. `ENVELOPE_VERSION` 1 gzips the
 * plaintext before encrypting, which buys roughly an order of magnitude of
 * headroom on highly-repetitive JSON. The long-term fix (chunked/per-entity
 * blobs) is a FUTURE PROTOCOL VERSION BUMP, deliberately deferred and
 * recorded in `PROTOCOL.md` so it is planned rather than discovered under
 * pressure.
 */
export const MAX_BLOB_BYTES = 2 * 1024 * 1024;

/** How many historical blob versions the service retains per account; older ones are pruned on every successful write. */
export const BLOB_VERSION_RETENTION = 5;

/**
 * Path prefix the blob/key-record endpoints are mounted under.
 *
 * CHANGED IN M128 SPEC 02, from `/api/sync` to `/v1/sync`: the standalone
 * service owns its whole URL space now and versions it as a whole, so the
 * blob routes sit beside `/v1/auth/*` under one namespace rather than in a
 * leftover mount path from the era when they were grafted onto the openplate
 * app's Express server.
 *
 * `PROTOCOL.md` §7 records this as a pre-1.0 change that does NOT bump
 * `PROTOCOL_VERSION` — zero production blobs exist, there are no third-party
 * implementations, and no deployed client can be broken by it.
 *
 * CROSS-REPO NOTE: `openplate/app/lib/sync/engine/protocol.ts` is the
 * hand-maintained duplicate of this file and still carries the old value.
 * Its drift-guard test asserts against a transcribed literal, so it will keep
 * passing while disagreeing — nothing in either repo can catch this
 * automatically. The client half of the move belongs to the spec that wires
 * the client to a real service.
 */
export const SYNC_API_PREFIX = '/v1/sync';

// ---------------------------------------------------------------------------
// Key records
// ---------------------------------------------------------------------------

/**
 * The two ways an account's DEK is wrapped: under the passphrase-derived KEK
 * (Argon2id → HKDF) and under the recovery-code-derived KEK (HKDF only).
 * Exactly one record of each kind may exist per account.
 */
export type SyncKeyRecordKind = 'passphrase' | 'recovery';

/** Every valid {@link SyncKeyRecordKind}, for validation and exhaustive iteration. */
export const SYNC_KEY_RECORD_KINDS: readonly SyncKeyRecordKind[] = ['passphrase', 'recovery'];

export function isSyncKeyRecordKind(value: JsonValue | undefined): value is SyncKeyRecordKind {
  return value === 'passphrase' || value === 'recovery';
}

// ---------------------------------------------------------------------------
// Signup policy
// ---------------------------------------------------------------------------

/**
 * Whether, and on what terms, an instance accepts new accounts.
 *
 *  - `'open'` — anyone may register. The default for a self-hosted instance.
 *  - `'invite'` — registration requires a single-use token the operator minted
 *    (`POST /v1/admin/invites`). What the hosted instance runs.
 *  - `'closed'` — nobody may register. Existing accounts keep working.
 *
 * This is deliberately NOT a secret. `POST /v1/auth/signup` already discloses
 * it to anyone who calls it, and any instance with a sign-up page shows it to
 * every visitor. Publishing it on the handshake only saves the client from
 * having to provoke a `403` to render the right form.
 */
export type SignupMode = 'open' | 'invite' | 'closed';

/** Every valid {@link SignupMode}, for validation and exhaustive iteration. */
export const SIGNUP_MODES: readonly SignupMode[] = ['open', 'invite', 'closed'];

export function isSignupMode(value: JsonValue | undefined): value is SignupMode {
  return value === 'open' || value === 'invite' || value === 'closed';
}

// ---------------------------------------------------------------------------
// Version handshake
// ---------------------------------------------------------------------------

/**
 * What a service reports about itself, read by the client BEFORE its first
 * sync of a session. This replaces the same-process `HOOK_VERSION` check that
 * died with M117's build-time composition seam: client and service are now
 * separately deployed artifacts that can drift by a release, and the only
 * safe way to notice is to ask.
 */
export interface ProtocolHandshake {
  /** The service's {@link PROTOCOL_VERSION}. */
  protocolVersion: number;
  /** The highest {@link ENVELOPE_VERSION} the service is willing to accept on a push. */
  envelopeVersion: number;
  /** Human-readable build identifier — diagnostics only, never compared. */
  serviceVersion: string;
  /**
   * How this instance treats new accounts — see {@link SignupMode}.
   *
   * OPTIONAL, and it must stay optional. A service older than this field
   * omits it entirely, and a client that required it would refuse to talk to
   * every such instance: a compatibility break wearing the clothes of an
   * additive change. Absent means "ask by trying" — attempt the signup and
   * handle the `403`.
   *
   * It is a HINT, never the contract. An operator can close signups between
   * the handshake and the submit, so the client keeps its `403` handling even
   * when this said `'open'`.
   */
  signupMode?: SignupMode;
}

/** Result of {@link checkProtocolCompatibility} — `reason` is a user-presentable sentence. */
export type ProtocolCompatibility = { status: 'compatible' } | { status: 'incompatible'; reason: string };

export function isProtocolHandshake(value: JsonValue | undefined): boolean {
  const candidate = asObject(value);
  if (candidate === null) return false;
  // `signupMode` is deliberately absent from this check. It is optional on the
  // wire, so demanding it here would reject every service older than the field.
  return (
    asNumber(candidate.protocolVersion) !== null &&
    asNumber(candidate.envelopeVersion) !== null &&
    asString(candidate.serviceVersion) !== null
  );
}

/**
 * Decides whether this build may talk to the service that returned `remote`.
 *
 * Pure and total — it never throws and never guesses. A mismatch is REFUSAL
 * with a clear message, never a best-effort attempt: pushing an envelope a
 * service can't store, or decrypting one framed by rules this build doesn't
 * know, corrupts an account's only copy of its data. Silent wrongness is the
 * one outcome this whole handshake exists to prevent.
 */
export function checkProtocolCompatibility(remote: ProtocolHandshake): ProtocolCompatibility {
  if (remote.protocolVersion !== PROTOCOL_VERSION) {
    return {
      status: 'incompatible',
      reason: `This sync server speaks protocol version ${remote.protocolVersion}; this app speaks version ${PROTOCOL_VERSION}. Update whichever side is older before syncing.`,
    };
  }
  if (remote.envelopeVersion !== ENVELOPE_VERSION) {
    return {
      status: 'incompatible',
      reason: `This sync server expects envelope version ${remote.envelopeVersion}; this app produces version ${ENVELOPE_VERSION}. Update whichever side is older before syncing.`,
    };
  }
  return { status: 'compatible' };
}

// ---------------------------------------------------------------------------
// Wire shapes — blobs
// ---------------------------------------------------------------------------

/**
 * A base64-encoded byte string. Binary fields (`ciphertext`, `wrappedDek`)
 * travel as base64 inside JSON bodies rather than as a binary content type,
 * so that every field of every request is inspectable by a self-hoster
 * debugging their own instance.
 */
export type Base64Bytes = string;

/** An ISO-8601 UTC timestamp string, e.g. `2026-08-04T10:11:12.000Z`. */
export type IsoTimestamp = string;

/** `POST {prefix}/blob` — a compare-and-swap write of the account's single encrypted blob. */
export interface PushBlobRequest {
  /**
   * The `blobVersion` this client believes is currently stored (`0` for "no
   * blob exists yet"). The write succeeds only if it still matches — this is
   * the entire concurrency model, and it is never a blind overwrite.
   */
  baseVersion: number;
  envelopeVersion: number;
  ciphertext: Base64Bytes;
}

/** `200` — the CAS write won. */
export interface PushBlobAcceptedResponse {
  newVersion: number;
}

/**
 * `409` — the CAS write lost: another device wrote first. The client must
 * pull `currentVersion`, merge (`openplate`'s `app/lib/sync/engine/merge/merge-entities.ts`), and retry
 * with `baseVersion: currentVersion`.
 */
export interface PushBlobConflictResponse {
  currentVersion: number;
}

/** `200` from `GET {prefix}/blob`. A `404` means this account has never pushed. */
export interface PullBlobResponse {
  blobVersion: number;
  envelopeVersion: number;
  ciphertext: Base64Bytes;
  createdAt: IsoTimestamp;
}

// ---------------------------------------------------------------------------
// Wire shapes — key records
// ---------------------------------------------------------------------------

/** One wrapped-DEK record as it appears on the wire. */
export interface KeyRecordWire {
  kind: SyncKeyRecordKind;
  /**
   * Argon2id salt + m/t/p parameters for the `passphrase` kind so any device
   * can re-derive the KEK; ALWAYS `null` for `recovery` (HKDF-only — a
   * ≥128-bit random code needs no memory-hard stretch and therefore has no
   * parameters to record). Non-secret by design.
   */
  kdfDescriptor: JsonObject | null;
  wrappedDek: Base64Bytes;
  updatedAt: IsoTimestamp;
}

/** `200` from `GET {prefix}/key-records`. */
export interface ListKeyRecordsResponse {
  records: KeyRecordWire[];
}

/** `PUT {prefix}/key-records/:kind` — also CAS-gated, mirroring the blob endpoint. */
export interface PutKeyRecordRequest {
  kdfDescriptor: JsonObject | null;
  wrappedDek: Base64Bytes;
  /**
   * `null` asserts "no record of this kind exists yet" (first-time setup);
   * any other value asserts "the record I last read had exactly this
   * `updatedAt`" (rotation).
   *
   * The key MUST be present. An ABSENT key is a `400`, deliberately — a
   * caller must not be able to skip the concurrency check by forgetting a
   * field.
   */
  expectedUpdatedAt: IsoTimestamp | null;
}

/** `409` from a key-record PUT whose `expectedUpdatedAt` no longer matches. */
export interface PutKeyRecordConflictResponse {
  currentUpdatedAt: IsoTimestamp | null;
}

/** Every non-2xx response body shape. `error` is diagnostic text, never a machine-readable code. */
export interface ProtocolErrorResponse {
  error: string;
}

/**
 * The status codes that carry protocol meaning. Anything else is a transport
 * or infrastructure failure and should be retried or surfaced as such.
 */
export const PROTOCOL_STATUS = {
  ok: 200,
  noContent: 204,
  badRequest: 400,
  unauthorized: 401,
  forbidden: 403,
  notFound: 404,
  conflict: 409,
  payloadTooLarge: 413,
} as const;
