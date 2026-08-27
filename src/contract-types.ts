/**
 * The HOST-INJECTION contract: what a host shell must provide for
 * `registerSyncRoutes` to mount the blob/key-record routes — a storage
 * adapter and a way to resolve the caller. Nothing here crosses the wire;
 * that is `protocol.ts`'s job.
 *
 * These shapes are INTERNAL to this repo. Until M128 spec 01 they duplicated
 * a matching set in the openplate app, because the app was the host that
 * injected them. It no longer is: this package gains its own Express +
 * Drizzle host shell in M128 spec 02, at which point these types describe a
 * boundary that lives entirely inside this repo. The openplate app keeps a
 * copy of the same shapes only until spec 03 deletes its now-unused sync
 * tables (`app/lib/sync/storage-types.ts`).
 */
import type { Request } from 'express';
// The record kind is a WIRE concept, so `protocol.ts` owns it and this file
// borrows it rather than declaring a second copy that could drift.
import type { SyncKeyRecordKind } from './protocol.js';
import type { JsonObject } from './lib/json.js';
import type { Logger } from './logger.js';

export interface SyncKeyRecord {
  accountId: number;
  kind: SyncKeyRecordKind;
  kdfDescriptor: JsonObject | null;
  /** The DEK, wrapped by this record's KEK — a SINGLE packed blob (12-byte IV + ciphertext+tag, `crypto/dek-wrap.ts`'s `wrapDek`). The server never unwraps it. */
  wrappedDek: Uint8Array;
  updatedAt: Date;
}

export interface SyncBlobRecord {
  accountId: number;
  blobVersion: number;
  envelopeVersion: number;
  /** Opaque, SINGLE packed blob (12-byte IV + AAD-bound ciphertext+tag, `envelope/build-envelope.ts`'s `buildEnvelope`) — the server never parses it. */
  ciphertext: Uint8Array;
  createdAt: Date;
}

export type PutBlobResult = { ok: true; newVersion: number } | { ok: false; currentVersion: number };

/**
 * Result of a CAS key-record write (security review finding #2 — mirrors
 * `PutBlobResult`'s optimistic-concurrency shape, applied to key records so
 * a rotation/first-time-setup race can never silently overwrite another
 * write). `currentUpdatedAt` is `null` only when the caller asserted
 * `expectedUpdatedAt: null` (first-time create) and lost the race to a
 * write that ALSO happened to fail for some other reason before any record
 * existed — in the normal case a conflict means a record now exists.
 */
export type PutKeyRecordResult = { ok: true; record: SyncKeyRecord } | { ok: false; currentUpdatedAt: Date | null };

export interface SyncStorageAdapter {
  getBlob(accountId: number): Promise<SyncBlobRecord | null>;
  putBlobIfVersionMatches(input: {
    accountId: number;
    baseVersion: number;
    envelopeVersion: number;
    ciphertext: Uint8Array;
  }): Promise<PutBlobResult>;
  listKeyRecords(accountId: number): Promise<SyncKeyRecord[]>;
  /**
   * CAS write (security review finding #2): succeeds only when
   * `expectedUpdatedAt` matches the account's current `(kind)` record —
   * `null` asserts "no record should exist yet" (first-time setup); any
   * other value asserts "the record I last read had exactly this
   * `updatedAt`" (rotation). A mismatch is a conflict, never a blind
   * upsert.
   */
  putKeyRecord(
    input: Omit<SyncKeyRecord, 'updatedAt'> & { expectedUpdatedAt: Date | null },
  ): Promise<PutKeyRecordResult>;
  deleteKeyRecord(input: { accountId: number; kind: SyncKeyRecordKind }): Promise<void>;
}

/**
 * A share row, as the grantee sees it (ADR-0002). `wrappedDek` is the frozen
 * 125-byte asymmetric wrap; the service stores and returns it verbatim and
 * holds no key for it.
 */
export interface SyncShare {
  /** The grantor — whose blob this wrap opens. */
  accountId: number;
  /** The grantee — whose public key the wrap is addressed to. */
  granteeAccountId: number;
  wrappedDek: Uint8Array;
  /** Pinning metadata. Never a key, and the service never endorses it. */
  recipientKeyFingerprint: string;
  createdAt: Date;
  /** The CAS token, exactly as `SyncKeyRecord.updatedAt` is. */
  updatedAt: Date;
}

/**
 * A share row WITHOUT its wrap — the shape the grantor is allowed to see.
 *
 * This is a separate type rather than an `Omit<>` at the route, because the
 * point is that the wrap is never SELECTed for the grantor's list at all: the
 * grantor has no use for a blob addressed to somebody else's key, so it does
 * not travel to where nobody needs it (ADR-0002).
 */
export interface SyncShareSummary {
  accountId: number;
  granteeAccountId: number;
  recipientKeyFingerprint: string;
  createdAt: Date;
  updatedAt: Date;
}

/** Mirrors {@link PutKeyRecordResult}: a losing CAS reports the real current token, never a blind upsert. */
export type PutShareResult = { ok: true; share: SyncShare } | { ok: false; currentUpdatedAt: Date | null };

/**
 * Storage for the share graph, kept OUT of {@link SyncStorageAdapter} on
 * purpose. The owner-only blob/key-record routes must not be able to reach
 * the share tables even by accident, and an instance with `SYNC_SHARING`
 * unset does not construct this at all.
 */
export interface SyncShareStore {
  /**
   * CAS write: `expectedUpdatedAt: null` asserts "no share to this grantee
   * exists yet"; any other value asserts "the row I last read had exactly
   * this `updatedAt`" (a re-wrap after rotation). `no-such-account` is the
   * grantee foreign key refusing a grant to an account that does not exist —
   * reported rather than thrown so the route can answer it without a 500.
   */
  putShare(input: {
    accountId: number;
    granteeAccountId: number;
    wrappedDek: Uint8Array;
    recipientKeyFingerprint: string;
    expectedUpdatedAt: Date | null;
  }): Promise<PutShareResult | { ok: false; reason: 'no-such-account' }>;
  /** The grantor's own grants. Returns summaries — the wrap is never selected here. */
  listSharesByGrantor(accountId: number): Promise<SyncShareSummary[]>;
  /** What has been shared WITH this account. The wrap travels, because only this caller can open it. */
  listSharesByGrantee(granteeAccountId: number): Promise<SyncShare[]>;
  /**
   * The single authorisation lookup for the grantee read path. Checked on
   * EVERY request and never cached — that is what makes a revoke effective
   * on the next request (ADR-0002's Tier 1).
   */
  getShare(input: { accountId: number; granteeAccountId: number }): Promise<SyncShare | null>;
  /** Hard delete, from either end. Idempotent: deleting a row that is not there is not an error. */
  deleteShare(input: { accountId: number; granteeAccountId: number }): Promise<void>;
}

/** The caller a request resolves to. M128 spec 02 replaces the "entitlement" framing with this service's own accounts. */
export interface SyncEntitledUser {
  userId: number;
}

/** Everything `registerSyncRoutes` needs from its host: storage, a way to identify the caller, and somewhere to warn. */
export interface SyncHostContext {
  storage: SyncStorageAdapter;
  resolveEntitledUser: (req: Request) => Promise<SyncEntitledUser | null>;
  /**
   * Optional so the handler tests can stay a two-field object literal. The
   * real shell always supplies one — it is what carries the blob-capacity
   * warning of `server/blob-size-telemetry.ts`, and a capacity cliff nobody
   * can see is a capacity cliff discovered by a user.
   */
  logger?: Logger;
}

/**
 * What `registerShareRoutes` needs. It takes `storage` only to read the
 * GRANTOR's blob by an explicitly-named id — the caller and the target are
 * separate values here, which is the whole point of not reusing
 * `resolveEntitledUser` to pick the target (ADR-0002: doing so would make a
 * grantee BECOME the grantor, including on the write and key-record paths).
 */
export interface SyncShareHostContext {
  shares: SyncShareStore;
  storage: SyncStorageAdapter;
  resolveEntitledUser: (req: Request) => Promise<SyncEntitledUser | null>;
}

// =============================================================================
// Atomic DEK rotation (ADR-0002 Tier 2)
// =============================================================================

/** One re-wrapped key record inside a rotation. Same rules as PROTOCOL.md §5.4, minus the per-record CAS token. */
export interface RotateDekKeyRecordInput {
  kind: SyncKeyRecordKind;
  kdfDescriptor: JsonObject | null;
  wrappedDek: Uint8Array;
}

/** One share the grantor is KEEPING, re-wrapped to the same recipient key under the new DEK. */
export interface RotateDekShareInput {
  granteeAccountId: number;
  wrappedDek: Uint8Array;
  recipientKeyFingerprint: string;
}

/**
 * A whole rotation, as one submission. Everything here lands together or
 * nothing does — see {@link SyncRotationStore}.
 *
 * `shares` is the KEEP list, and that inverts PROTOCOL.md §5.14's
 * untouched-means-kept rule deliberately: these rows are somebody else's
 * capability on the grantor's diary, so silence must be the safe answer.
 */
export interface RotateDekInput {
  accountId: number;
  blob: { baseVersion: number; envelopeVersion: number; ciphertext: Uint8Array };
  /** Both kinds, always — a missing kind is refused before the store is reached. */
  keyRecords: RotateDekKeyRecordInput[];
  /** Only the shares to keep. Every other share row owned by `accountId` is deleted in the same transaction. */
  shares: RotateDekShareInput[];
}

export type RotateDekResult =
  | { ok: true; newVersion: number; keptShares: number; revokedShares: number }
  /** The blob CAS did not hold — same meaning as {@link PutBlobResult}'s conflict, and nothing was written. */
  | { ok: false; reason: 'blob-conflict'; currentVersion: number }
  /** A share named in the keep list does not exist. Rolled back rather than treated as a grant. */
  | { ok: false; reason: 'unknown-share'; granteeAccountId: number };

/**
 * The atomic rotation, kept in its OWN store rather than added to
 * {@link SyncStorageAdapter} or {@link SyncShareStore}: it is the one
 * operation that writes across both of their tables, and it can only be
 * correct if it does so in a single transaction (ADR-0002 prohibition 8 —
 * `rotate-dek` is atomic or it does not exist).
 *
 * Splitting it across the two existing stores would produce exactly the
 * sequence of individually-committing writes that prohibition forbids.
 */
export interface SyncRotationStore {
  rotateDek(input: RotateDekInput): Promise<RotateDekResult>;
}
