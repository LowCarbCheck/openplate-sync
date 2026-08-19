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
