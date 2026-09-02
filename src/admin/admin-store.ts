/**
 * The read contract the admin API is written against — the metadata half of
 * `AccountStore`, deliberately kept as a SEPARATE interface rather than
 * grafted onto it.
 *
 * WHY A SECOND INTERFACE AND NOT MORE METHODS ON `AccountStore`. The account
 * store is what the auth handlers hold, and everything on it is something a
 * user's own request may cause: find an account, rotate a credential, revoke
 * a token. Nothing here is. Reading every account on the instance is an
 * operator action, and putting it on the same object would make it reachable
 * — one autocomplete away — from every handler that already has a store in
 * scope. The two capabilities are separated so that a handler cannot enumerate
 * accounts by accident.
 *
 * WHAT IT MAY RETURN IS FIXED BY THE ADR, NOT BY CONVENIENCE. There is no
 * ciphertext here, no verifier, no KDF descriptor, no token and no token
 * digest, and there is no method that could be extended to produce one: the
 * blob is described by its BYTE COUNT and the instant it last changed, and a
 * key record by the fact that it exists. That is a projection, not a habit of
 * remembering not to select a column — see
 * `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md` for what each
 * prohibition is protecting and why an operator has no legitimate use for the
 * material behind it.
 *
 * DELETION IS NOT HERE. It is `AccountStore.deleteAccount`, which the
 * self-service path calls too, so the two erasure paths cannot drift apart.
 * See `server/admin-routes.ts`.
 */
import type { SyncKeyRecordKind } from '../protocol.js';

/** What the admin surface knows about an account. Everything else about it is out of reach by construction. */
export interface AdminAccountSummary {
  id: number;
  /** The account's opaque per-server identifier. It is not an address and cannot be resolved to a person. */
  handle: string;
  createdAt: Date;
  /**
   * The account's current blob, described and never handed over: how many
   * bytes it occupies, and when those bytes last changed. `null` when the
   * account has never pushed one.
   */
  blob: AdminBlobSummary | null;
  /**
   * WHICH key records exist — never their contents. `passphrase` present and
   * `recovery` absent tells an operator the user has no recovery path, which
   * is a real support answer; the wrapped DEK behind either of them is not.
   */
  keyRecordKinds: SyncKeyRecordKind[];
}

export interface AdminBlobSummary {
  sizeBytes: number;
  /**
   * The instant the account's newest blob version was written. Blob rows are
   * append-only (`db/storage-adapter.ts`), so the newest row's `createdAt`
   * IS the blob's last-modified time.
   */
  updatedAt: Date;
}

/** One page of accounts, plus the total the page was taken from. */
export interface AdminAccountPage {
  accounts: AdminAccountSummary[];
  total: number;
}

/** Aggregate counts for the whole instance. Sums and counts only — no row here is attributable to a person. */
export interface AdminStats {
  accounts: number;
  accountsWithBlob: number;
  /** Every retained blob version, not just the newest one — this is what the disk actually holds. */
  blobVersions: number;
  keyRecords: number;
  /** Summed `size_bytes` across every retained blob version. */
  blobBytes: number;
}

export interface ListAccountsInput {
  limit: number;
  offset: number;
}

export interface AdminMetadataStore {
  listAccounts(input: ListAccountsInput): Promise<AdminAccountPage>;
  getAccount(accountId: number): Promise<AdminAccountSummary | null>;
  stats(): Promise<AdminStats>;
}
