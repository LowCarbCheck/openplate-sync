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
import type { AccountRole, SyncKeyRecordKind } from '../protocol.js';

/**
 * What the admin surface knows about an account. Everything else about it is
 * out of reach by construction.
 *
 * IT IS A SUPERSET OF THE WIRE'S `AccountView`, NOT A DIFFERENT SHAPE. The
 * M192 contract says the admin account endpoints return `AccountView[]`, and
 * every field of one is here; `blob` and `keyRecordKinds` are the two extra
 * operator facts ADR-0001 requires, and they exist because a storage bill and
 * "does this person have a recovery path" are questions only an operator asks.
 * A client decoding an `AccountView` from an admin response therefore works
 * unchanged, and reads two fields it did not ask for.
 */
export interface AdminAccountSummary {
  id: number;
  /** The account's identity: the canonical address it signs in with. */
  email: string;
  displayName: string | null;
  role: AccountRole;
  dailyAiLimit: number;
  /** AI requests spent on the current UTC day — a count, never a log of what was asked. */
  aiUsedToday: number;
  /** Non-`null` while the account is suspended. */
  suspendedAt: Date | null;
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
  /** Invites minted, not yet redeemed, not revoked, not expired — the letters still outstanding. */
  pendingInvites: number;
  /** Accounts whose `role` is `admin`. An operator's answer to "who else can do this". */
  admins: number;
  /** AI requests every account together spent on the current UTC day. A count, never a log. */
  aiRequestsToday: number;
}

export interface ListAccountsInput {
  limit: number;
  offset: number;
  /** The UTC day `aiUsedToday` is counted over (`lib/utc-day.ts`). Injected, so a test controls "today". */
  day: string;
}

export interface AdminMetadataStore {
  listAccounts(input: ListAccountsInput): Promise<AdminAccountPage>;
  getAccount(input: { accountId: number; day: string }): Promise<AdminAccountSummary | null>;
  /** `now` is injected for the same reason every clock in this repo is: `pendingInvites` and `aiRequestsToday` both key on it. */
  stats(input: { now: Date }): Promise<AdminStats>;
}
