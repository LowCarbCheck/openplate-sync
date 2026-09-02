/**
 * The persistence contract the auth handler cores are written against —
 * the account-system counterpart to `contract-types.ts`'s
 * `SyncStorageAdapter`.
 *
 * Every method here is something the handlers need and nothing more. Keeping
 * it an interface rather than importing Drizzle directly is what lets
 * `auth-handlers.ts` stay pure and DB-free: the unit suite injects an
 * in-memory implementation and exercises signup, login, rotation, reuse
 * detection and revocation without a Postgres anywhere. The Drizzle
 * implementation lives in `db/account-store.ts`.
 *
 * `rotateCredential` is the one method whose ATOMICITY is a correctness
 * requirement rather than an implementation detail — see its doc.
 */
import type { SyncKeyRecordKind } from '../protocol.js';
import type { JsonObject } from '../lib/json.js';
import type { AccountTokenKind } from '../lib/tokens.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';

export interface AccountRecord {
  id: number;
  /** Always the normalized form (`lib/verifier.ts`'s `normalizeHandle`) — normalization happens before the store is called. */
  handle: string;
  displayName: string | null;
  verifier: string;
  kdfDescriptor: KdfDescriptor;
  createdAt: Date;
}

/** A persisted token row, reduced to what a lifecycle decision needs. The digest itself never comes back out. */
export interface StoredToken {
  id: number;
  accountId: number;
  kind: AccountTokenKind;
  familyId: string | null;
  expiresAt: Date;
  revokedAt: Date | null;
}

export interface NewTokenInput {
  accountId: number;
  kind: AccountTokenKind;
  tokenHash: string;
  familyId: string | null;
  expiresAt: Date;
}

export interface CreateAccountInput {
  handle: string;
  displayName: string | null;
  verifier: string;
  kdfDescriptor: KdfDescriptor;
}

/** `handle-taken` is the ONLY expected failure; anything else is a real fault and throws. */
export type CreateAccountResult = { ok: true; account: AccountRecord } | { ok: false; reason: 'handle-taken' };

/**
 * The outcome of an invited signup. `invite-invalid` is ONE member covering
 * unknown, expired and already-redeemed tokens: the caller must not be able to
 * tell those apart, and a single member makes that a type-level guarantee
 * rather than three call sites remembering to say the same thing.
 */
export type RedeemInviteResult =
  { ok: true; account: AccountRecord } | { ok: false; reason: 'handle-taken' | 'invite-invalid' };

export interface RedeemInviteAndCreateAccountInput {
  /** SHA-256 hex of the token the caller presented. The raw token never reaches the store. */
  inviteTokenHash: string;
  /** The caller's clock, injected. Expiry is judged against this, never the database's `now()` — see the method's doc. */
  now: Date;
  account: CreateAccountInput;
}

/** A client-re-wrapped DEK submitted as part of a credential rotation. */
export interface KeyRecordSubmission {
  kind: SyncKeyRecordKind;
  kdfDescriptor: JsonObject | null;
  wrappedDek: Uint8Array;
}

export interface RotateCredentialInput {
  accountId: number;
  /** The new verifier — `HMAC(pepper, newAuthHash)`. */
  verifier: string;
  kdfDescriptor: KdfDescriptor;
  /**
   * Re-wrapped DEKs, upserted by `kind`. Kinds NOT submitted are left
   * untouched on purpose: a passphrase change re-wraps only `passphrase`,
   * and the `recovery` record still wraps the same (unchanged) DEK, so
   * deleting it would destroy a working recovery path for no reason.
   */
  keyRecords: KeyRecordSubmission[];
  /** Session tokens minted for the caller, inserted inside the same transaction so a rotation always leaves them logged in. */
  issue: NewTokenInput[];
  /** Instant stamped on every revocation this rotation performs. */
  revokedAt: Date;
}

export interface AccountStore {
  findAccountByHandle(handle: string): Promise<AccountRecord | null>;
  findAccountById(accountId: number): Promise<AccountRecord | null>;
  createAccount(input: CreateAccountInput): Promise<CreateAccountResult>;
  /** Cascades to `sync_blobs` and `sync_key_records` via the schema's FKs — the self-serve DSAR path. */
  deleteAccount(accountId: number): Promise<void>;

  insertTokens(tokens: NewTokenInput[]): Promise<void>;
  findToken(input: { kind: AccountTokenKind; tokenHash: string }): Promise<StoredToken | null>;
  revokeToken(input: { tokenId: number; revokedAt: Date }): Promise<void>;
  /** Revokes one device's lineage — used by logout and by refresh-reuse detection. */
  revokeFamily(input: { accountId: number; familyId: string; revokedAt: Date }): Promise<void>;
  /** Revokes every `access`/`refresh` token for the account. */
  revokeSessions(input: { accountId: number; revokedAt: Date }): Promise<void>;

  /**
   * ATOMIC credential rotation: new verifier + new KDF descriptor + upserted
   * key records + revocation of every outstanding session + the caller's new
   * session, in ONE transaction.
   *
   * This is the seam a recovery-code rotation joins (M181 spec 02): the shape
   * is already "prove something, then move the verifier and the key records
   * together", and the proof is what differs.
   *
   * It has to be one transaction. A partial application is a data-loss bug,
   * not a retryable hiccup: a new verifier stored without the re-wrapped DEK
   * leaves an account that can log in but can never decrypt its own blob
   * again, and the user has no way to tell until they try.
   */
  rotateCredential(input: RotateCredentialInput): Promise<void>;

  /**
   * ATOMIC invited signup: consume one invite and create the account it paid
   * for, in ONE transaction (M166).
   *
   * THIS METHOD EXISTS SO THE HANDLERS STAY PURE. `handleSignup` is policy over
   * an injected context and owns no transaction — that is what lets every auth
   * outcome be unit-tested with no database. Consuming an invite and creating
   * an account is two writes that must succeed or fail together, so the
   * atomicity lives here, in the store, exactly as `rotateCredential` does.
   *
   * IT NEEDS BOTH GUARDS, NOT EITHER:
   *
   *  - A conditional `UPDATE ... WHERE redeemed_at IS NULL` closes the
   *    double-redeem race. Two concurrent redemptions of one invite: exactly
   *    one of them updates a row, because the second finds the predicate false.
   *  - The surrounding TRANSACTION is what gives the invite back when
   *    `createAccount` then hits the unique violation on `handle`. Without it,
   *    probing a taken handle would destroy a capability the person still
   *    needs. A `409` must cost the invite nothing.
   *
   * Expiry is compared against `input.now`, never the database clock. A rule
   * judged by `now()` inside SQL cannot be exercised by the pure test rig that
   * every other expiry rule in this service is tested through.
   */
  redeemInviteAndCreateAccount(input: RedeemInviteAndCreateAccountInput): Promise<RedeemInviteResult>;

  /** Housekeeping: drops rows whose `expiresAt` is far enough in the past to be useless even for reuse detection. */
  purgeExpiredTokens(input: { before: Date }): Promise<number>;
}
