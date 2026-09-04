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
import type { AccountRole, SyncKeyRecordKind } from '../protocol.js';
import type { JsonObject } from '../lib/json.js';
import type { AccountTokenKind } from '../lib/tokens.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';

export interface AccountRecord {
  id: number;
  /** Always the normalized form (`lib/verifier.ts`'s `normalizeEmail`) — normalization happens before the store is called. */
  email: string;
  displayName: string | null;
  /** `'admin'` or `'member'`. Carried from the invite at signup; changed only by an operator. */
  role: AccountRole;
  /** AI requests allowed per UTC day. `0` means this account has no AI. */
  dailyAiLimit: number;
  /**
   * Non-`null` while the account is suspended. Every caller that authenticates
   * an account MUST check this — login, refresh, the bearer middleware and the
   * recovery paths all answer `403 account-suspended` for a non-`null` value.
   */
  suspendedAt: Date | null;
  verifier: string;
  /**
   * The recovery-code verifier — `HMAC(pepper, recoveryAuthHash)`, or `null`
   * for an account that has no second authenticator. See the schema column
   * for why its HKDF label is not the recovery-KEK label.
   */
  recoveryVerifier: string | null;
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

/**
 * The account material a signup submits. The EMAIL IS ABSENT ON PURPOSE: it
 * comes from the invite row, inside the same transaction, so a request body
 * cannot claim an address the operator did not invite. Same for `role` and
 * `dailyAiLimit` — an invite grants standing, and a signup body never asks
 * for any.
 */
export interface CreateAccountInput {
  displayName: string | null;
  verifier: string;
  /** The recovery-code verifier. Required since M192: a client that hides the code must leave a way back in. */
  recoveryVerifier: string;
  kdfDescriptor: KdfDescriptor;
  /** The sealed recovery code (`lib/escrow.ts`). Written in the same statement as the account. */
  recoveryCodeEscrow: Buffer;
  /** The DEK wrapped under the passphrase KEK and under the recovery KEK — exactly one record of each kind. */
  keyRecords: KeyRecordSubmission[];
}

/**
 * The outcome of an invited signup. `invite-invalid` is ONE member covering
 * unknown, expired, revoked and already-redeemed tokens: the caller must not
 * be able to tell those apart, and a single member makes that a type-level
 * guarantee rather than four call sites remembering to say the same thing.
 *
 * `email-taken` is the separate `409`, and it must leave the invite spendable.
 */
export type RedeemInviteResult =
  { ok: true; account: AccountRecord } | { ok: false; reason: 'email-taken' | 'invite-invalid' };

export interface RedeemInviteAndCreateAccountInput {
  /** SHA-256 hex of the token the caller presented. The raw token never reaches the store. */
  inviteTokenHash: string;
  /** The caller's clock, injected. Expiry is judged against this, never the database's `now()` — see the method's doc. */
  now: Date;
  account: CreateAccountInput;
}

/**
 * What `POST /v1/auth/invite-lookup` shows a person before they choose a
 * passphrase: the address the invitation was sent to, and the name the
 * operator typed. Nothing about the account it will create, and nothing that
 * would let a caller enumerate invites — every bad token is one `404`.
 */
export interface InviteAddressing {
  email: string;
  displayName: string | null;
  expiresAt: Date;
}

/** The one thing `POST /v1/auth/reset/open` returns, read out of the account the consumed token belonged to. */
export interface ConsumedPasswordReset {
  email: string;
  /** The sealed bytes, still sealed. Opening them is `lib/escrow.ts`'s job and the handler's decision. */
  recoveryCodeEscrow: Buffer;
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

/**
 * A recovery-code rotation: the whole move a user makes when they have lost
 * their passphrase and still hold their recovery code.
 *
 * `expectedRecoveryVerifier` makes the write a COMPARE-AND-SWAP rather than a
 * blind update. The handler has already checked the proof, so this is not the
 * authentication — it is the guard against two rotations racing. Without it,
 * a second recovery that started before the first committed would overwrite a
 * verifier the user has already been told is theirs, and would do it under a
 * recovery code that is no longer current.
 */
export interface RecoverAndRotatePassphraseInput {
  accountId: number;
  /** The recovery verifier the handler matched against, re-asserted inside the transaction. */
  expectedRecoveryVerifier: string;
  /** The new passphrase verifier — `HMAC(pepper, newAuthHash)`. */
  verifier: string;
  kdfDescriptor: KdfDescriptor;
  /**
   * The new recovery verifier when the user is also replacing their recovery
   * code, `null` to leave the existing one in place. A non-`null` value must
   * arrive with a `recovery` key record; the handler refuses the pair
   * half-supplied, because a rotated code whose record still wraps under the
   * old one authenticates and then unwraps nothing.
   */
  newRecoveryVerifier: string | null;
  /**
   * The re-sealed recovery code, or `null` to leave the escrow untouched.
   *
   * A FOURTH THING THAT MOVES WITH THE OTHER THREE. It arrives exactly when
   * {@link RecoverAndRotatePassphraseInput.newRecoveryVerifier} does, and it is
   * written inside the same transaction: an escrow that still holds the OLD
   * code after a rotation is a mailed reset that hands somebody a code the
   * account no longer accepts, discovered on the day they need it.
   */
  newRecoveryCodeEscrow: Buffer | null;
  /** Re-wrapped DEKs, upserted by `kind`, exactly as {@link RotateCredentialInput.keyRecords}. */
  keyRecords: KeyRecordSubmission[];
  /** Session tokens minted for the caller, inserted inside the same transaction. */
  issue: NewTokenInput[];
  /** Instant stamped on every revocation this rotation performs. */
  revokedAt: Date;
}

/**
 * `recovery-superseded` is the ONLY expected failure: the account's recovery
 * verifier changed between the handler's check and the transaction, so this
 * rotation is operating on a credential that no longer exists. The caller
 * reports it as the same generic failure a wrong code gets — a race must not
 * be distinguishable from a bad guess.
 */
export type RecoverAndRotatePassphraseResult = { ok: true } | { ok: false; reason: 'recovery-superseded' };

export interface AccountStore {
  findAccountByEmail(email: string): Promise<AccountRecord | null>;
  findAccountById(accountId: number): Promise<AccountRecord | null>;
  /** Cascades to `sync_blobs` and `sync_key_records` via the schema's FKs — the self-serve DSAR path. */
  deleteAccount(accountId: number): Promise<void>;

  /**
   * `PATCH /v1/auth/account` — the ONE field an account owner may change about
   * themselves here. `null` clears it.
   *
   * Everything else on the row is either authentication material, which moves
   * only through a rotation, or standing an operator granted, which an account
   * must not be able to raise for itself.
   */
  updateDisplayName(input: { accountId: number; displayName: string | null }): Promise<AccountRecord | null>;

  /**
   * The operator's edit: role, allowance and display name, each optional and
   * each meaning "leave it alone" when absent.
   *
   * SEPARATE FROM {@link AccountStore.updateDisplayName}, which is the OWNER's
   * edit and can change nothing else. Folding the two into one method would
   * leave the self-service handler one argument away from raising its own
   * allowance, which is exactly the reachability the split exists to remove.
   *
   * Suspension is NOT here: it has to revoke every session in the same effect,
   * so it is {@link AccountStore.suspendAccount}.
   */
  updateStanding(input: UpdateStandingInput): Promise<AccountRecord | null>;

  /**
   * Suspends an account AND revokes every one of its session tokens, in that
   * order and as one effect.
   *
   * BOTH HALVES OR THE SUSPENSION IS COSMETIC. `suspended_at` alone stops the
   * next login; it does not stop the access token already in a phone, which
   * stays valid for up to fifteen minutes and whose refresh token stays valid
   * for thirty days. An operator who suspends somebody means "now".
   */
  suspendAccount(input: { accountId: number; suspendedAt: Date }): Promise<AccountRecord | null>;

  /** Clears `suspended_at`. Deliberately does NOT restore any session: the person signs in again. */
  reactivateAccount(accountId: number): Promise<AccountRecord | null>;

  /**
   * Stamps `accounts.last_seen_at`. Operator diagnostics only: never a rate
   * limit, never an authorization input.
   *
   * ITS ONE CALLER IS THE AI PROXY, and that is a deliberate narrowing rather
   * than the obvious place. Writing it from the bearer middleware would mean
   * one UPDATE on every authenticated request, including every sync poll, to
   * answer a question no code asks. The proxy is a request a person made on
   * purpose, so "last seen" means what an operator reads it as.
   */
  touchLastSeen(input: { accountId: number; seenAt: Date }): Promise<void>;


  /** How many AI requests this account has spent on the given UTC day (`lib/utc-day.ts`). Read-only here; spec 03 writes. */
  aiUsageOn(input: { accountId: number; day: string }): Promise<number>;

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
   * ATOMIC recovery-code rotation: the new passphrase verifier, the new KDF
   * descriptor, an optionally-new recovery verifier, the re-wrapped key
   * records, the revocation of every outstanding session and the caller's new
   * session — in ONE transaction.
   *
   * EVERY HALF-STATE HERE IS A DISTINCT DISASTER, which is why this is one
   * method rather than a handler calling four:
   *
   *  - verifier moved, `passphrase` key record not: the user logs in with the
   *    new passphrase and decrypts nothing. That is the exact brick
   *    `server/rotate-dek-handler.ts` already refuses to create.
   *  - key record moved, verifier not: the user cannot log in at all, and the
   *    old passphrase they no longer have is the only key to a DEK that has
   *    just been re-wrapped away from it.
   *  - recovery verifier moved, `recovery` key record not: the code that
   *    authenticates no longer unwraps.
   *
   * None of these is a retryable hiccup and none of them is visible until the
   * user tries. Postgres is where the guarantee lives; the integration suite
   * injects a failure part-way through and asserts the account is untouched.
   */
  recoverAndRotatePassphrase(input: RecoverAndRotatePassphraseInput): Promise<RecoverAndRotatePassphraseResult>;

  /**
   * ATOMIC invited signup: consume one addressed invite and create the account
   * it paid for, in ONE transaction (M166, widened in M192).
   *
   * THIS METHOD EXISTS SO THE HANDLERS STAY PURE. `handleSignup` is policy over
   * an injected context and owns no transaction — that is what lets every auth
   * outcome be unit-tested with no database. Since M192 it commits FIVE things
   * together: the invite redemption, the account (with the invite's email, role
   * and allowance), the sealed recovery code, and both key records. Every one
   * of them is useless without the others.
   *
   * IT NEEDS BOTH GUARDS, NOT EITHER:
   *
   *  - A conditional `UPDATE ... WHERE redeemed_at IS NULL AND revoked_at IS
   *    NULL AND expires_at > now` closes the double-redeem race. Two concurrent
   *    redemptions of one invite: exactly one of them updates a row, because
   *    the second finds the predicate false.
   *  - The surrounding TRANSACTION is what gives the invite back when the
   *    account insert then hits the unique violation on `email`. Without it, a
   *    signup for an address that already has an account would destroy a
   *    capability the person still needs. A `409` must cost the invite nothing.
   *
   * Expiry is compared against `input.now`, never the database clock. A rule
   * judged by `now()` inside SQL cannot be exercised by the pure test rig that
   * every other expiry rule in this service is tested through.
   */
  redeemInviteAndCreateAccount(input: RedeemInviteAndCreateAccountInput): Promise<RedeemInviteResult>;

  /**
   * `POST /v1/auth/invite-lookup` — who an invite is addressed to, or `null`.
   *
   * ONE `null` FOR FOUR CAUSES, exactly as {@link RedeemInviteResult}'s
   * `invite-invalid` covers four: unknown, expired, revoked and already
   * redeemed. The endpoint above it answers `404` for all of them after
   * identical work, so holding a spent invite tells a caller nothing a
   * fictional one would not.
   */
  findInviteAddressing(input: { inviteTokenHash: string; now: Date }): Promise<InviteAddressing | null>;

  /**
   * Records a password-reset token, superseding every older live one for the
   * same account, in ONE transaction.
   *
   * SUPERSEDING IS PART OF THE WRITE, not a separate call. Two letters in a
   * mailbox, both live, is a second copy of a credential that hands over a
   * recovery code — and the person who asked twice is exactly the person who
   * would redeem the older one by scrolling up.
   */
  createPasswordReset(input: CreatePasswordResetInput): Promise<void>;

  /**
   * `POST /v1/auth/reset/open` — spends a reset token and returns what it was
   * worth, or `null`.
   *
   * ONE STATEMENT, and it must stay one: `UPDATE ... WHERE consumed_at IS NULL
   * AND expires_at > now RETURNING`. A read-then-write would let two requests
   * both pass the read and both be told the recovery code, which is the one
   * thing a single-use token exists to prevent.
   *
   * `null` covers unknown, spent and expired alike — the caller answers `404
   * reset-invalid` to all three.
   */
  consumePasswordReset(input: { tokenHash: string; now: Date }): Promise<ConsumedPasswordReset | null>;

  /** Housekeeping: drops rows whose `expiresAt` is far enough in the past to be useless even for reuse detection. */
  purgeExpiredTokens(input: { before: Date }): Promise<number>;
}

export interface UpdateStandingInput {
  accountId: number;
  role?: AccountRole;
  dailyAiLimit?: number;
  displayName?: string | null;
}

export interface CreatePasswordResetInput {
  accountId: number;
  /** SHA-256 hex of the raw `sr_` token. The raw value exists only in the mail. */
  tokenHash: string;
  expiresAt: Date;
  /** Stamped on the rows this request supersedes. Injected, like every other instant in this contract. */
  now: Date;
}
