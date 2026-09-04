/**
 * Drizzle implementation of `AccountStore` — the imperative shell under the
 * pure auth handlers.
 *
 * Three things here are load-bearing rather than incidental:
 *
 * 1. **`rotateCredential` and `recoverAndRotatePassphrase` are one transaction
 *    each.** Verifier swap, KDF-descriptor swap, key-record upsert, escrow
 *    re-seal, session revocation, and the caller's new tokens all commit
 *    together or not at all. A partial application is silent data loss: a new
 *    verifier without the re-wrapped DEK leaves an account that logs in fine
 *    and can never decrypt its own blob again, with nothing to tell the user
 *    until they try.
 * 2. **`redeemInviteAndCreateAccount` is one transaction over five writes.**
 *    Invite redemption, account, escrow and both key records. It is the only
 *    door onto this service, so every one of them or none.
 * 3. **Account deletion relies on `ON DELETE CASCADE`**, declared on the
 *    `sync_blobs`, `sync_key_records`, `password_resets` and `ai_usage_days`
 *    foreign keys. One DELETE removes the account and every byte of ciphertext
 *    it owns, inside Postgres, with no application-level cleanup that could be
 *    skipped or half-run. That is the self-serve erasure path.
 */
import { and, eq, gt, inArray, isNull, lt, ne } from 'drizzle-orm';
import type {
  AccountRecord,
  AccountStore,
  ConsumedPasswordReset,
  CreatePasswordResetInput,
  InviteAddressing,
  KeyRecordSubmission,
  NewTokenInput,
  RecoverAndRotatePassphraseInput,
  RecoverAndRotatePassphraseResult,
  RedeemInviteAndCreateAccountInput,
  RedeemInviteResult,
  RotateCredentialInput,
  StoredToken,
  UpdateStandingInput,
} from '../accounts/account-store.js';
import type { AccountTokenKind } from '../lib/tokens.js';
import { SESSION_TOKEN_KINDS } from '../lib/tokens.js';
import { isUniqueViolation } from '../lib/storage-conflict.js';
import type { Database } from './client.js';
import { accountTokens, accounts, aiUsageDays, passwordResets, signupInvites, syncKeyRecords } from './schema.js';

/**
 * Internal control signal for `redeemInviteAndCreateAccount`, never thrown out
 * of this module. A rollback can only be expressed as a throw, so the
 * duplicate-address outcome has to travel as one; this class is what lets the
 * catch tell it apart from a genuine database fault, which must still
 * propagate.
 */
class EmailTakenSignal extends Error {
  constructor() {
    super('email taken');
    this.name = 'EmailTakenSignal';
  }
}

/**
 * Refusal signal for `recoverAndRotatePassphrase`, never thrown out of this
 * module. A `return` from a transaction callback COMMITS what has already
 * been written — the exact half-application this method exists to prevent —
 * so a refusal has to travel as a throw. Same discipline as
 * `db/rotation-store.ts`'s `RotationRefused` and `EmailTakenSignal` above.
 */
class RecoveryRotationRefused extends Error {
  readonly result: RecoverAndRotatePassphraseResult;

  constructor(result: RecoverAndRotatePassphraseResult) {
    super('recovery rotation refused');
    this.name = 'RecoveryRotationRefused';
    this.result = result;
  }
}

/**
 * A transaction handle, as drizzle hands one to a `db.transaction` callback.
 * Named so the shared write helpers below can only be given one.
 */
type Transaction = Parameters<Parameters<Database['transaction']>[0]>[0];

type AccountRow = typeof accounts.$inferSelect;
type TokenRow = typeof accountTokens.$inferSelect;

function mapAccountRow(row: AccountRow): AccountRecord {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    role: row.role,
    dailyAiLimit: row.dailyAiLimit,
    suspendedAt: row.suspendedAt,
    verifier: row.verifier,
    recoveryVerifier: row.recoveryVerifier,
    kdfDescriptor: row.kdfDescriptor,
    createdAt: row.createdAt,
  };
}

function mapTokenRow(row: TokenRow): StoredToken {
  return {
    id: row.id,
    accountId: row.accountId,
    kind: row.kind,
    familyId: row.familyId,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
  };
}

/** The mutable rows of a token insert, shared by the standalone and in-transaction paths. */
function tokenValues(tokens: NewTokenInput[]): (typeof accountTokens.$inferInsert)[] {
  return tokens.map((token) => ({
    accountId: token.accountId,
    kind: token.kind,
    tokenHash: token.tokenHash,
    familyId: token.familyId,
    expiresAt: token.expiresAt,
  }));
}

/**
 * Upserts the submitted re-wrapped DEKs, one row per `kind`.
 *
 * Shared by every rotation so they can never drift: `tx` is always a
 * TRANSACTION handle, never the pool, because a key-record write that lands
 * outside its rotation's transaction is exactly the half-state its callers
 * exist to prevent.
 *
 * Kinds NOT submitted are left untouched on purpose. A passphrase change
 * re-wraps only `passphrase`; the `recovery` record still wraps the SAME
 * (unchanged) DEK and stays valid, so touching it would destroy a working
 * recovery path for nothing.
 */
async function upsertKeyRecords(
  tx: Transaction,
  input: { accountId: number; keyRecords: KeyRecordSubmission[]; updatedAt: Date },
): Promise<void> {
  for (const record of input.keyRecords) {
    await tx
      .insert(syncKeyRecords)
      .values({
        accountId: input.accountId,
        kind: record.kind,
        kdfDescriptor: record.kdfDescriptor,
        wrappedDek: Buffer.from(record.wrappedDek),
      })
      .onConflictDoUpdate({
        target: [syncKeyRecords.accountId, syncKeyRecords.kind],
        set: {
          kdfDescriptor: record.kdfDescriptor,
          wrappedDek: Buffer.from(record.wrappedDek),
          updatedAt: input.updatedAt,
        },
      });
  }
}

/** Revokes every live session for one account. Transaction-scoped, for the same reason {@link upsertKeyRecords} is. */
async function revokeSessionsIn(tx: Transaction, input: { accountId: number; revokedAt: Date }): Promise<void> {
  await tx
    .update(accountTokens)
    .set({ revokedAt: input.revokedAt })
    .where(
      and(
        eq(accountTokens.accountId, input.accountId),
        inArray(accountTokens.kind, [...SESSION_TOKEN_KINDS]),
        isNull(accountTokens.revokedAt),
      ),
    );
}

export function createDrizzleAccountStore(db: Database): AccountStore {
  return {
    async findAccountByEmail(email: string): Promise<AccountRecord | null> {
      const [row] = await db.select().from(accounts).where(eq(accounts.email, email)).limit(1);
      return row ? mapAccountRow(row) : null;
    },

    async findAccountById(accountId: number): Promise<AccountRecord | null> {
      const [row] = await db.select().from(accounts).where(eq(accounts.id, accountId)).limit(1);
      return row ? mapAccountRow(row) : null;
    },

    async updateDisplayName(input: { accountId: number; displayName: string | null }): Promise<AccountRecord | null> {
      const [row] = await db
        .update(accounts)
        .set({ displayName: input.displayName })
        .where(eq(accounts.id, input.accountId))
        .returning();
      return row ? mapAccountRow(row) : null;
    },

    async updateStanding(input: UpdateStandingInput): Promise<AccountRecord | null> {
      // `undefined` omits a column from the SET list, which is how "leave it
      // alone" is expressed. `displayName: null` is a real value here — it
      // CLEARS the name — which is why it is spread conditionally on the key's
      // presence rather than on the value's nullness.
      const changes: Partial<typeof accounts.$inferInsert> = {};
      if (input.role !== undefined) changes.role = input.role;
      if (input.dailyAiLimit !== undefined) changes.dailyAiLimit = input.dailyAiLimit;
      if (input.displayName !== undefined) changes.displayName = input.displayName;

      // An empty patch is refused by the route, so this is unreachable; reading
      // the row back rather than issuing `SET` with nothing in it keeps the
      // method total instead of letting Drizzle build invalid SQL.
      if (Object.keys(changes).length === 0) {
        const [existing] = await db.select().from(accounts).where(eq(accounts.id, input.accountId)).limit(1);
        return existing ? mapAccountRow(existing) : null;
      }

      const [row] = await db.update(accounts).set(changes).where(eq(accounts.id, input.accountId)).returning();
      return row ? mapAccountRow(row) : null;
    },

    async suspendAccount(input: { accountId: number; suspendedAt: Date }): Promise<AccountRecord | null> {
      // ONE transaction, because the two halves are one act: a `suspended_at`
      // without the revocation leaves the person's phone syncing for another
      // quarter of an hour, and an operator who suspends somebody means now.
      return await db.transaction(async (tx): Promise<AccountRecord | null> => {
        const [row] = await tx
          .update(accounts)
          // `isNull` guard: a second suspension keeps the instant of the first,
          // which is the one an operator would look for in an audit.
          .set({ suspendedAt: input.suspendedAt })
          .where(and(eq(accounts.id, input.accountId), isNull(accounts.suspendedAt)))
          .returning();

        if (!row) {
          // Either no such account, or it was already suspended. Read it back
          // so an idempotent re-suspend still reports the account rather than
          // reading as "no such account".
          const [existing] = await tx.select().from(accounts).where(eq(accounts.id, input.accountId)).limit(1);
          return existing ? mapAccountRow(existing) : null;
        }

        await revokeSessionsIn(tx, { accountId: input.accountId, revokedAt: input.suspendedAt });
        return mapAccountRow(row);
      });
    },

    async reactivateAccount(accountId: number): Promise<AccountRecord | null> {
      const [row] = await db.update(accounts).set({ suspendedAt: null }).where(eq(accounts.id, accountId)).returning();
      return row ? mapAccountRow(row) : null;
    },

    async touchLastSeen(input: { accountId: number; seenAt: Date }): Promise<void> {
      await db.update(accounts).set({ lastSeenAt: input.seenAt }).where(eq(accounts.id, input.accountId));
    },

    async aiUsageOn(input: { accountId: number; day: string }): Promise<number> {
      const [row] = await db
        .select({ count: aiUsageDays.count })
        .from(aiUsageDays)
        .where(and(eq(aiUsageDays.accountId, input.accountId), eq(aiUsageDays.day, input.day)))
        .limit(1);
      // No row means no request today, which is zero rather than an absence
      // the caller has to interpret.
      return row?.count ?? 0;
    },

    async redeemInviteAndCreateAccount(input: RedeemInviteAndCreateAccountInput): Promise<RedeemInviteResult> {
      // ONE transaction, because a consumed invite with no account is a
      // capability destroyed for nothing, and an account with an unconsumed
      // invite is a capability that can be spent twice.
      //
      // The taken-address case is signalled by THROWING rather than returning,
      // and the reason is explicitness rather than necessity. Postgres has
      // already aborted the transaction by the time the unique violation
      // surfaces, so a plain `return` would issue a COMMIT that the server
      // treats as a ROLLBACK and the invite would survive either way. Relying
      // on that would make the guarantee depend on a subtlety no reader of this
      // method can see. The throw states the intent in the code, and is caught
      // immediately below so nothing outside this method sees an exception.
      //
      // What is genuinely load-bearing is the TRANSACTION itself: with the
      // statements run outside one, the claim commits on its own and a
      // duplicate-address signup burns the invite. `tests/integration/
      // signup-invites.test.ts` fails on exactly that change.
      try {
        return await db.transaction(async (tx): Promise<RedeemInviteResult> => {
          // The conditional UPDATE is the race guard. Two concurrent redemptions
          // of the same invite both reach this statement; the row-level lock
          // serialises them, and the second one finds `redeemed_at` no longer
          // NULL and updates nothing. Never a SELECT-then-UPDATE, which would
          // let both readers see it unredeemed.
          //
          // Expiry is compared against the INJECTED clock, not `now()`, so the
          // rule stays exercisable from a test that controls time.
          const [claimed] = await tx
            .update(signupInvites)
            .set({ redeemedAt: input.now })
            .where(
              and(
                eq(signupInvites.tokenHash, input.inviteTokenHash),
                isNull(signupInvites.redeemedAt),
                isNull(signupInvites.revokedAt),
                gt(signupInvites.expiresAt, input.now),
              ),
            )
            .returning();

          // Unknown, expired, revoked and already-spent all land here,
          // indistinguishably.
          if (!claimed) return { ok: false, reason: 'invite-invalid' };

          let account: AccountRow | undefined;
          try {
            [account] = await tx
              .insert(accounts)
              .values({
                // THE ADDRESS COMES FROM THE INVITE ROW. This line is what
                // makes the invitation the address verification: a signup body
                // cannot name a mailbox the operator did not write to.
                email: claimed.email,
                displayName: input.account.displayName,
                role: claimed.role,
                dailyAiLimit: claimed.dailyAiLimit,
                verifier: input.account.verifier,
                recoveryVerifier: input.account.recoveryVerifier,
                kdfDescriptor: input.account.kdfDescriptor,
                recoveryCodeEscrow: input.account.recoveryCodeEscrow,
              })
              .returning();
          } catch (error) {
            if (!isUniqueViolation(error)) throw error;
            // THE INVITE MUST SURVIVE THIS. The address already has an account,
            // which is the operator's mistake and not a reason to burn a
            // capability somebody still needs. Unwinding the transaction
            // un-claims the invite by undoing the UPDATE above — precisely why
            // the transaction is here and the conditional UPDATE alone would
            // not be enough.
            throw new EmailTakenSignal();
          }
          if (!account) throw new Error('Failed to insert account');

          // Both key records, in the same transaction. An account without them
          // logs in and decrypts nothing, and the client has already thrown the
          // passphrase away by the time it would find out.
          await upsertKeyRecords(tx, {
            accountId: account.id,
            keyRecords: input.account.keyRecords,
            updatedAt: input.now,
          });

          await tx.update(signupInvites).set({ redeemedAccountId: account.id }).where(eq(signupInvites.id, claimed.id));

          return { ok: true, account: mapAccountRow(account) };
        });
      } catch (error) {
        if (error instanceof EmailTakenSignal) return { ok: false, reason: 'email-taken' };
        throw error;
      }
    },

    async findInviteAddressing(input: { inviteTokenHash: string; now: Date }): Promise<InviteAddressing | null> {
      // The predicate is the SAME one the redemption applies, so a token that
      // looks up here is a token that would redeem. `token_hash` is matched but
      // never selected.
      const [row] = await db
        .select({
          email: signupInvites.email,
          displayName: signupInvites.displayName,
          expiresAt: signupInvites.expiresAt,
        })
        .from(signupInvites)
        .where(
          and(
            eq(signupInvites.tokenHash, input.inviteTokenHash),
            isNull(signupInvites.redeemedAt),
            isNull(signupInvites.revokedAt),
            gt(signupInvites.expiresAt, input.now),
          ),
        )
        .limit(1);
      return row ?? null;
    },

    async createPasswordReset(input: CreatePasswordResetInput): Promise<void> {
      await db.transaction(async (tx) => {
        const [row] = await tx
          .insert(passwordResets)
          .values({
            accountId: input.accountId,
            tokenHash: input.tokenHash,
            expiresAt: input.expiresAt,
          })
          .returning({ id: passwordResets.id });
        if (!row) throw new Error('Failed to insert password reset');

        // SUPERSEDE EVERY OLDER LIVE TOKEN, in the same transaction and after
        // the insert so the new row's own id can be excluded by `ne`. Two live
        // letters in one mailbox is a second copy of a credential that hands
        // over a recovery code.
        await tx
          .update(passwordResets)
          .set({ consumedAt: input.now })
          .where(
            and(
              eq(passwordResets.accountId, input.accountId),
              ne(passwordResets.id, row.id),
              isNull(passwordResets.consumedAt),
            ),
          );
      });
    },

    async consumePasswordReset(input: { tokenHash: string; now: Date }): Promise<ConsumedPasswordReset | null> {
      // ONE statement for the spend, so two requests carrying one token cannot
      // both pass a read. The account is read afterwards, by the id the UPDATE
      // returned: a join would need the same row lock and would not make the
      // spend any more atomic than it already is.
      const [claimed] = await db
        .update(passwordResets)
        .set({ consumedAt: input.now })
        .where(
          and(
            eq(passwordResets.tokenHash, input.tokenHash),
            isNull(passwordResets.consumedAt),
            gt(passwordResets.expiresAt, input.now),
          ),
        )
        .returning({ accountId: passwordResets.accountId });

      // Unknown, spent and expired all land here, indistinguishably.
      if (!claimed) return null;

      const [account] = await db
        .select({ email: accounts.email, recoveryCodeEscrow: accounts.recoveryCodeEscrow })
        .from(accounts)
        .where(eq(accounts.id, claimed.accountId))
        .limit(1);
      // The cascade means a deleted account takes its reset rows with it, so
      // this is unreachable in practice; `null` rather than a throw keeps the
      // handler's one answer for every miss.
      if (!account || account.recoveryCodeEscrow === null) return null;

      return { email: account.email, recoveryCodeEscrow: account.recoveryCodeEscrow };
    },

    async deleteAccount(accountId: number): Promise<void> {
      await db.delete(accounts).where(eq(accounts.id, accountId));
    },

    async insertTokens(tokens: NewTokenInput[]): Promise<void> {
      if (tokens.length === 0) return;
      await db.insert(accountTokens).values(tokenValues(tokens));
    },

    async findToken(input: { kind: AccountTokenKind; tokenHash: string }): Promise<StoredToken | null> {
      const [row] = await db
        .select()
        .from(accountTokens)
        .where(and(eq(accountTokens.tokenHash, input.tokenHash), eq(accountTokens.kind, input.kind)))
        .limit(1);
      return row ? mapTokenRow(row) : null;
    },

    async revokeToken(input: { tokenId: number; revokedAt: Date }): Promise<void> {
      // `isNull` guard: revocation is stamped once, so a re-revoked token keeps
      // the instant it was actually invalidated.
      await db
        .update(accountTokens)
        .set({ revokedAt: input.revokedAt })
        .where(and(eq(accountTokens.id, input.tokenId), isNull(accountTokens.revokedAt)));
    },

    async revokeFamily(input: { accountId: number; familyId: string; revokedAt: Date }): Promise<void> {
      await db
        .update(accountTokens)
        .set({ revokedAt: input.revokedAt })
        .where(
          and(
            eq(accountTokens.accountId, input.accountId),
            eq(accountTokens.familyId, input.familyId),
            isNull(accountTokens.revokedAt),
          ),
        );
    },

    async revokeSessions(input: { accountId: number; revokedAt: Date }): Promise<void> {
      await db
        .update(accountTokens)
        .set({ revokedAt: input.revokedAt })
        .where(
          and(
            eq(accountTokens.accountId, input.accountId),
            inArray(accountTokens.kind, [...SESSION_TOKEN_KINDS]),
            isNull(accountTokens.revokedAt),
          ),
        );
    },

    async rotateCredential(input: RotateCredentialInput): Promise<void> {
      await db.transaction(async (tx) => {
        await tx
          .update(accounts)
          .set({ verifier: input.verifier, kdfDescriptor: input.kdfDescriptor })
          .where(eq(accounts.id, input.accountId));

        await upsertKeyRecords(tx, {
          accountId: input.accountId,
          keyRecords: input.keyRecords,
          updatedAt: input.revokedAt,
        });

        // Every other device is logged out. A user changing their passphrase
        // under suspicion expects exactly this.
        await revokeSessionsIn(tx, { accountId: input.accountId, revokedAt: input.revokedAt });

        if (input.issue.length > 0) {
          await tx.insert(accountTokens).values(tokenValues(input.issue));
        }
      });
    },

    async recoverAndRotatePassphrase(
      input: RecoverAndRotatePassphraseInput,
    ): Promise<RecoverAndRotatePassphraseResult> {
      // ONE transaction, and the writes below are the whole reason this
      // method exists rather than a handler calling the store four times. See
      // `AccountStore.recoverAndRotatePassphrase` for what each half-state
      // costs the user; none of them is recoverable and none is visible until
      // they try to read their own diary.
      try {
        return await db.transaction(async (tx): Promise<RecoverAndRotatePassphraseResult> => {
          // (1) to (3): the passphrase verifier and, when the user is also
          // replacing their code, the recovery verifier AND the re-sealed
          // escrow — in one UPDATE, guarded by the recovery verifier the
          // handler matched. Zero rows means another rotation committed in
          // between, so this one is operating on a credential that no longer
          // exists and must not proceed.
          const [updated] = await tx
            .update(accounts)
            .set({
              verifier: input.verifier,
              kdfDescriptor: input.kdfDescriptor,
              // `undefined` omits the column from the SET list, which is how a
              // rotation that keeps the existing code leaves it alone. `null`
              // would CLEAR it and silently destroy the second authenticator.
              recoveryVerifier: input.newRecoveryVerifier ?? undefined,
              // Same rule, same reason: an escrow cleared here is a mailed
              // reset that can never be answered again.
              recoveryCodeEscrow: input.newRecoveryCodeEscrow ?? undefined,
            })
            .where(and(eq(accounts.id, input.accountId), eq(accounts.recoveryVerifier, input.expectedRecoveryVerifier)))
            .returning({ id: accounts.id });

          if (!updated) throw new RecoveryRotationRefused({ ok: false, reason: 'recovery-superseded' });

          // (4) and (5): the re-wrapped `passphrase` record, and the `recovery`
          // record when the code itself moved. Same statement as an ordinary
          // change-passphrase, inside this transaction.
          await upsertKeyRecords(tx, {
            accountId: input.accountId,
            keyRecords: input.keyRecords,
            updatedAt: input.revokedAt,
          });

          // A recovery is a stronger event than a passphrase change: whoever
          // held the old passphrase is, by construction, not the person doing
          // this. Every outstanding session goes.
          await revokeSessionsIn(tx, { accountId: input.accountId, revokedAt: input.revokedAt });

          if (input.issue.length > 0) {
            await tx.insert(accountTokens).values(tokenValues(input.issue));
          }

          return { ok: true };
        });
      } catch (error) {
        if (error instanceof RecoveryRotationRefused) return error.result;
        throw error;
      }
    },

    async purgeExpiredTokens(input: { before: Date }): Promise<number> {
      const rows = await db
        .delete(accountTokens)
        .where(lt(accountTokens.expiresAt, input.before))
        .returning({ id: accountTokens.id });
      return rows.length;
    },
  };
}
