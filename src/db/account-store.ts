/**
 * Drizzle implementation of `AccountStore` — the imperative shell under the
 * pure auth handlers.
 *
 * Two things here are load-bearing rather than incidental:
 *
 * 1. **`rotateCredential` is one transaction.** Verifier swap, KDF-descriptor
 *    swap, key-record upsert, session revocation, and the caller's new tokens
 *    all commit together or not at all. A partial application is silent data
 *    loss: a new verifier without the re-wrapped DEK leaves an account that
 *    logs in fine and can never decrypt its own blob again, with nothing to
 *    tell the user until they try.
 * 2. **Account deletion relies on `ON DELETE CASCADE`**, declared on the
 *    `sync_blobs` and `sync_key_records` foreign keys. One DELETE removes the
 *    account and every byte of ciphertext it owns, inside Postgres, with no
 *    application-level cleanup that could be skipped or half-run. That is the
 *    self-serve erasure path.
 */
import { and, eq, inArray, isNull, lt } from 'drizzle-orm';
import type {
  AccountRecord,
  AccountStore,
  CreateAccountInput,
  CreateAccountResult,
  NewTokenInput,
  RotateCredentialInput,
  StoredToken,
} from '../accounts/account-store.js';
import type { AccountTokenKind } from '../lib/tokens.js';
import { SESSION_TOKEN_KINDS } from '../lib/tokens.js';
import { isUniqueViolation } from '../lib/storage-conflict.js';
import type { Database } from './client.js';
import { accountTokens, accounts, syncKeyRecords } from './schema.js';

type AccountRow = typeof accounts.$inferSelect;
type TokenRow = typeof accountTokens.$inferSelect;

function mapAccountRow(row: AccountRow): AccountRecord {
  return {
    id: row.id,
    email: row.email,
    displayName: row.displayName,
    verifier: row.verifier,
    kdfDescriptor: row.kdfDescriptor,
    emailVerifiedAt: row.emailVerifiedAt,
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

    async createAccount(input: CreateAccountInput): Promise<CreateAccountResult> {
      try {
        const [row] = await db
          .insert(accounts)
          .values({
            email: input.email,
            displayName: input.displayName,
            verifier: input.verifier,
            kdfDescriptor: input.kdfDescriptor,
          })
          .returning();
        if (!row) throw new Error('Failed to insert account');
        return { ok: true, account: mapAccountRow(row) };
      } catch (error) {
        // The unique index on `email` is what makes concurrent signups for
        // the same address safe — never a read-then-insert check.
        if (!isUniqueViolation(error)) throw error;
        return { ok: false, reason: 'email-taken' };
      }
    },

    async deleteAccount(accountId: number): Promise<void> {
      await db.delete(accounts).where(eq(accounts.id, accountId));
    },

    async markEmailVerified(input: { accountId: number; verifiedAt: Date }): Promise<void> {
      await db.update(accounts).set({ emailVerifiedAt: input.verifiedAt }).where(eq(accounts.id, input.accountId));
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

    async revokeTokensOfKind(input: { accountId: number; kind: AccountTokenKind; revokedAt: Date }): Promise<void> {
      await db
        .update(accountTokens)
        .set({ revokedAt: input.revokedAt })
        .where(
          and(
            eq(accountTokens.accountId, input.accountId),
            eq(accountTokens.kind, input.kind),
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

        // Upsert only the submitted kinds. A passphrase change re-wraps the
        // DEK under a new passphrase-KEK; the recovery record still wraps the
        // SAME (unchanged) DEK and stays valid, so touching it would destroy a
        // working recovery path for nothing.
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
                updatedAt: input.revokedAt,
              },
            });
        }

        // Every other device is logged out. A user changing their passphrase
        // under suspicion expects exactly this.
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

        if (input.consumeTokenId !== null) {
          await tx
            .update(accountTokens)
            .set({ revokedAt: input.revokedAt })
            .where(and(eq(accountTokens.id, input.consumeTokenId), isNull(accountTokens.revokedAt)));
        }

        if (input.issue.length > 0) {
          await tx.insert(accountTokens).values(tokenValues(input.issue));
        }
      });
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
