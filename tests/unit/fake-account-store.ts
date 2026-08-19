/**
 * In-memory `AccountStore` for the auth handler tests — the account-system
 * counterpart to `fake-storage-adapter.ts`.
 *
 * It implements the same semantics the Drizzle store must: unique emails,
 * digest-keyed token lookup, revocation that is stamped once and never
 * cleared, and a `rotateCredential` that applies its whole effect. The last
 * one is the reason this fake is worth having — the handler tests can assert
 * that a rotation revoked every session AND upserted the key records AND
 * consumed the link token, without a database.
 *
 * It deliberately does NOT simulate a transaction rollback. Atomicity is a
 * property of Postgres, and the integration suite is where it is exercised.
 */
import type {
  AccountRecord,
  AccountStore,
  CreateAccountInput,
  CreateAccountResult,
  KeyRecordSubmission,
  NewTokenInput,
  RotateCredentialInput,
  StoredToken,
} from '../../src/accounts/account-store.js';
import type { AccountTokenKind } from '../../src/lib/tokens.js';
import { SESSION_TOKEN_KINDS } from '../../src/lib/tokens.js';
import type { SyncKeyRecordKind } from '../../src/protocol.js';

interface StoredTokenRow extends StoredToken {
  tokenHash: string;
}

export interface FakeAccountStore extends AccountStore {
  /** Test-only: the key records a rotation wrote, by account then kind. */
  keyRecordsFor(accountId: number): Map<SyncKeyRecordKind, KeyRecordSubmission>;
  /** Test-only: every token row, so a test can assert on revocation state. */
  allTokens(): StoredTokenRow[];
  /** Test-only: whether the account row still exists. */
  hasAccount(accountId: number): boolean;
}

export function createFakeAccountStore(): FakeAccountStore {
  const accountsById = new Map<number, AccountRecord>();
  const tokens: StoredTokenRow[] = [];
  const keyRecords = new Map<number, Map<SyncKeyRecordKind, KeyRecordSubmission>>();
  let nextAccountId = 1;
  let nextTokenId = 1;

  function revokeMatching(predicate: (token: StoredTokenRow) => boolean, revokedAt: Date): void {
    for (const token of tokens) {
      if (token.revokedAt === null && predicate(token)) token.revokedAt = revokedAt;
    }
  }

  function upsertKeyRecords(accountId: number, records: KeyRecordSubmission[]): void {
    const forAccount = keyRecords.get(accountId) ?? new Map<SyncKeyRecordKind, KeyRecordSubmission>();
    for (const record of records) {
      forAccount.set(record.kind, record);
    }
    keyRecords.set(accountId, forAccount);
  }

  return {
    async findAccountByEmail(email: string): Promise<AccountRecord | null> {
      for (const account of accountsById.values()) {
        if (account.email === email) return { ...account };
      }
      return null;
    },

    async findAccountById(accountId: number): Promise<AccountRecord | null> {
      const account = accountsById.get(accountId);
      return account ? { ...account } : null;
    },

    async createAccount(input: CreateAccountInput): Promise<CreateAccountResult> {
      for (const account of accountsById.values()) {
        if (account.email === input.email) return { ok: false, reason: 'email-taken' };
      }
      const account: AccountRecord = {
        id: nextAccountId++,
        email: input.email,
        displayName: input.displayName,
        verifier: input.verifier,
        kdfDescriptor: input.kdfDescriptor,
        emailVerifiedAt: null,
        createdAt: new Date(),
      };
      accountsById.set(account.id, account);
      return { ok: true, account: { ...account } };
    },

    async deleteAccount(accountId: number): Promise<void> {
      // Mirrors the ON DELETE CASCADE the real schema declares.
      accountsById.delete(accountId);
      keyRecords.delete(accountId);
      for (let index = tokens.length - 1; index >= 0; index -= 1) {
        if (tokens[index]?.accountId === accountId) tokens.splice(index, 1);
      }
    },

    async markEmailVerified(input: { accountId: number; verifiedAt: Date }): Promise<void> {
      const account = accountsById.get(input.accountId);
      if (account) account.emailVerifiedAt = input.verifiedAt;
    },

    async insertTokens(newTokens: NewTokenInput[]): Promise<void> {
      for (const token of newTokens) {
        tokens.push({
          id: nextTokenId++,
          accountId: token.accountId,
          kind: token.kind,
          familyId: token.familyId,
          expiresAt: token.expiresAt,
          revokedAt: null,
          tokenHash: token.tokenHash,
        });
      }
    },

    async findToken(input: { kind: AccountTokenKind; tokenHash: string }): Promise<StoredToken | null> {
      const found = tokens.find((token) => token.kind === input.kind && token.tokenHash === input.tokenHash);
      return found ? { ...found } : null;
    },

    async revokeToken(input: { tokenId: number; revokedAt: Date }): Promise<void> {
      revokeMatching((token) => token.id === input.tokenId, input.revokedAt);
    },

    async revokeFamily(input: { accountId: number; familyId: string; revokedAt: Date }): Promise<void> {
      revokeMatching(
        (token) => token.accountId === input.accountId && token.familyId === input.familyId,
        input.revokedAt,
      );
    },

    async revokeSessions(input: { accountId: number; revokedAt: Date }): Promise<void> {
      revokeMatching(
        (token) => token.accountId === input.accountId && SESSION_TOKEN_KINDS.includes(token.kind),
        input.revokedAt,
      );
    },

    async revokeTokensOfKind(input: { accountId: number; kind: AccountTokenKind; revokedAt: Date }): Promise<void> {
      revokeMatching((token) => token.accountId === input.accountId && token.kind === input.kind, input.revokedAt);
    },

    async rotateCredential(input: RotateCredentialInput): Promise<void> {
      const account = accountsById.get(input.accountId);
      if (account) {
        account.verifier = input.verifier;
        account.kdfDescriptor = input.kdfDescriptor;
      }
      upsertKeyRecords(input.accountId, input.keyRecords);
      revokeMatching(
        (token) => token.accountId === input.accountId && SESSION_TOKEN_KINDS.includes(token.kind),
        input.revokedAt,
      );
      if (input.consumeTokenId !== null) {
        revokeMatching((token) => token.id === input.consumeTokenId, input.revokedAt);
      }
      for (const token of input.issue) {
        tokens.push({
          id: nextTokenId++,
          accountId: token.accountId,
          kind: token.kind,
          familyId: token.familyId,
          expiresAt: token.expiresAt,
          revokedAt: null,
          tokenHash: token.tokenHash,
        });
      }
    },

    async purgeExpiredTokens(input: { before: Date }): Promise<number> {
      let deleted = 0;
      for (let index = tokens.length - 1; index >= 0; index -= 1) {
        const token = tokens[index];
        if (token && token.expiresAt.getTime() < input.before.getTime()) {
          tokens.splice(index, 1);
          deleted += 1;
        }
      }
      return deleted;
    },

    keyRecordsFor(accountId: number) {
      return keyRecords.get(accountId) ?? new Map<SyncKeyRecordKind, KeyRecordSubmission>();
    },

    allTokens() {
      // Defensive copy: a test must not be able to mutate the store's rows.
      return structuredClone(tokens);
    },

    hasAccount(accountId: number) {
      return accountsById.has(accountId);
    },
  };
}
