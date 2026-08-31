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
 * `redeemInviteAndCreateAccount` therefore reproduces the RULES the real
 * transaction enforces (one redemption per invite; a taken email leaves the
 * invite spendable) by ordering its writes, not by rolling anything back. The
 * concurrency guarantee behind those rules is only testable against Postgres.
 */
import type {
  AccountRecord,
  AccountStore,
  CreateAccountInput,
  CreateAccountResult,
  KeyRecordSubmission,
  NewTokenInput,
  RedeemInviteAndCreateAccountInput,
  RedeemInviteResult,
  RotateCredentialInput,
  StoredToken,
} from '../../src/accounts/account-store.js';
import type { AccountTokenKind } from '../../src/lib/tokens.js';
import { SESSION_TOKEN_KINDS } from '../../src/lib/tokens.js';
import type { SyncKeyRecordKind } from '../../src/protocol.js';

interface StoredTokenRow extends StoredToken {
  tokenHash: string;
}

interface FakeInviteRow {
  tokenHash: string;
  expiresAt: Date;
  redeemedAt: Date | null;
}

export interface FakeAccountStore extends AccountStore {
  /** Test-only: the key records a rotation wrote, by account then kind. */
  keyRecordsFor(accountId: number): Map<SyncKeyRecordKind, KeyRecordSubmission>;
  /** Test-only: every token row, so a test can assert on revocation state. */
  allTokens(): StoredTokenRow[];
  /** Test-only: whether the account row still exists. */
  hasAccount(accountId: number): boolean;
  /** Test-only: seeds an invite so a handler test can redeem one without an admin API. */
  seedInvite(input: { tokenHash: string; expiresAt: Date }): void;
  /** Test-only: whether the invite is still spendable — the assertion a "409 must not burn it" test makes. */
  inviteIsRedeemable(tokenHash: string): boolean;
}

export function createFakeAccountStore(): FakeAccountStore {
  const accountsById = new Map<number, AccountRecord>();
  const tokens: StoredTokenRow[] = [];
  const keyRecords = new Map<number, Map<SyncKeyRecordKind, KeyRecordSubmission>>();
  const invites: FakeInviteRow[] = [];
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

    async redeemInviteAndCreateAccount(input: RedeemInviteAndCreateAccountInput): Promise<RedeemInviteResult> {
      const invite = invites.find((row) => row.tokenHash === input.inviteTokenHash);
      // Unknown, expired and already-spent collapse into one answer here for
      // the same reason they do in the real store: the caller must not be able
      // to tell them apart.
      if (!invite || invite.redeemedAt !== null || invite.expiresAt.getTime() <= input.now.getTime()) {
        return { ok: false, reason: 'invite-invalid' };
      }

      const created = await this.createAccount(input.account);
      // The invite is marked spent ONLY on success. This fake cannot roll a
      // transaction back, but it can honour the rule the transaction exists to
      // enforce — a duplicate email must leave the invite redeemable — by
      // simply not claiming it until the account exists.
      if (!created.ok) return { ok: false, reason: 'email-taken' };

      invite.redeemedAt = input.now;
      return { ok: true, account: created.account };
    },

    seedInvite(input: { tokenHash: string; expiresAt: Date }): void {
      invites.push({ tokenHash: input.tokenHash, expiresAt: input.expiresAt, redeemedAt: null });
    },

    inviteIsRedeemable(tokenHash: string): boolean {
      const invite = invites.find((row) => row.tokenHash === tokenHash);
      return invite !== undefined && invite.redeemedAt === null;
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
