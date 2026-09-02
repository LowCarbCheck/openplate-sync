/**
 * In-memory `AccountStore` for the auth handler tests — the account-system
 * counterpart to `fake-storage-adapter.ts`.
 *
 * It implements the same semantics the Drizzle store must: unique handles,
 * digest-keyed token lookup, revocation that is stamped once and never
 * cleared, and a `rotateCredential` that applies its whole effect. The last
 * one is the reason this fake is worth having — the handler tests can assert
 * that a rotation revoked every session AND upserted the key records AND
 * consumed the link token, without a database.
 *
 * `recoverAndRotatePassphrase` is here for the same reason, and with the same
 * limit: it reproduces the compare-and-swap RULE, not the atomicity. Proving
 * that a failure part-way through leaves nothing behind needs a real
 * transaction, and that test lives in `tests/integration/`.
 *
 * It deliberately does NOT simulate a transaction rollback. Atomicity is a
 * property of Postgres, and the integration suite is where it is exercised.
 * `redeemInviteAndCreateAccount` therefore reproduces the RULES the real
 * transaction enforces (one redemption per invite; a taken handle leaves the
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
  RecoverAndRotatePassphraseInput,
  RecoverAndRotatePassphraseResult,
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
    async findAccountByHandle(handle: string): Promise<AccountRecord | null> {
      for (const account of accountsById.values()) {
        if (account.handle === handle) return { ...account };
      }
      return null;
    },

    async findAccountById(accountId: number): Promise<AccountRecord | null> {
      const account = accountsById.get(accountId);
      return account ? { ...account } : null;
    },

    async createAccount(input: CreateAccountInput): Promise<CreateAccountResult> {
      for (const account of accountsById.values()) {
        if (account.handle === input.handle) return { ok: false, reason: 'handle-taken' };
      }
      const account: AccountRecord = {
        id: nextAccountId++,
        handle: input.handle,
        displayName: input.displayName,
        verifier: input.verifier,
        recoveryVerifier: input.recoveryVerifier,
        kdfDescriptor: input.kdfDescriptor,
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
      // enforce — a duplicate handle must leave the invite redeemable — by
      // simply not claiming it until the account exists.
      if (!created.ok) return { ok: false, reason: 'handle-taken' };

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

    async recoverAndRotatePassphrase(
      input: RecoverAndRotatePassphraseInput,
    ): Promise<RecoverAndRotatePassphraseResult> {
      const account = accountsById.get(input.accountId);
      // The compare-and-swap the real store performs inside its transaction,
      // reproduced as a RULE rather than as a rollback (see the header): a
      // rotation whose expected recovery verifier no longer matches applies
      // nothing at all.
      if (!account || account.recoveryVerifier !== input.expectedRecoveryVerifier) {
        return { ok: false, reason: 'recovery-superseded' };
      }

      account.verifier = input.verifier;
      account.kdfDescriptor = input.kdfDescriptor;
      if (input.newRecoveryVerifier !== null) account.recoveryVerifier = input.newRecoveryVerifier;
      upsertKeyRecords(input.accountId, input.keyRecords);
      revokeMatching(
        (token) => token.accountId === input.accountId && SESSION_TOKEN_KINDS.includes(token.kind),
        input.revokedAt,
      );
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
      return { ok: true };
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
