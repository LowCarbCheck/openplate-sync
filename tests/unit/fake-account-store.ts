/**
 * In-memory `AccountStore` for the auth handler tests — the account-system
 * counterpart to `fake-storage-adapter.ts`.
 *
 * It implements the same semantics the Drizzle store must: unique addresses,
 * digest-keyed token lookup, revocation that is stamped once and never
 * cleared, and rotations that apply their whole effect. That last one is the
 * reason this fake is worth having — the handler tests can assert that a
 * rotation revoked every session AND upserted the key records AND re-sealed
 * the escrow, without a database.
 *
 * It deliberately does NOT simulate a transaction rollback. Atomicity is a
 * property of Postgres, and the integration suite is where it is exercised.
 * `redeemInviteAndCreateAccount` therefore reproduces the RULES the real
 * transaction enforces (one redemption per invite; a taken address leaves the
 * invite spendable) by ordering its writes, not by rolling anything back. The
 * concurrency guarantee behind those rules is only testable against Postgres.
 * `recoverAndRotatePassphrase` has the same limit: it reproduces the
 * compare-and-swap RULE, not the atomicity.
 */
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
} from '../../src/accounts/account-store.js';
import type { AccountTokenKind } from '../../src/lib/tokens.js';
import { SESSION_TOKEN_KINDS } from '../../src/lib/tokens.js';
import type { AccountRole, SyncKeyRecordKind } from '../../src/protocol.js';

interface StoredTokenRow extends StoredToken {
  tokenHash: string;
}

interface FakeInviteRow {
  tokenHash: string;
  email: string;
  displayName: string | null;
  role: AccountRole;
  dailyAiLimit: number;
  expiresAt: Date;
  redeemedAt: Date | null;
  revokedAt: Date | null;
}

interface FakeResetRow {
  accountId: number;
  tokenHash: string;
  expiresAt: Date;
  consumedAt: Date | null;
}

/** What a test seeds when it wants an invite to redeem. Everything but the digest has a default. */
export interface SeedInviteInput {
  tokenHash: string;
  expiresAt: Date;
  email?: string;
  displayName?: string | null;
  role?: AccountRole;
  dailyAiLimit?: number;
  revokedAt?: Date | null;
}

export interface FakeAccountStore extends AccountStore {
  /** Test-only: the key records a signup or rotation wrote, by account then kind. */
  keyRecordsFor(accountId: number): Map<SyncKeyRecordKind, KeyRecordSubmission>;
  /** Test-only: the sealed recovery code on an account, so a test can assert it never equals the plaintext. */
  escrowFor(accountId: number): Buffer | null;
  /** Test-only: every token row, so a test can assert on revocation state. */
  allTokens(): StoredTokenRow[];
  /** Test-only: whether the account row still exists. */
  hasAccount(accountId: number): boolean;
  /** Test-only: seeds an invite so a handler test can redeem one without an admin API. */
  seedInvite(input: SeedInviteInput): void;
  /** Test-only: whether the invite is still spendable — the assertion a "409 must not burn it" test makes. */
  inviteIsRedeemable(tokenHash: string): boolean;
  /** Test-only: sets today's AI spend, so an `AccountView` assertion has something to read. */
  seedAiUsage(input: { accountId: number; day: string; count: number }): void;
  /** Test-only: when the proxy last stamped the account, so a test can prove it did. */
  lastSeenFor(accountId: number): Date | null;
  /** Test-only: every password-reset row, so a test can assert one token superseded another. */
  allPasswordResets(): FakeResetRow[];
  /**
   * Test-only: creates an account THROUGH AN INVITE, which is the only way the
   * service itself can. A helper that inserted a row directly would let a test
   * set up a state the production code cannot reach.
   */
  seedAccount(input: SeedAccountInput): Promise<AccountRecord>;
}

/** What a test names when it needs an account to exist. Everything but the address has a default. */
export interface SeedAccountInput {
  email: string;
  displayName?: string | null;
  role?: AccountRole;
  dailyAiLimit?: number;
  verifier?: string;
  recoveryVerifier?: string;
  recoveryCodeEscrow?: Buffer;
  now?: Date;
}

export function createFakeAccountStore(): FakeAccountStore {
  const accountsById = new Map<number, AccountRecord>();
  const escrowByAccount = new Map<number, Buffer>();
  const tokens: StoredTokenRow[] = [];
  const keyRecords = new Map<number, Map<SyncKeyRecordKind, KeyRecordSubmission>>();
  const invites: FakeInviteRow[] = [];
  const resets: FakeResetRow[] = [];
  const aiUsage = new Map<string, number>();
  const lastSeenByAccount = new Map<number, Date>();
  let nextAccountId = 1;
  let nextTokenId = 1;
  let seedCounter = 0;

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

  function insertTokenRows(newTokens: NewTokenInput[]): void {
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

    async updateDisplayName(input: { accountId: number; displayName: string | null }): Promise<AccountRecord | null> {
      const account = accountsById.get(input.accountId);
      if (!account) return null;
      account.displayName = input.displayName;
      return { ...account };
    },

    async updateStanding(input: UpdateStandingInput): Promise<AccountRecord | null> {
      const account = accountsById.get(input.accountId);
      if (!account) return null;
      // `undefined` means untouched; `displayName: null` is a real value that
      // clears the name, so both are keyed on the property's presence.
      if (input.role !== undefined) account.role = input.role;
      if (input.dailyAiLimit !== undefined) account.dailyAiLimit = input.dailyAiLimit;
      if (input.displayName !== undefined) account.displayName = input.displayName;
      return { ...account };
    },

    async suspendAccount(input: { accountId: number; suspendedAt: Date }): Promise<AccountRecord | null> {
      const account = accountsById.get(input.accountId);
      if (!account) return null;
      // Stamped once, as the real store's `isNull` guard does: a second
      // suspension keeps the instant of the first.
      account.suspendedAt ??= input.suspendedAt;
      revokeMatching(
        (token) => token.accountId === input.accountId && SESSION_TOKEN_KINDS.includes(token.kind),
        input.suspendedAt,
      );
      return { ...account };
    },

    async reactivateAccount(accountId: number): Promise<AccountRecord | null> {
      const account = accountsById.get(accountId);
      if (!account) return null;
      account.suspendedAt = null;
      return { ...account };
    },

    async touchLastSeen(input: { accountId: number; seenAt: Date }): Promise<void> {
      lastSeenByAccount.set(input.accountId, input.seenAt);
    },

    lastSeenFor(accountId: number): Date | null {
      return lastSeenByAccount.get(accountId) ?? null;
    },

    async aiUsageOn(input: { accountId: number; day: string }): Promise<number> {
      return aiUsage.get(`${input.accountId}:${input.day}`) ?? 0;
    },

    seedAiUsage(input: { accountId: number; day: string; count: number }): void {
      aiUsage.set(`${input.accountId}:${input.day}`, input.count);
    },

    async redeemInviteAndCreateAccount(input: RedeemInviteAndCreateAccountInput): Promise<RedeemInviteResult> {
      const invite = invites.find((row) => row.tokenHash === input.inviteTokenHash);
      // Unknown, expired, revoked and already-spent collapse into one answer
      // here for the same reason they do in the real store: the caller must not
      // be able to tell them apart.
      if (
        !invite ||
        invite.redeemedAt !== null ||
        invite.revokedAt !== null ||
        invite.expiresAt.getTime() <= input.now.getTime()
      ) {
        return { ok: false, reason: 'invite-invalid' };
      }

      for (const existing of accountsById.values()) {
        // The invite is NOT claimed on this branch. This fake cannot roll a
        // transaction back, but it can honour the rule the transaction exists
        // to enforce — a duplicate address must leave the invite redeemable —
        // by simply not claiming it until the account exists.
        if (existing.email === invite.email) return { ok: false, reason: 'email-taken' };
      }

      const account: AccountRecord = {
        id: nextAccountId++,
        // THE ADDRESS COMES FROM THE INVITE, exactly as it does in Postgres.
        email: invite.email,
        displayName: input.account.displayName,
        role: invite.role,
        dailyAiLimit: invite.dailyAiLimit,
        suspendedAt: null,
        verifier: input.account.verifier,
        recoveryVerifier: input.account.recoveryVerifier,
        kdfDescriptor: input.account.kdfDescriptor,
        createdAt: input.now,
      };
      accountsById.set(account.id, account);
      escrowByAccount.set(account.id, input.account.recoveryCodeEscrow);
      upsertKeyRecords(account.id, input.account.keyRecords);
      invite.redeemedAt = input.now;
      return { ok: true, account: { ...account } };
    },

    async findInviteAddressing(input: { inviteTokenHash: string; now: Date }): Promise<InviteAddressing | null> {
      const invite = invites.find((row) => row.tokenHash === input.inviteTokenHash);
      if (
        !invite ||
        invite.redeemedAt !== null ||
        invite.revokedAt !== null ||
        invite.expiresAt.getTime() <= input.now.getTime()
      ) {
        return null;
      }
      return { email: invite.email, displayName: invite.displayName, expiresAt: invite.expiresAt };
    },

    seedInvite(input: SeedInviteInput): void {
      invites.push({
        tokenHash: input.tokenHash,
        email: input.email ?? 'anna@example.org',
        displayName: input.displayName ?? null,
        role: input.role ?? 'member',
        dailyAiLimit: input.dailyAiLimit ?? 0,
        expiresAt: input.expiresAt,
        redeemedAt: null,
        revokedAt: input.revokedAt ?? null,
      });
    },

    inviteIsRedeemable(tokenHash: string): boolean {
      const invite = invites.find((row) => row.tokenHash === tokenHash);
      return invite !== undefined && invite.redeemedAt === null && invite.revokedAt === null;
    },

    async createPasswordReset(input: CreatePasswordResetInput): Promise<void> {
      // Supersede first, then insert — the order does not matter here because
      // nothing races, and it keeps the new row out of its own sweep.
      for (const row of resets) {
        if (row.accountId === input.accountId && row.consumedAt === null) row.consumedAt = input.now;
      }
      resets.push({
        accountId: input.accountId,
        tokenHash: input.tokenHash,
        expiresAt: input.expiresAt,
        consumedAt: null,
      });
    },

    async consumePasswordReset(input: { tokenHash: string; now: Date }): Promise<ConsumedPasswordReset | null> {
      const row = resets.find((candidate) => candidate.tokenHash === input.tokenHash);
      if (!row || row.consumedAt !== null || row.expiresAt.getTime() <= input.now.getTime()) return null;
      row.consumedAt = input.now;

      const account = accountsById.get(row.accountId);
      const escrow = escrowByAccount.get(row.accountId);
      if (!account || !escrow) return null;
      return { email: account.email, recoveryCodeEscrow: escrow };
    },

    allPasswordResets(): FakeResetRow[] {
      return resets.map((row) => ({ ...row }));
    },

    async seedAccount(input: SeedAccountInput): Promise<AccountRecord> {
      const now = input.now ?? new Date('2026-08-04T10:00:00.000Z');
      // A UNIQUE token per call, not one derived from the address. Deriving it
      // meant a second `seedAccount` for the same address hit the first call's
      // already-redeemed invite and failed with `invite-invalid`, which is a
      // fixture artefact — the rule a test wants to see there is `email-taken`.
      seedCounter += 1;
      const tokenHash = `seeded-invite-${seedCounter}`;
      this.seedInvite({
        tokenHash,
        expiresAt: new Date(now.getTime() + 60_000),
        email: input.email,
        displayName: input.displayName ?? null,
        role: input.role ?? 'member',
        dailyAiLimit: input.dailyAiLimit ?? 0,
      });
      const created = await this.redeemInviteAndCreateAccount({
        inviteTokenHash: tokenHash,
        now,
        account: {
          displayName: input.displayName ?? null,
          verifier: input.verifier ?? `seeded-verifier-${input.email}`,
          recoveryVerifier: input.recoveryVerifier ?? `seeded-recovery-verifier-${input.email}`,
          recoveryCodeEscrow: input.recoveryCodeEscrow ?? Buffer.alloc(60, 0x11),
          kdfDescriptor: { salt: 'AAAA', params: { memorySizeKib: 65536, iterations: 3, parallelism: 1 } },
          keyRecords: [],
        },
      });
      if (!created.ok) throw new Error(`could not seed ${input.email}: ${created.reason}`);
      return created.account;
    },

    async deleteAccount(accountId: number): Promise<void> {
      // Mirrors the ON DELETE CASCADE the real schema declares.
      accountsById.delete(accountId);
      escrowByAccount.delete(accountId);
      keyRecords.delete(accountId);
      for (let index = resets.length - 1; index >= 0; index -= 1) {
        if (resets[index]?.accountId === accountId) resets.splice(index, 1);
      }
      for (let index = tokens.length - 1; index >= 0; index -= 1) {
        if (tokens[index]?.accountId === accountId) tokens.splice(index, 1);
      }
    },

    async insertTokens(newTokens: NewTokenInput[]): Promise<void> {
      insertTokenRows(newTokens);
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
      insertTokenRows(input.issue);
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
      // The escrow moves with the verifier, or not at all — the same
      // `undefined`-omits-the-column rule the real UPDATE relies on.
      if (input.newRecoveryCodeEscrow !== null) escrowByAccount.set(input.accountId, input.newRecoveryCodeEscrow);
      upsertKeyRecords(input.accountId, input.keyRecords);
      revokeMatching(
        (token) => token.accountId === input.accountId && SESSION_TOKEN_KINDS.includes(token.kind),
        input.revokedAt,
      );
      insertTokenRows(input.issue);
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

    escrowFor(accountId: number) {
      return escrowByAccount.get(accountId) ?? null;
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
