/**
 * A controllable `AuthContext` for the auth handler tests.
 *
 * The clock and both token minters are deterministic, which is what makes
 * expiry, rotation and a mailed reset assertable without sleeping, without a
 * network, and without a database. `mintToken` hands out `token-1`, `token-2`,
 * … so a test can name the exact token it expects a handler to have issued;
 * `mintResetToken` hands out `sr_reset-1`, … so a test can post back the token
 * the mailer was given.
 *
 * The MAILER IS A RECORDER, not a stub that swallows. M192 gave this service
 * two letters again, and the assertion "a reset for an unknown address sends
 * nothing" is only meaningful against something that would have recorded a
 * send.
 */
import { createSilentLogger } from '../../src/logger.js';
import { hashToken, type GeneratedToken } from '../../src/lib/tokens.js';
import type { AuthContext } from '../../src/accounts/auth-handlers.js';
import type { Mailer, SendInviteInput, SendResetInput } from '../../src/mail/mailer.js';
import { createFakeAccountStore, type FakeAccountStore } from './fake-account-store.js';

/** Every letter the handlers asked for, in order. */
export interface RecordingMailer extends Mailer {
  invites: SendInviteInput[];
  resets: SendResetInput[];
}

export function createRecordingMailer(): RecordingMailer {
  const invites: SendInviteInput[] = [];
  const resets: SendResetInput[] = [];
  return {
    invites,
    resets,
    async sendInvite(input: SendInviteInput): Promise<void> {
      invites.push(input);
    },
    async sendReset(input: SendResetInput): Promise<void> {
      resets.push(input);
    },
  };
}

export interface AuthFixture {
  ctx: AuthContext;
  store: FakeAccountStore;
  mailer: RecordingMailer;
  /** Moves the fixture clock forward. */
  advance(ms: number): void;
  /** Current fixture time. */
  now(): Date;
}

export interface AuthFixtureOptions {
  startAt?: Date;
}

/**
 * A fixed 32-byte escrow key. Not derived from a `SERVER_SECRET` here, because
 * the derivation is `lib/server-secrets.ts`'s own test — what these tests need
 * is a key they can also hand to `openRecoveryCode` when asserting what was
 * sealed.
 */
export const TEST_ESCROW_KEY = Buffer.alloc(32, 0x5a);

export function createAuthFixture(options: AuthFixtureOptions = {}): AuthFixture {
  const store = createFakeAccountStore();
  const mailer = createRecordingMailer();
  let clock = options.startAt ?? new Date('2026-08-04T10:00:00.000Z');
  let tokenCounter = 0;
  let resetCounter = 0;
  let familyCounter = 0;

  function mintToken(): GeneratedToken {
    tokenCounter += 1;
    const raw = `token-${tokenCounter}`;
    return { raw, hash: hashToken(raw) };
  }

  function mintResetToken(): GeneratedToken {
    resetCounter += 1;
    // The `sr_` prefix is part of the shape the real minter produces, and a
    // fixture that dropped it would let a prefix bug pass every unit test.
    const raw = `sr_reset-${resetCounter}`;
    return { raw, hash: hashToken(raw) };
  }

  const ctx: AuthContext = {
    store,
    pepper: 'unit-test-pepper',
    enumerationSecret: 'unit-test-enumeration-secret',
    escrowKey: TEST_ESCROW_KEY,
    mailer,
    now: () => new Date(clock.getTime()),
    mintToken,
    mintResetToken,
    mintFamilyId: () => {
      familyCounter += 1;
      return `family-${familyCounter}`;
    },
    logger: createSilentLogger(),
  };

  return {
    ctx,
    store,
    mailer,
    advance(ms: number) {
      clock = new Date(clock.getTime() + ms);
    },
    now: () => new Date(clock.getTime()),
  };
}

/** A structurally valid Argon2id descriptor for request bodies. */
export function sampleKdfDescriptor(saltByte = 1) {
  return {
    salt: Buffer.alloc(16, saltByte).toString('base64'),
    params: { memorySizeKib: 65536, iterations: 3, parallelism: 1 },
  };
}

/** A structurally valid base64 auth-hash (32 bytes), distinct per `seed`. */
export function sampleAuthHash(seed = 7): string {
  return Buffer.alloc(32, seed).toString('base64');
}

/** A non-empty opaque wrapped-DEK payload. */
export function sampleWrappedDek(seed = 9): string {
  return Buffer.alloc(60, seed).toString('base64');
}

/**
 * A structurally valid recovery code: 32 Crockford base32 characters, which is
 * the 160 bits PROTOCOL.md §3.1 specifies. Distinct per `seed`, and rendered in
 * the grouped form a person actually reads so the canonicaliser is exercised
 * by every test that uses one.
 */
export function sampleRecoveryCode(seed = 0): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const characters = Array.from({ length: 32 }, (_unused, index) => alphabet[(index * 7 + seed) % alphabet.length]);
  return (characters.join('').match(/.{1,5}/g) ?? []).join('-');
}
