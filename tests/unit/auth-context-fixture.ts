/**
 * A controllable `AuthContext` for the auth handler tests.
 *
 * The clock and the token minter are both deterministic, which is what makes
 * expiry and rotation assertable without sleeping, without a network, and
 * without a database. `mintToken` hands out `token-1`, `token-2`, … so a test
 * can name the exact token it expects a handler to have issued.
 *
 * There is no mailer to substitute any more: M181 deleted `src/mail/`, so the
 * only thing this fixture still fakes is time and randomness.
 */
import { createSilentLogger } from '../../src/logger.js';
import { hashToken, type GeneratedToken } from '../../src/lib/tokens.js';
import type { AuthContext } from '../../src/accounts/auth-handlers.js';
import type { SignupMode } from '../../src/protocol.js';
import { createFakeAccountStore, type FakeAccountStore } from './fake-account-store.js';

export interface AuthFixture {
  ctx: AuthContext;
  store: FakeAccountStore;
  /** Moves the fixture clock forward. */
  advance(ms: number): void;
  /** Current fixture time. */
  now(): Date;
}

export interface AuthFixtureOptions {
  signupMode?: SignupMode;
  startAt?: Date;
}

export function createAuthFixture(options: AuthFixtureOptions = {}): AuthFixture {
  const store = createFakeAccountStore();
  let clock = options.startAt ?? new Date('2026-08-04T10:00:00.000Z');
  let tokenCounter = 0;
  let familyCounter = 0;

  function mintToken(): GeneratedToken {
    tokenCounter += 1;
    const raw = `token-${tokenCounter}`;
    return { raw, hash: hashToken(raw) };
  }

  const ctx: AuthContext = {
    store,
    pepper: 'unit-test-pepper',
    enumerationSecret: 'unit-test-enumeration-secret',
    signupMode: options.signupMode ?? 'open',
    now: () => new Date(clock.getTime()),
    mintToken,
    mintFamilyId: () => {
      familyCounter += 1;
      return `family-${familyCounter}`;
    },
    logger: createSilentLogger(),
  };

  return {
    ctx,
    store,
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
