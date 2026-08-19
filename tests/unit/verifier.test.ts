/**
 * The verifier's security properties, asserted directly: peppering actually
 * binds (a stolen table is useless without `SERVER_SECRET`), comparison is
 * length-safe, email normalization is total, and a malformed auth-hash is
 * refused rather than silently truncated.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTH_HASH_BYTES,
  computeVerifier,
  isPlausibleEmail,
  normalizeEmail,
  parseAuthHash,
  verifierMatches,
} from '../../src/lib/verifier.js';
import { deriveServerSecrets } from '../../src/lib/server-secrets.js';

const AUTH_HASH = Buffer.alloc(AUTH_HASH_BYTES, 5).toString('base64');

test('the same auth hash and pepper always produce the same verifier', () => {
  assert.equal(
    computeVerifier({ authHash: AUTH_HASH, pepper: 'pepper' }),
    computeVerifier({ authHash: AUTH_HASH, pepper: 'pepper' }),
  );
});

test('a different pepper produces a different verifier for the same auth hash', () => {
  // This IS the pepper's purpose: a dumped `accounts` table cannot be checked
  // offline against guessed auth-hashes without the environment secret.
  assert.notEqual(
    computeVerifier({ authHash: AUTH_HASH, pepper: 'pepper-a' }),
    computeVerifier({ authHash: AUTH_HASH, pepper: 'pepper-b' }),
  );
});

test('verifierMatches is true for equal values and false for a length mismatch', () => {
  const verifier = computeVerifier({ authHash: AUTH_HASH, pepper: 'pepper' });
  assert.equal(verifierMatches({ candidate: verifier, stored: verifier }), true);
  // Must return false rather than throw — `timingSafeEqual` throws on unequal
  // lengths, and a malformed stored value must not become a 500.
  assert.equal(verifierMatches({ candidate: verifier, stored: 'short' }), false);
});

test('parseAuthHash accepts exactly 32 decoded bytes', () => {
  assert.notEqual(parseAuthHash(AUTH_HASH), null);
  assert.equal(parseAuthHash(Buffer.alloc(31, 1).toString('base64')), null);
  assert.equal(parseAuthHash(Buffer.alloc(33, 1).toString('base64')), null);
  assert.equal(parseAuthHash(''), null);
  assert.equal(parseAuthHash(42), null);
});

test('normalizeEmail trims and lowercases', () => {
  assert.equal(normalizeEmail('  Person@Example.TEST '), 'person@example.test');
});

test('isPlausibleEmail rejects structurally impossible addresses', () => {
  assert.equal(isPlausibleEmail('person@example.test'), true);
  assert.equal(isPlausibleEmail('person@localhost'), false);
  assert.equal(isPlausibleEmail('no-at-sign'), false);
  assert.equal(isPlausibleEmail('two@@example.test'), false);
  assert.equal(isPlausibleEmail('with space@example.test'), false);
});

test('the two derived server subkeys differ and are stable', () => {
  const first = deriveServerSecrets('a-root-secret-of-sufficient-length!!');
  const second = deriveServerSecrets('a-root-secret-of-sufficient-length!!');
  assert.deepEqual(first, second);
  // Domain separation: reusing one key for the other purpose is the mistake
  // this derivation exists to make impossible.
  assert.notEqual(first.verifierPepper, first.enumerationSecret);
});
