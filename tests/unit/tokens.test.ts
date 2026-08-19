/**
 * Token lifecycle rules: digests are what get stored, revocation outranks
 * expiry when classifying (because the two mean different things to the
 * refresh handler), and the bearer header is parsed strictly.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  ACCESS_TOKEN_TTL_MS,
  REFRESH_TOKEN_TTL_MS,
  TOKEN_TTL_MS,
  classifyToken,
  computeExpiry,
  generateFamilyId,
  generateToken,
  hashToken,
  isTokenUsable,
  parseBearerHeader,
} from '../../src/lib/tokens.js';

const NOW = new Date('2026-08-04T12:00:00.000Z');

test('generateToken returns a raw token and its matching digest', () => {
  const token = generateToken();
  assert.equal(token.hash, hashToken(token.raw));
  // Distinct every time — the pre-image is 256 bits of randomness, which is
  // why an unstretched SHA-256 is the right hash here.
  assert.notEqual(generateToken().raw, token.raw);
  assert.notEqual(generateFamilyId(), generateFamilyId());
});

test('an access token expires long before a refresh token', () => {
  assert.ok(ACCESS_TOKEN_TTL_MS < REFRESH_TOKEN_TTL_MS);
  assert.equal(TOKEN_TTL_MS.access, ACCESS_TOKEN_TTL_MS);
  assert.equal(TOKEN_TTL_MS.refresh, REFRESH_TOKEN_TTL_MS);
});

test('classifyToken reports revoked ahead of expired', () => {
  const expiredAndRevoked = { expiresAt: new Date(NOW.getTime() - 1), revokedAt: new Date(NOW.getTime() - 2) };
  // Revocation of an in-TTL token is the reuse signal; conflating it with a
  // routine expiry would lose that.
  assert.equal(classifyToken(expiredAndRevoked, NOW), 'revoked');
});

test('classifyToken treats the exact expiry instant as expired', () => {
  assert.equal(classifyToken({ expiresAt: NOW, revokedAt: null }, NOW), 'expired');
  assert.equal(classifyToken({ expiresAt: new Date(NOW.getTime() + 1), revokedAt: null }, NOW), 'valid');
});

test('isTokenUsable is true only for a live, unrevoked token', () => {
  assert.equal(isTokenUsable({ expiresAt: computeExpiry(NOW, 1000), revokedAt: null }, NOW), true);
  assert.equal(isTokenUsable({ expiresAt: computeExpiry(NOW, 1000), revokedAt: NOW }, NOW), false);
});

test('parseBearerHeader accepts only a well-formed bearer header', () => {
  assert.equal(parseBearerHeader('Bearer abc123'), 'abc123');
  assert.equal(parseBearerHeader('bearer abc123'), 'abc123');
  assert.equal(parseBearerHeader('  Bearer   abc123  '), 'abc123');
  assert.equal(parseBearerHeader('Basic abc123'), null);
  assert.equal(parseBearerHeader('Bearer'), null);
  assert.equal(parseBearerHeader('Bearer '), null);
  assert.equal(parseBearerHeader(undefined), null);
});
