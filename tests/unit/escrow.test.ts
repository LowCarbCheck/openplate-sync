/**
 * The recovery-code escrow: the one thing this service can decrypt, and the
 * properties that bound what that means.
 *
 * TWO ASSERTIONS CARRY THE FILE. The stored bytes never contain the code, in
 * any encoding somebody would plausibly grep a database dump with — so a
 * dumped `accounts` table is not a list of recovery codes. And a CHANGED
 * `SERVER_SECRET` cannot open an existing escrow — so the key really does live
 * in the environment rather than in the row, which is the whole reason
 * ADR-0005 could supersede ADR-0004's prohibition 5 without also handing the
 * database itself a decryption capability.
 *
 * The rest pins the framing (`iv ‖ ciphertext ‖ tag`) and the refusal to
 * guess: a failed tag THROWS rather than returning an empty string a mail
 * would then deliver.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ESCROW_IV_BYTES, ESCROW_TAG_BYTES, openRecoveryCode, sealRecoveryCode } from '../../src/lib/escrow.js';
import { deriveServerSecrets, ESCROW_KEY_LABEL } from '../../src/lib/server-secrets.js';

/** A real 32-character Crockford base32 code, as `parseRecoveryCode` canonicalises one. */
const CODE = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789';

const SECRET = 'a-root-secret-of-sufficient-length!!';
const OTHER_SECRET = 'a-DIFFERENT-root-secret-long-enough!';

function keyFor(secret: string): Buffer {
  return deriveServerSecrets(secret).escrowKey;
}

test('a sealed code round-trips under the same key', () => {
  const key = keyFor(SECRET);
  assert.equal(openRecoveryCode({ sealed: sealRecoveryCode({ code: CODE, escrowKey: key }), escrowKey: key }), CODE);
});

test('the stored bytes never contain the code, in any encoding a dump would be grepped with', () => {
  // THE ASSERTION THAT MAKES A DATABASE DUMP NOT A LIST OF RECOVERY CODES.
  const sealed = sealRecoveryCode({ code: CODE, escrowKey: keyFor(SECRET) });
  for (const encoding of ['utf8', 'hex', 'base64', 'latin1'] as const) {
    assert.ok(!sealed.toString(encoding).includes(CODE), `the sealed value leaked the code as ${encoding}`);
  }
  // And the ciphertext is not merely the code with a wrapper around it: it is
  // as long as the code, no longer, plus exactly the IV and the tag.
  assert.equal(sealed.byteLength, ESCROW_IV_BYTES + CODE.length + ESCROW_TAG_BYTES);
});

test('a changed SERVER_SECRET cannot open an existing escrow', () => {
  // THE ASSERTION THAT PUTS THE KEY IN THE ENVIRONMENT RATHER THAN IN THE ROW.
  // It is also the operational warning ADR-0005 records: rotating
  // `SERVER_SECRET` makes every mailed reset on the instance stop working, for
  // accounts that signed up before the change.
  const sealed = sealRecoveryCode({ code: CODE, escrowKey: keyFor(SECRET) });
  assert.throws(() => openRecoveryCode({ sealed, escrowKey: keyFor(OTHER_SECRET) }));
});

test('two seals of the same code differ, because the IV is fresh every time', () => {
  const key = keyFor(SECRET);
  const first = sealRecoveryCode({ code: CODE, escrowKey: key });
  const second = sealRecoveryCode({ code: CODE, escrowKey: key });
  assert.notDeepEqual(first, second);
  // Both still open, so the difference is the IV and not a corruption.
  assert.equal(openRecoveryCode({ sealed: first, escrowKey: key }), CODE);
  assert.equal(openRecoveryCode({ sealed: second, escrowKey: key }), CODE);
});

test('a tampered ciphertext or tag throws rather than returning something', () => {
  const key = keyFor(SECRET);
  const sealed = sealRecoveryCode({ code: CODE, escrowKey: key });

  // A flipped bit in the ciphertext.
  const corruptedBody = Buffer.from(sealed);
  const bodyIndex = ESCROW_IV_BYTES + 1;
  corruptedBody[bodyIndex] = (corruptedBody[bodyIndex] ?? 0) ^ 0xff;
  assert.throws(() => openRecoveryCode({ sealed: corruptedBody, escrowKey: key }));

  // A flipped bit in the tag.
  const corruptedTag = Buffer.from(sealed);
  const tagIndex = corruptedTag.byteLength - 1;
  corruptedTag[tagIndex] = (corruptedTag[tagIndex] ?? 0) ^ 0xff;
  assert.throws(() => openRecoveryCode({ sealed: corruptedTag, escrowKey: key }));

  // A value too short to be one of ours at all.
  assert.throws(() => openRecoveryCode({ sealed: Buffer.alloc(8), escrowKey: key }));
});

test('the escrow key is a separate frozen label, not the verifier pepper', () => {
  // Domain separation is why a pepper that a login comparison handles on every
  // request is not also the key that opens a diary's recovery code.
  assert.equal(ESCROW_KEY_LABEL, 'openplate-sync:escrow-key:v1');

  const secrets = deriveServerSecrets(SECRET);
  assert.notEqual(secrets.escrowKey.toString('hex'), secrets.verifierPepper);
  assert.notEqual(secrets.escrowKey.toString('hex'), secrets.enumerationSecret);
  // AES-256 needs exactly 32 bytes.
  assert.equal(secrets.escrowKey.byteLength, 32);
});

test('a wrong-length key is refused before anything is encrypted', () => {
  // A 16-byte key would silently give AES-128, and a hex-encoded 32-byte key
  // would be 64 bytes carrying half the entropy. Both are configuration
  // mistakes worth failing loudly on.
  assert.throws(() => sealRecoveryCode({ code: CODE, escrowKey: Buffer.alloc(16) }));
  assert.throws(() => openRecoveryCode({ sealed: Buffer.alloc(60), escrowKey: Buffer.alloc(64) }));
});
