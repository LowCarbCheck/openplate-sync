/**
 * The recovery-code escrow: AES-256-GCM under a subkey of `SERVER_SECRET`.
 *
 * WHAT THIS MODULE IS, SAID PLAINLY. It is the one place in this service that
 * can decrypt something. ADR-0004 prohibition 5 forbade server-side escrow
 * outright; ADR-0005 supersedes that with its eyes open, because an
 * organization cannot hand every employee a code they must never lose, and
 * because the operator of a managed instance already sees every plate photo
 * that passes through its AI proxy. What the escrow buys is a mailed password
 * reset that RESTORES THE DIARY rather than replacing the lock on an empty
 * room — the failure ADR-0004 called a negative recovery mechanism.
 *
 * WHAT IT IS NOT. It is not a key to a blob. The sealed value is the recovery
 * code, and the code only becomes a key after the CLIENT runs HKDF over it.
 * That distinction changes nothing about the operator's power (they can run
 * HKDF too) and everything about the code path: nothing on this server ever
 * derives `KEK_r`, ever unwraps a DEK, or ever holds one.
 *
 * FRAMING, frozen: `iv(12) ‖ ciphertext ‖ tag(16)`, one packed buffer, the
 * same packing `sync_blobs.ciphertext` and `sync_key_records.wrapped_dek` use
 * on the client side. A 12-byte IV is the GCM-native size; a 16-byte tag is
 * the full-strength one, and it is appended rather than stored beside so a row
 * is one column.
 *
 * THE CODE IS NEVER LOGGED, here or anywhere. `sealRecoveryCode` takes it,
 * `openRecoveryCode` returns it, and nothing in between writes it to a logger,
 * an error message or a stack trace.
 *
 * Pure module — no config, no DB, no clock. The key is injected.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

/** GCM's native IV size. Frozen: it is the leading bytes of every sealed value ever written. */
export const ESCROW_IV_BYTES = 12;
/** The full-strength GCM tag. Frozen: it is the trailing bytes of every sealed value ever written. */
export const ESCROW_TAG_BYTES = 16;
/** AES-256. The key comes from `lib/server-secrets.ts`, which derives exactly this many bytes. */
export const ESCROW_KEY_BYTES = 32;

const ESCROW_CIPHER = 'aes-256-gcm';

export interface SealRecoveryCodeInput {
  /** The canonical 32-character recovery code (`accounts/auth-input.ts`'s `parseRecoveryCode`). */
  code: string;
  /** The 32-byte subkey from `deriveServerSecrets`. */
  escrowKey: Buffer;
}

export interface OpenRecoveryCodeInput {
  /** The stored `iv ‖ ciphertext ‖ tag` blob, exactly as `sealRecoveryCode` produced it. */
  sealed: Buffer;
  escrowKey: Buffer;
}

function assertKey(escrowKey: Buffer): void {
  if (escrowKey.byteLength !== ESCROW_KEY_BYTES) {
    throw new Error(`escrow key must be ${ESCROW_KEY_BYTES} bytes, got ${escrowKey.byteLength}`);
  }
}

/**
 * Seals a recovery code for storage in `accounts.recovery_code_escrow`.
 *
 * A FRESH RANDOM IV EVERY TIME, so two accounts that happen to share a code
 * (they will not, but the construction must not depend on that) do not share
 * a ciphertext, and so re-escrowing the same code after a rotation is not
 * visibly a no-op to anyone reading the column.
 */
export function sealRecoveryCode(input: SealRecoveryCodeInput): Buffer {
  assertKey(input.escrowKey);
  const iv = randomBytes(ESCROW_IV_BYTES);
  const cipher = createCipheriv(ESCROW_CIPHER, input.escrowKey, iv);
  const ciphertext = Buffer.concat([cipher.update(input.code, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, ciphertext, cipher.getAuthTag()]);
}

/**
 * Opens a sealed recovery code.
 *
 * THROWS rather than returning `null` on any failure, and the asymmetry with
 * the rest of this service is deliberate. Every other parser here is total
 * because its input is a stranger's request body. This input is our own
 * column, sealed by our own key: a tag failure means the operator rotated
 * `SERVER_SECRET` (which has already broken every verifier on the instance) or
 * the column was tampered with. Neither is a `400` and neither has a sensible
 * fallback, so it surfaces as the 500 it is instead of as a quiet empty
 * string that a mail would then deliver.
 */
export function openRecoveryCode(input: OpenRecoveryCodeInput): string {
  assertKey(input.escrowKey);
  if (input.sealed.byteLength <= ESCROW_IV_BYTES + ESCROW_TAG_BYTES) {
    throw new Error('sealed recovery code is too short to contain an IV, a ciphertext and a tag');
  }

  const iv = input.sealed.subarray(0, ESCROW_IV_BYTES);
  const tag = input.sealed.subarray(input.sealed.byteLength - ESCROW_TAG_BYTES);
  const ciphertext = input.sealed.subarray(ESCROW_IV_BYTES, input.sealed.byteLength - ESCROW_TAG_BYTES);

  const decipher = createDecipheriv(ESCROW_CIPHER, input.escrowKey, iv);
  decipher.setAuthTag(tag);
  // `final()` is what verifies the tag; a wrong key or altered bytes throw
  // here, which is exactly the outcome this function documents.
  return `${decipher.update(ciphertext, undefined, 'utf8')}${decipher.final('utf8')}`;
}
