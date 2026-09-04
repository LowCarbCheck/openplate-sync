/**
 * Domain-separated subkeys derived from the single operator-supplied
 * `SERVER_SECRET`.
 *
 * WHY ONE ENV VAR AND NOT TWO: a self-hoster who has to generate, store and
 * rotate two independent secrets will eventually reuse one for the other, and
 * reusing a key across two unrelated HMAC purposes is exactly the mistake
 * domain separation exists to prevent. Deriving both from one root removes
 * the opportunity: they are unequal by construction, and neither can be
 * recovered from the other.
 *
 * The labels are frozen. Changing one is a breaking operational change:
 * `verifierPepper` feeds every stored account verifier (every account would
 * have to reset), `enumerationSecret` feeds the dummy KDF descriptors (a
 * client mid-flight against a dummy would see the salt change), and
 * `escrowKey` decrypts every stored recovery code — change it and every
 * mailed reset on the instance stops working, silently, for accounts that
 * signed up before the change.
 */
import { createHmac } from 'node:crypto';

/** Feeds `lib/verifier.ts` — the pepper mixed into every stored verifier. */
export const VERIFIER_PEPPER_LABEL = 'openplate-sync:verifier-pepper:v1';
/** Feeds `lib/kdf-descriptor.ts` — the key behind the deterministic dummy descriptors served for unknown addresses. */
export const ENUMERATION_SECRET_LABEL = 'openplate-sync:kdf-dummy:v1';
/**
 * Feeds `lib/escrow.ts` — the AES-256-GCM key that seals `accounts.recovery_code_escrow` (M192, ADR-0005).
 *
 * THE THIRD LABEL IS THE ONE THAT DECRYPTS SOMETHING. The other two feed
 * one-way constructions: a verifier and a dummy salt reveal nothing if the
 * key leaks alongside them. This one opens a recovery code, and a recovery
 * code opens a diary. It is derived rather than configured for the reason in
 * the header — an operator asked for a second secret would reuse the first —
 * and it is a SEPARATE label so that the pepper, which a verifier comparison
 * handles on every login, is never the key an escrow is sealed under.
 */
export const ESCROW_KEY_LABEL = 'openplate-sync:escrow-key:v1';

export interface ServerSecrets {
  verifierPepper: string;
  enumerationSecret: string;
  /** RAW 32 bytes, not hex: it is an AES-256-GCM key, and `crypto.createCipheriv` wants the key itself. */
  escrowKey: Buffer;
}

function deriveSubkey(rootSecret: string, label: string): string {
  return createHmac('sha256', rootSecret).update(label).digest('hex');
}

/** Pure. Same root secret always yields the same three values — this is required, not incidental (see the header). */
export function deriveServerSecrets(rootSecret: string): ServerSecrets {
  return {
    verifierPepper: deriveSubkey(rootSecret, VERIFIER_PEPPER_LABEL),
    enumerationSecret: deriveSubkey(rootSecret, ENUMERATION_SECRET_LABEL),
    // HMAC-SHA-256 is 32 bytes, which is exactly an AES-256 key. Taken raw
    // rather than hex-encoded: hex would be 64 bytes of 4-bit-per-character
    // material, and a caller that truncated it to 32 would keep only half the
    // entropy.
    escrowKey: createHmac('sha256', rootSecret).update(ESCROW_KEY_LABEL).digest(),
  };
}
