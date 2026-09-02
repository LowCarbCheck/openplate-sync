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
 * have to reset), and `enumerationSecret` feeds the dummy KDF descriptors
 * (a client mid-flight against a dummy would see the salt change).
 */
import { createHmac } from 'node:crypto';

/** Feeds `lib/verifier.ts` — the pepper mixed into every stored verifier. */
export const VERIFIER_PEPPER_LABEL = 'openplate-sync:verifier-pepper:v1';
/** Feeds `lib/kdf-descriptor.ts` — the key behind the deterministic dummy descriptors served for unknown handles. */
export const ENUMERATION_SECRET_LABEL = 'openplate-sync:kdf-dummy:v1';

export interface ServerSecrets {
  verifierPepper: string;
  enumerationSecret: string;
}

function deriveSubkey(rootSecret: string, label: string): string {
  return createHmac('sha256', rootSecret).update(label).digest('hex');
}

/** Pure. Same root secret always yields the same pair — this is required, not incidental (see the header). */
export function deriveServerSecrets(rootSecret: string): ServerSecrets {
  return {
    verifierPepper: deriveSubkey(rootSecret, VERIFIER_PEPPER_LABEL),
    enumerationSecret: deriveSubkey(rootSecret, ENUMERATION_SECRET_LABEL),
  };
}
