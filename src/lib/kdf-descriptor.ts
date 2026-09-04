/**
 * The per-account KDF descriptor — the non-secret Argon2id salt and cost
 * parameters a NEW device needs BEFORE it can log in, and the deterministic
 * dummy that keeps serving it from becoming an account-enumeration oracle.
 *
 * THE ENUMERATION PROBLEM, stated plainly: a zero-knowledge login requires
 * the client to derive its auth-hash before authenticating, which requires
 * the salt, which requires an UNAUTHENTICATED endpoint keyed by the account's
 * identifier. Done naively that endpoint answers "does this address have an
 * account?" for anyone who asks.
 *
 * THE FIX (decided in the M128 counsel, not left residual): an unknown
 * identifier gets a descriptor derived as `HMAC(enumerationSecret, identifier)`
 * — stable across requests, indistinguishable from a real one, and produced by
 * the SAME function on the SAME code path with the SAME response shape.
 * Stability matters as much as shape: a random dummy would be distinguishable
 * by asking twice.
 *
 * What a dummy costs an attacker: they can still burn Argon2id at 64 MiB per
 * guess and get a login rejection. What it denies them: a cheap, silent,
 * unthrottleable list of which addresses hold accounts.
 *
 * Pure module — no DB, no config, no clock.
 */
import { createHmac } from 'node:crypto';
import { asObject, asPositiveInteger, asString, type JsonValue } from './json.js';

/** Argon2id cost parameters, exactly as PROTOCOL.md §3.1 records them. */
export interface Argon2Params {
  memorySizeKib: number;
  iterations: number;
  parallelism: number;
}

export interface KdfDescriptor {
  /** Base64 Argon2id salt, 16 bytes. Non-secret by design — it exists to be served pre-login. */
  salt: string;
  params: Argon2Params;
}

/** PROTOCOL.md §3.1 defaults. Real accounts store whatever their client chose; the dummy always reports these. */
export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memorySizeKib: 65536,
  iterations: 3,
  parallelism: 1,
};

/** Argon2id salt length in bytes (PROTOCOL.md §3.1). Enforced on real descriptors and matched by the dummy. */
export const KDF_SALT_BYTES = 16;

/** Domain separation for the dummy derivation — frozen; see `lib/server-secrets.ts`. */
const DUMMY_SALT_LABEL = 'kdf-descriptor-salt';

/**
 * Validates a client-submitted descriptor. Returns `null` on anything
 * malformed rather than throwing — every caller turns that into a `400`.
 *
 * The salt is checked for exact length: a client that submits a 1-byte salt
 * has weakened its own account in a way the server can cheaply refuse, and
 * the server must be able to serve a dummy of indistinguishable length.
 */
export function parseKdfDescriptor(value: JsonValue | undefined): KdfDescriptor | null {
  const candidate = asObject(value);
  if (candidate === null) return null;

  const salt = asString(candidate.salt);
  if (salt === null || Buffer.from(salt, 'base64').byteLength !== KDF_SALT_BYTES) return null;

  const params = asObject(candidate.params);
  if (params === null) return null;

  const memorySizeKib = asPositiveInteger(params.memorySizeKib);
  const iterations = asPositiveInteger(params.iterations);
  const parallelism = asPositiveInteger(params.parallelism);
  if (memorySizeKib === null || iterations === null || parallelism === null) return null;

  return { salt, params: { memorySizeKib, iterations, parallelism } };
}

/**
 * The deterministic dummy for an identifier with no account. Same identifier +
 * same `enumerationSecret` always yields the same descriptor; a different
 * secret yields an unrelated one, so two instances of this service cannot be
 * cross-referenced.
 *
 * Callers MUST pass an already-canonicalised value (`lib/verifier.ts`'s
 * `normalizeEmail`). The derivation is over an OPAQUE STRING and cares nothing
 * about its shape, which is why neither the M181 move to handles nor the M192
 * move back to addresses changed a line of it.
 */
export function deriveDummyKdfDescriptor(input: { identifier: string; enumerationSecret: string }): KdfDescriptor {
  const digest = createHmac('sha256', input.enumerationSecret)
    .update(`${DUMMY_SALT_LABEL}:${input.identifier}`)
    .digest();
  return {
    salt: digest.subarray(0, KDF_SALT_BYTES).toString('base64'),
    params: { ...DEFAULT_ARGON2_PARAMS },
  };
}
