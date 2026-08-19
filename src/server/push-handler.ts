/**
 * Push-blob handler core (design spec D3/D4) — CAS write. Separated from the
 * Express glue (`register-routes.ts`) so it's unit-testable against a fake
 * `SyncStorageAdapter`, with no HTTP server involved.
 */
import type { SyncStorageAdapter } from '../contract-types.js';

export interface PushBlobInput {
  accountId: number;
  baseVersion: number;
  envelopeVersion: number;
  ciphertext: Uint8Array;
}

export type PushBlobResult =
  | { status: 'accepted'; newVersion: number }
  | { status: 'conflict'; currentVersion: number }
  | { status: 'invalid'; reason: string };

/** Validates the request shape, then attempts the CAS write. Never throws — every failure is a typed result. */
export async function handlePushBlob(input: PushBlobInput, storage: SyncStorageAdapter): Promise<PushBlobResult> {
  if (!Number.isInteger(input.baseVersion) || input.baseVersion < 0) {
    return { status: 'invalid', reason: 'baseVersion must be a non-negative integer' };
  }
  if (!Number.isInteger(input.envelopeVersion) || input.envelopeVersion < 1) {
    return { status: 'invalid', reason: 'envelopeVersion must be a positive integer' };
  }
  if (input.ciphertext.byteLength === 0) {
    return { status: 'invalid', reason: 'ciphertext must not be empty' };
  }

  const result = await storage.putBlobIfVersionMatches({
    accountId: input.accountId,
    baseVersion: input.baseVersion,
    envelopeVersion: input.envelopeVersion,
    ciphertext: input.ciphertext,
  });

  return result.ok
    ? { status: 'accepted', newVersion: result.newVersion }
    : { status: 'conflict', currentVersion: result.currentVersion };
}
