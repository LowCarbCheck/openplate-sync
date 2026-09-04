/**
 * `POST /v1/sync/rotate-dek` handler core — ADR-0002's Tier 2 revocation.
 *
 * Tier 1 (deleting a share row) stops the server serving, immediately and
 * completely. It cannot un-know: the clinician may hold the DEK and
 * everything already pulled. Rotation is what defends the FUTURE against a
 * leaked DEK plus a leaky or coerced server, and it is the incident response
 * for a compromised clinician account.
 *
 * Everything below is validation. The actual write is one transaction inside
 * `db/rotation-store.ts` — blob, both key records, every kept share, and the
 * deletion of every share not resubmitted, landing together or not at all
 * (ADR-0002 prohibition 8).
 *
 * WHAT IS REFUSED, AND WHY EACH REFUSAL EXISTS RATHER THAN A LENIENT DEFAULT:
 *
 *  - A MISSING KEY-RECORD KIND is a 400, never a silent partial rotation. A
 *    submission carrying only the `passphrase` wrap would leave the
 *    `recovery` record wrapping a DEK that no longer opens anything, so the
 *    recovery code would still log the account in and would never again
 *    decrypt it — discovered by the user on the worst possible day.
 *  - A MISSING `newRecoveryAuthHash` OR `recoveryCode` is a 400 too, and for
 *    the same reason one step further out (M192 addendum). The `recovery` wrap
 *    above is sealed under a KEK derived from a code the client has just
 *    minted, so the account's recovery verifier and its escrow have to move
 *    with it. Those two are refused in the ROUTE, which is where the raw
 *    values still exist; by the time they reach here they are a verifier and
 *    a sealed blob, and "missing" is no longer representable.
 *  - A DUPLICATE GRANTEE in the keep list is a 400: two wraps for one row is
 *    a client that does not know its own state, and picking one silently
 *    would decide which clinician keeps access by array order.
 *  - The KEEP LIST is exhaustive by contract. Absence means revoke, so an
 *    empty `shares` array is valid and meaningful — but an ABSENT key is not,
 *    for the reason §5.4 requires `expectedUpdatedAt` explicitly: silence
 *    must never be read as consent on a path that can strand data. That
 *    check lives in the route, where the difference between `[]` and a
 *    missing key still exists.
 */
import type { RotateDekInput, RotateDekShareInput, SyncRotationStore } from '../contract-types.js';
import { SYNC_KEY_RECORD_KINDS } from '../protocol.js';
import { SHARE_WRAPPED_DEK_BYTES } from './share-routes.js';

/** Enough for any reasonable fingerprint encoding — the same bound `share-routes.ts` applies on the grant path. */
const MAX_FINGERPRINT_CHARS = 128;

export interface RotateDekRequest extends RotateDekInput {
  /**
   * Whether this instance has a share graph at all (`SYNC_SHARING`).
   *
   * Rotation itself is NOT gated on it — see `rotate-dek-route.ts` — but a
   * keep list is meaningless where no share can exist, and accepting one
   * silently would tell a client its clinicians were re-wrapped when the
   * instance has never held a share row.
   */
  sharingEnabled: boolean;
}

export type RotateDekHandlerResult =
  | { status: 'ok'; newVersion: number; keptShares: number; revokedShares: number }
  | { status: 'invalid'; reason: string }
  | { status: 'conflict'; currentVersion: number }
  | { status: 'unknown-share'; granteeAccountId: number };

function validateKeyRecords(input: RotateDekInput): string | null {
  const kinds = input.keyRecords.map((record) => record.kind);
  if (kinds.length !== new Set(kinds).size) return 'rotate-dek accepts at most one key record per kind';
  for (const kind of SYNC_KEY_RECORD_KINDS) {
    if (!kinds.includes(kind)) return `rotate-dek requires both key record kinds; missing key record kind: ${kind}`;
  }

  for (const record of input.keyRecords) {
    if (record.wrappedDek.byteLength === 0) return 'wrappedDek must not be empty';
    // The same two rules PROTOCOL.md §5.4 applies to a single-record PUT: the
    // recovery path is HKDF-only and has no parameters to record.
    if (record.kind === 'recovery' && record.kdfDescriptor !== null) {
      return 'recovery key records must not carry a kdfDescriptor';
    }
    if (record.kind === 'passphrase' && record.kdfDescriptor === null) {
      return 'passphrase key records require a kdfDescriptor';
    }
  }
  return null;
}

function validateShare(share: RotateDekShareInput, accountId: number): string | null {
  if (!Number.isInteger(share.granteeAccountId) || share.granteeAccountId < 1) {
    return 'granteeAccountId must be a positive integer';
  }
  if (share.granteeAccountId === accountId) return 'an account cannot hold a share on itself';
  if (share.wrappedDek.byteLength !== SHARE_WRAPPED_DEK_BYTES) {
    return `a share wrappedDek must be exactly ${SHARE_WRAPPED_DEK_BYTES} bytes`;
  }
  const fingerprint = share.recipientKeyFingerprint.trim();
  if (fingerprint.length === 0 || fingerprint.length > MAX_FINGERPRINT_CHARS) {
    return 'recipientKeyFingerprint must be a non-empty string';
  }
  return null;
}

function validateShares(input: RotateDekRequest): string | null {
  if (!input.sharingEnabled && input.shares.length > 0) {
    return 'this instance holds no shares';
  }
  const grantees = input.shares.map((share) => share.granteeAccountId);
  if (grantees.length !== new Set(grantees).size) return 'each grantee may appear at most once';
  for (const share of input.shares) {
    const reason = validateShare(share, input.accountId);
    if (reason !== null) return reason;
  }
  return null;
}

/** Validates the whole submission, then hands it to the one transaction. Never throws — every failure is a typed result. */
export async function handleRotateDek(
  request: RotateDekRequest,
  rotation: SyncRotationStore,
): Promise<RotateDekHandlerResult> {
  if (!Number.isInteger(request.blob.baseVersion) || request.blob.baseVersion < 0) {
    return { status: 'invalid', reason: 'baseVersion must be a non-negative integer' };
  }
  if (!Number.isInteger(request.blob.envelopeVersion) || request.blob.envelopeVersion < 1) {
    return { status: 'invalid', reason: 'envelopeVersion must be a positive integer' };
  }
  if (request.blob.ciphertext.byteLength === 0) {
    return { status: 'invalid', reason: 'ciphertext must not be empty' };
  }

  const keyRecordProblem = validateKeyRecords(request);
  if (keyRecordProblem !== null) return { status: 'invalid', reason: keyRecordProblem };

  const shareProblem = validateShares(request);
  if (shareProblem !== null) return { status: 'invalid', reason: shareProblem };

  const result = await rotation.rotateDek({
    accountId: request.accountId,
    blob: request.blob,
    keyRecords: request.keyRecords,
    shares: request.shares,
    // Already derived by the route from `newRecoveryAuthHash` and
    // `recoveryCode`, both required (M192 addendum). They ride into the same
    // transaction as everything else — see `SyncRotationStore`.
    recoveryVerifier: request.recoveryVerifier,
    recoveryCodeEscrow: request.recoveryCodeEscrow,
  });

  if (result.ok) {
    return {
      status: 'ok',
      newVersion: result.newVersion,
      keptShares: result.keptShares,
      revokedShares: result.revokedShares,
    };
  }
  if (result.reason === 'blob-conflict') return { status: 'conflict', currentVersion: result.currentVersion };
  return { status: 'unknown-share', granteeAccountId: result.granteeAccountId };
}
