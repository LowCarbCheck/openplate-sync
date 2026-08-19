/**
 * Capacity-cliff observability, as a pure decision so it can be tested
 * without an HTTP server or a 2 MiB buffer.
 *
 * PROTOCOL.md §8 states the problem plainly: one blob holds an account's
 * ENTIRE store, and daily food logging walks it toward the 2 MiB cap over
 * years. Gzip bought roughly an order of magnitude of headroom; it did not
 * remove the cliff, and the fix (chunked or per-entity blobs) is a protocol
 * version bump, not a patch.
 *
 * That fix must be started because a graph crossed a line, not because a user
 * filed a bug saying sync stopped working. So every push that crosses 80% of
 * the cap logs a warning naming the account and the byte count. The gap
 * between the first warning and the first hard `413` is months of daily
 * logging — the entire point is that it be visible for all of them.
 */
import { MAX_BLOB_BYTES } from '../protocol.js';

/** Fraction of `MAX_BLOB_BYTES` at which a push starts warning. */
export const BLOB_SIZE_WARN_RATIO = 0.8;

/** Absolute byte threshold, derived so raising the cap can never leave this behind. */
export const BLOB_SIZE_WARN_BYTES = Math.floor(MAX_BLOB_BYTES * BLOB_SIZE_WARN_RATIO);

/** Whether a push of `byteLength` has entered the warning band. */
export function shouldWarnBlobSize(byteLength: number): boolean {
  return byteLength >= BLOB_SIZE_WARN_BYTES;
}

/** Percentage of the cap this push occupies, rounded to a whole number for the log line. */
export function blobCapacityPercent(byteLength: number): number {
  return Math.round((byteLength / MAX_BLOB_BYTES) * 100);
}
