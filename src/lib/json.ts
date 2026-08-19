/**
 * The JSON I/O boundary — one named domain type for "bytes that arrived over
 * the wire", plus the handful of decoders that turn it into real values.
 *
 * Every request body enters the service as parsed JSON of unproven shape.
 * Rather than let that vagueness spread through the code as `unknown` and
 * ad-hoc `typeof` ladders, it is given a name here — {@link JsonValue} — and
 * narrowed only through the decoders below. The parsers elsewhere in the
 * service (`accounts/auth-input.ts`, `lib/kdf-descriptor.ts`, `protocol.ts`)
 * take a `JsonValue` and hand back a domain type; nothing downstream of them
 * re-inspects a representation.
 *
 * This module is the ONE place that discriminates JSON primitives at runtime,
 * because it *is* the boundary: these decoders are what let every other
 * module branch on a decoded value instead of on a `typeof`. Each such check
 * below carries a narrow, single-line rule suppression for that reason.
 *
 * Pure module — no config, no DB, no clock.
 */

/** A value that came from `JSON.parse` (or Express's body parser) and has not been decoded yet. */
export type JsonValue = string | number | boolean | null | JsonValue[] | JsonObject;

/**
 * A JSON object with unproven keys. Values are optional because an absent key
 * and a present `undefined` are indistinguishable to a caller, and the
 * decoders below must treat both identically.
 */
export interface JsonObject {
  readonly [key: string]: JsonValue | undefined;
}

/**
 * Decodes an object. Arrays and `null` are rejected first: both are `typeof
 * 'object'` in JavaScript and neither is a field bag.
 */
export function asObject(value: JsonValue | undefined): JsonObject | null {
  if (value === null || value === undefined || Array.isArray(value)) return null;
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- boundary decoder; see the module docblock.
  return typeof value === 'object' ? value : null;
}

/** Decodes a string. No coercion — a number where a string was promised is a client bug, not an input. */
export function asString(value: JsonValue | undefined): string | null {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- boundary decoder; see the module docblock.
  return typeof value === 'string' ? value : null;
}

/** Decodes a finite number. `NaN` and the infinities are rejected: `JSON.parse` cannot produce them. */
export function asNumber(value: JsonValue | undefined): number | null {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- boundary decoder; see the module docblock.
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

/** Decodes a boolean. */
export function asBoolean(value: JsonValue | undefined): boolean | null {
  // oxlint-disable-next-line anti-slop/no-runtime-typeof -- boundary decoder; see the module docblock.
  return typeof value === 'boolean' ? value : null;
}

/** Decodes an array. Elements stay undecoded — each caller decodes them with the decoder its own contract needs. */
export function asArray(value: JsonValue | undefined): JsonValue[] | null {
  return Array.isArray(value) ? value : null;
}

/** Decodes a positive integer — the only numeric shape any parameter in this service accepts. */
export function asPositiveInteger(value: JsonValue | undefined): number | null {
  const decoded = asNumber(value);
  return decoded !== null && Number.isInteger(decoded) && decoded > 0 ? decoded : null;
}

/** Decodes a non-empty string that has been trimmed. Blank-after-trim is treated as absent. */
export function asTrimmedString(value: JsonValue | undefined): string | null {
  const decoded = asString(value);
  if (decoded === null) return null;
  const trimmed = decoded.trim();
  return trimmed.length === 0 ? null : trimmed;
}
