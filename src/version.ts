/**
 * The service's own build identifier, reported by `GET /health` as
 * `serviceVersion` (PROTOCOL.md §5.6).
 *
 * Deliberately a source constant rather than a runtime read of
 * `package.json`: the production artifact is a single esbuild bundle in
 * `dist/`, where `package.json` is not guaranteed to sit at any particular
 * relative path. `SERVICE_VERSION` env overrides it so a CI build can stamp
 * a git sha without a source edit.
 *
 * It is DIAGNOSTIC ONLY. `protocolVersion`/`envelopeVersion` are the values
 * a client compares (PROTOCOL.md §6); this one is never compared by anyone.
 */

/**
 * Resolution order, and why each step exists:
 *
 *  1. `SERVICE_VERSION` in the environment — lets an operator or a CI build
 *     stamp a git sha without touching source.
 *  2. `__SERVICE_VERSION__`, inlined by `scripts/build.ts` from `package.json`
 *     at build time. This is what the shipped image reports.
 *  3. `'0.0.0-dev'` — only reachable when running the TS sources directly.
 *
 * There is deliberately NO hand-maintained release number here any more. The
 * previous constant said `'0.2.0'` while the 0.3.0 image was serving traffic,
 * and that string is precisely what an operator reads to decide whether their
 * deploy landed.
 */
// SAFETY: `scripts/build.ts` replaces this exact member expression with a string
// literal at build time (esbuild `define`). Running the TS sources leaves it
// absent, which the `??` chain below handles — so the cast describes what the
// build guarantees, not an assumption about untrusted input.
const injected = (globalThis as { __SERVICE_VERSION__?: string }).__SERVICE_VERSION__;

export const SERVICE_VERSION = process.env.SERVICE_VERSION ?? injected ?? '0.0.0-dev';
