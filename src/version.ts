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
export const SERVICE_VERSION = process.env.SERVICE_VERSION ?? '0.2.0';
