/**
 * The module surface of this package, for readers and tests.
 *
 * `src/main.ts` — not this file — is the SERVICE entry point (the thing
 * `pnpm start` and the Docker image run). This barrel exists so the pieces
 * can be imported individually: the composition root without the process
 * lifecycle, the handler cores without Express, the wire contract without
 * either.
 *
 * What used to live here — the client crypto, envelope and merge modules —
 * moved into the openplate app (`app/lib/sync/engine/`) in M128 spec 01. They
 * were never the server's business: it stores opaque bytes and cannot decrypt
 * them by construction, so shipping the crypto alongside it only blurred
 * where the trust boundary actually sits.
 */

// The wire contract (normative document: PROTOCOL.md).
export * from './protocol.js';
export type * from './contract-types.js';

// HTTP composition.
export { createApp } from './server/create-app.js';
export type { CreateAppOptions } from './server/create-app.js';
export { registerSyncRoutes } from './server/register-routes.js';
export { registerAuthRoutes, AUTH_API_PREFIX } from './accounts/register-auth-routes.js';
export { createBearerAuthMiddleware, createEntitledUserResolver, getRequestSession } from './server/bearer-auth.js';

// Account system.
export * from './accounts/auth-handlers.js';
export type * from './accounts/account-store.js';

// Persistence.
export { createDatabase, runMigrations, waitForDatabase } from './db/client.js';
export type { Database, DatabaseHandle } from './db/client.js';
export { createDrizzleAccountStore } from './db/account-store.js';
export { createDrizzleStorageAdapter } from './db/storage-adapter.js';
export * as schema from './db/schema.js';

// Configuration and cross-cutting utilities.
export { parseConfig } from './config.js';
export type { ServiceConfig, EmailSettings } from './config.js';
export { createLogger, createSilentLogger } from './logger.js';
export type { Logger, LogLevel } from './logger.js';
export { deriveServerSecrets } from './lib/server-secrets.js';
export { createThrottleStore } from './lib/throttle.js';
export * from './lib/tokens.js';
export * from './lib/verifier.js';
export * from './lib/kdf-descriptor.js';
export { selectTransport } from './mail/transport.js';
export type { MailMessage, MailResult, MailTransport } from './mail/transport.js';
export { SERVICE_VERSION } from './version.js';
