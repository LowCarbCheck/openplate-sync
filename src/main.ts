/**
 * Service entry point — the only module in `src/` that reads `process.env`,
 * opens sockets, or decides when the process should die.
 *
 * Boot order is deliberate and strict:
 *   1. Parse config. A misconfiguration must kill the process here, before
 *      anything downstream has a chance to half-work.
 *   2. Wait for Postgres (bounded retry — a `docker compose up` starts both
 *      at once and the database is not ready for a second or two).
 *   3. Run migrations. A self-hoster pulling a newer image must never have to
 *      run a second command, and a half-migrated schema must never serve a
 *      request.
 *   4. Only then open the listener.
 *
 * Anything that fails in 1–3 exits non-zero with a scrubbed message, so a
 * container orchestrator restarts (or, for a genuinely bad config, backs off
 * and reports) rather than a broken instance quietly accepting signups.
 */
import 'dotenv/config';
import { resolve } from 'node:path';
import { parseConfig } from './config.js';
import { createLogger } from './logger.js';
import { createDatabase, runMigrations, waitForDatabase } from './db/client.js';
import { createDrizzleAccountStore } from './db/account-store.js';
import { createDrizzleStorageAdapter } from './db/storage-adapter.js';
import { createDrizzleAdminStore } from './db/admin-store.js';
import { createDrizzleShareStore } from './db/share-store.js';
import { deriveServerSecrets } from './lib/server-secrets.js';
import { createThrottleStore } from './lib/throttle.js';
import { generateFamilyId, generateToken } from './lib/tokens.js';
import { selectTransport } from './mail/transport.js';
import { createApp } from './server/create-app.js';
import type { AuthContext } from './accounts/auth-handlers.js';
import { SERVICE_VERSION } from './version.js';

/** How long a fully-expired token row is kept before the sweeper drops it. */
const TOKEN_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
/** How often the sweeper runs. Hourly is far more often than necessary and costs one indexed DELETE. */
const TOKEN_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

async function main(): Promise<void> {
  const config = parseConfig(process.env);
  const logger = createLogger({ component: 'openplate-sync', level: config.logLevel });

  const secrets = deriveServerSecrets(config.serverSecret);
  const database = createDatabase({ connectionString: config.databaseUrl, ssl: config.databaseSsl });

  await waitForDatabase({ pool: database.pool, logger });
  await runMigrations({
    db: database.db,
    migrationsFolder: resolve(process.env.MIGRATIONS_DIR ?? 'drizzle/migrations'),
  });
  logger.info('Migrations applied');

  const mailTransport = selectTransport(config.email, logger);
  logger.info('Mail transport selected', { transport: mailTransport.name });

  const authContext: AuthContext = {
    store: createDrizzleAccountStore(database.db),
    pepper: secrets.verifierPepper,
    enumerationSecret: secrets.enumerationSecret,
    signupsOpen: config.signupsOpen,
    requireEmailVerification: config.requireEmailVerification,
    clientBaseUrl: config.clientBaseUrl,
    sendMail: (message) => mailTransport.send(message),
    now: () => new Date(),
    mintToken: generateToken,
    mintFamilyId: generateFamilyId,
    logger,
  };

  // `null` unless ADMIN_TOKEN is set, which leaves the whole `/v1/admin` tree
  // answering the ordinary unknown-path 404 — see `server/create-app.ts`.
  const admin =
    config.adminToken === null ? null : { token: config.adminToken, metadata: createDrizzleAdminStore(database.db) };

  // `null` unless SYNC_SHARING is on, which leaves both share subtrees
  // answering the ordinary unknown-path 404 — see `server/create-app.ts`.
  const shares = config.sharingEnabled ? createDrizzleShareStore(database.db) : null;

  const app = createApp({
    authContext,
    storage: createDrizzleStorageAdapter(database.db),
    throttle: createThrottleStore(),
    logger,
    trustProxy: config.trustProxy,
    admin,
    shares,
  });

  const server = app.listen(config.port, () => {
    logger.info('openplate-sync listening', {
      port: config.port,
      serviceVersion: SERVICE_VERSION,
      signupsOpen: config.signupsOpen,
      requireEmailVerification: config.requireEmailVerification,
      // Whether the operator API exists on this instance, never its token.
      adminApi: admin !== null,
      sharing: shares !== null,
    });
  });

  const accountStore = authContext.store;
  const sweeper = setInterval(() => {
    void (async () => {
      try {
        const deleted = await accountStore.purgeExpiredTokens({
          before: new Date(Date.now() - TOKEN_RETENTION_MS),
        });
        if (deleted > 0) logger.info('Purged expired token rows', { deleted });
      } catch (cause) {
        logger.error('Token sweep failed', { error: cause instanceof Error ? cause.message : 'unknown error' });
      }
    })();
  }, TOKEN_SWEEP_INTERVAL_MS);
  // Never the reason the process stays alive.
  sweeper.unref();

  async function shutdown(signal: string): Promise<void> {
    logger.info('Shutting down', { signal });
    clearInterval(sweeper);
    await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    await database.close();
    process.exit(0);
  }

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((cause: unknown) => {
  // Scrubbed: a config or connection error can carry a connection string.
  process.stderr.write(`${cause instanceof Error ? cause.message : 'unknown startup error'}\n`);
  process.exit(1);
});
