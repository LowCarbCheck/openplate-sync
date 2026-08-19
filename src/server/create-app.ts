/**
 * Composition root for the HTTP surface: assembles CORS, the health
 * handshake, the account routes, the bearer-guarded sync routes, and the
 * terminal error handler into one Express app.
 *
 * It takes a fully-built `AuthContext` and `SyncStorageAdapter` rather than a
 * config object and a connection string, so the integration suite can boot
 * the REAL app against a real database while still swapping the clock, the
 * token minter, and the mailer. Everything that reads `process.env` lives in
 * `main.ts`; nothing below does.
 *
 * ORDER MATTERS, in three places:
 *  1. CORS first, so even a `401` and a preflight carry the headers.
 *  2. The bearer middleware is mounted on the sync prefix BEFORE the sync
 *     router, so an unauthenticated caller gets `401` instead of falling
 *     through to `resolveEntitledUser`'s `403`.
 *  3. The 404 and the error handler are last — Express only reaches a
 *     four-argument handler after everything before it has passed along.
 */
import express from 'express';
import type { Express } from 'express';
import { ENVELOPE_VERSION, PROTOCOL_VERSION, SYNC_API_PREFIX } from '../protocol.js';
import type { ProtocolHandshake } from '../protocol.js';
import type { SyncStorageAdapter } from '../contract-types.js';
import type { AuthContext } from '../accounts/auth-handlers.js';
import { registerAuthRoutes } from '../accounts/register-auth-routes.js';
import { registerSyncRoutes } from './register-routes.js';
import { createBearerAuthMiddleware, createEntitledUserResolver } from './bearer-auth.js';
import { createCorsMiddleware } from './cors.js';
import { createErrorMiddleware, handleNotFound } from './error-middleware.js';
import type { ThrottleStore } from '../lib/throttle.js';
import type { Logger } from '../logger.js';
import { SERVICE_VERSION } from '../version.js';

export interface CreateAppOptions {
  authContext: AuthContext;
  storage: SyncStorageAdapter;
  throttle: ThrottleStore;
  logger: Logger;
  /** Express `trust proxy`. Wrong here means `req.ip` is the proxy's and the whole throttle is one shared bucket. */
  trustProxy: boolean | number;
}

export function createApp(options: CreateAppOptions): Express {
  const app = express();
  app.set('trust proxy', options.trustProxy);
  // Nothing here serves HTML or benefits from an ETag; both only add
  // surface and a version banner.
  app.disable('x-powered-by');
  app.disable('etag');

  app.use(createCorsMiddleware());

  /**
   * `GET /health` — the version handshake of PROTOCOL.md §6, and the container
   * healthcheck. Unauthenticated on purpose: a client must be able to discover
   * that it is incompatible BEFORE it has credentials, and a healthcheck that
   * needed a token would report on the token, not the service.
   */
  app.get('/health', (_req, res) => {
    const handshake: ProtocolHandshake = {
      protocolVersion: PROTOCOL_VERSION,
      envelopeVersion: ENVELOPE_VERSION,
      serviceVersion: SERVICE_VERSION,
    };
    res.status(200).json(handshake);
  });

  const requireAuth = createBearerAuthMiddleware(options.authContext);
  registerAuthRoutes(app, { ctx: options.authContext, throttle: options.throttle, requireAuth });

  // Every blob/key-record route is behind the bearer gate. `registerSyncRoutes`
  // still does its own `resolveEntitledUser` check — defence in depth, and the
  // seam a future entitlement rule would use.
  app.use(SYNC_API_PREFIX, requireAuth);
  registerSyncRoutes(app, {
    storage: options.storage,
    resolveEntitledUser: createEntitledUserResolver(),
    logger: options.logger,
  });

  app.use(handleNotFound);
  app.use(createErrorMiddleware(options.logger));

  return app;
}
