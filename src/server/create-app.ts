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
 *
 * THE ADMIN API IS MOUNTED, OR THE WHOLE TREE IS A 404. `options.admin` is
 * absent on every deployment that has not set `ADMIN_TOKEN`, which is the
 * default, and then `/v1/admin/*` answers exactly what `/wp-admin` answers.
 * Not 401: a 401 confirms that an admin surface exists here and is merely
 * locked, on a service whose threat model assumes the attacker can reach it.
 * This service auto-deploys on push, so the commit that adds the routes is the
 * commit that puts them in production — the indistinguishability has to be
 * true from the first one. See
 * `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`.
 *
 * THE SHARE TREE IS THE SAME BARGAIN, WITH ONE EXTRA CONSTRAINT. `SYNC_SHARING`
 * unset means `/v1/sync/shares*` and `/v1/sync/shared*` answer the ordinary
 * unknown-path 404 to everybody. Its terminator is mounted BEFORE the bearer
 * middleware rather than after it, because those paths sit inside
 * `SYNC_API_PREFIX`: mounted after, an unconfigured tree would answer 401 to
 * an anonymous caller and announce that a credential exists worth guessing.
 * See `docs/adr/0002-sharing-a-diary-without-giving-the-server-a-key.md`.
 */
import express from 'express';
import type { Express } from 'express';
import { ENVELOPE_VERSION, PROTOCOL_VERSION, SYNC_API_PREFIX } from '../protocol.js';
import type { ProtocolHandshake } from '../protocol.js';
import type { SyncRotationStore, SyncShareStore, SyncStorageAdapter } from '../contract-types.js';
import type { AuthContext } from '../accounts/auth-handlers.js';
import { registerAuthRoutes } from '../accounts/register-auth-routes.js';
import { ADMIN_API_PREFIX, createAdminRoutes } from './admin-routes.js';
import { createAdminAuthMiddleware } from './admin-auth.js';
import { registerSyncRoutes } from './register-routes.js';
import { SHARE_API_PREFIXES, registerShareRoutes } from './share-routes.js';
import { registerRotateDekRoute } from './rotate-dek-route.js';
import { createBearerAuthMiddleware, createEntitledUserResolver } from './bearer-auth.js';
import { createCorsMiddleware } from './cors.js';
import { createErrorMiddleware, handleNotFound } from './error-middleware.js';
import type { AdminMetadataStore } from '../admin/admin-store.js';
import type { ThrottleStore } from '../lib/throttle.js';
import type { Logger } from '../logger.js';
import { SERVICE_VERSION } from '../version.js';

/**
 * What the admin API needs to exist. `createApp` takes this as an OPTION and
 * treats its absence as "no admin surface at all" — the same condition
 * `config.adminToken === null` expresses in `main.ts`.
 */
export interface AdminSurfaceOptions {
  /** Already length-validated by `parseConfig`; this module only compares it. */
  token: string;
  /** Metadata reads. Erasure goes through `authContext.store`, the same method the self-service path calls. */
  metadata: AdminMetadataStore;
}

export interface CreateAppOptions {
  authContext: AuthContext;
  storage: SyncStorageAdapter;
  /**
   * The atomic DEK rotation of PROTOCOL.md §5.17. Required on every instance,
   * deliberately unlike `shares` — see below, and `server/rotate-dek-route.ts`.
   */
  rotation: SyncRotationStore;
  throttle: ThrottleStore;
  logger: Logger;
  /** Express `trust proxy`. Wrong here means `req.ip` is the proxy's and the whole throttle is one shared bucket. */
  trustProxy: boolean | number;
  /**
   * The operator's API, or `null`/absent for "this instance does not have
   * one" — which is the default and what every unconfigured deployment gets.
   * See the module header for why absence is a 404 rather than a 401.
   */
  admin?: AdminSurfaceOptions | null;
  /**
   * The share graph's storage, or `null`/absent for "this instance does not
   * do sharing" — which is the default and what every deployment without
   * `SYNC_SHARING` gets. Absence is a 404 on both share subtrees, not a
   * mounted-but-refusing surface.
   */
  shares?: SyncShareStore | null;
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

  // THE SHARE TERMINATOR, AND WHY IT IS HERE AND NOT LOWER DOWN.
  //
  // `SYNC_SHARING` is unset on every deployment that has not deliberately
  // turned sharing on. Both share subtrees then answer the ordinary
  // unknown-path 404, to everybody, credentialed or not — the same bargain
  // the admin tree makes, for the same reason (this service auto-deploys on
  // push).
  //
  // The ORDER is the load-bearing part. These paths live inside
  // `SYNC_API_PREFIX`, so the bearer middleware mounted just below would
  // otherwise reach them first and answer 401 to an anonymous caller — which
  // announces that a credential exists here worth guessing. Mounting the
  // terminator ahead of authentication is what makes an unconfigured instance
  // indistinguishable from one where the feature was never written.
  const shares = options.shares ?? null;
  if (shares === null) {
    // No SYNC_SHARING on this instance: an explicit 404, never a bare absence.
    for (const prefix of SHARE_API_PREFIXES) {
      app.use(prefix, handleNotFound);
    }
  }

  // Every blob/key-record route is behind the bearer gate. `registerSyncRoutes`
  // still does its own `resolveEntitledUser` check — defence in depth, and the
  // seam a future entitlement rule would use.
  app.use(SYNC_API_PREFIX, requireAuth);
  const resolveEntitledUser = createEntitledUserResolver();
  registerSyncRoutes(app, {
    storage: options.storage,
    resolveEntitledUser,
    logger: options.logger,
  });

  // `POST /v1/sync/rotate-dek`, on EVERY instance — it is not part of the
  // dark share surface. It rewrites the caller's own blob and their own two
  // key records, rows that exist on every account everywhere, and an owner
  // who has never shared anything still needs a way to retire a DEK they
  // believe leaked. `sharingEnabled` only decides whether a keep list may say
  // anything; the route itself is never gated. See that module's header.
  registerRotateDekRoute(app, {
    rotation: options.rotation,
    resolveEntitledUser,
    sharingEnabled: shares !== null,
  });

  // The share family, when this instance has one. It is handed the same
  // caller resolver, and deliberately NOT a way to turn a caller into a
  // target — see `share-routes.ts`'s header on the confused deputy that
  // reusing this resolver for target selection would create.
  if (shares !== null) {
    registerShareRoutes(app, { shares, storage: options.storage, resolveEntitledUser });
  }

  // The admin API, or nothing that admits to being one.
  //
  // The `else` branch is not merely "leave it unmounted": it is an explicit
  // terminator, so the answer for `/v1/admin/*` is pinned to the ordinary
  // unknown-path 404 and cannot be changed into a 401 by some future
  // middleware mounted between here and the fallthrough below.
  const admin = options.admin ?? null;
  if (admin === null) {
    app.use(ADMIN_API_PREFIX, handleNotFound);
  } else {
    app.use(
      ADMIN_API_PREFIX,
      createAdminAuthMiddleware({ adminToken: admin.token, logger: options.logger }),
      createAdminRoutes({ metadata: admin.metadata, accounts: options.authContext.store, logger: options.logger }),
    );
  }

  app.use(handleNotFound);
  app.use(createErrorMiddleware(options.logger));

  return app;
}
