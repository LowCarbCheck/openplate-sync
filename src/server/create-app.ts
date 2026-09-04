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
 * THE ADMIN API IS ALWAYS MOUNTED, AND ITS MIDDLEWARE DECIDES WHAT TO ADMIT
 * TO (M192). It used to be mounted only when `ADMIN_TOKEN` was set, so absence
 * was expressed as a missing router; an admin ACCOUNT's own access token is
 * now a second credential, and whether one exists is not something a
 * mount-time branch can know. `server/admin-auth.ts` therefore answers the
 * ordinary unknown-path 404 when no static token is configured AND the caller
 * is not an admin account — the same answer `/wp-admin` gets, and the same
 * property ADR-0001 bought. Not 401: a 401 confirms that an admin surface
 * exists here and is merely locked, on a service whose threat model assumes
 * the attacker can reach it. This service auto-deploys on push, so the commit
 * that adds a route is the commit that puts it in production. See
 * `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`.
 *
 * THE SHARE TREE IS THE SAME BARGAIN, WITH ONE EXTRA CONSTRAINT. `SYNC_SHARING`
 * unset means `/v1/sync/shares*` and `/v1/sync/shared*` answer the ordinary
 * unknown-path 404 to everybody. Its terminator is mounted BEFORE the bearer
 * middleware rather than after it, because those paths sit inside
 * `SYNC_API_PREFIX`: mounted after, an unconfigured tree would answer 401 to
 * an anonymous caller and announce that a credential exists worth guessing.
 * See `docs/adr/0002-sharing-a-diary-without-giving-the-server-a-key.md`.
 *
 * THE RESEARCH TREE IS THE SAME BARGAIN AGAIN, AND ON ITS OWN FLAG.
 * `SYNC_RESEARCH` unset means `/v1/sync/contributions*` and
 * `/v1/sync/study*` answer the ordinary unknown-path 404, to everybody, with
 * the terminator mounted BEFORE the bearer middleware for the same reason.
 * It is INDEPENDENT of `SYNC_SHARING` — neither flag implies the other, and
 * a deployment may reasonably run either alone. See
 * `docs/adr/0003-research-contributions-pseudonymous-but-never-anonymous.md`.
 */
import express from 'express';
import type { Express } from 'express';
import { ENVELOPE_VERSION, PROTOCOL_VERSION, SYNC_API_PREFIX } from '../protocol.js';
import type { InstanceInfo, OperatorNotice, ProtocolHandshake } from '../protocol.js';
import type { SyncResearchStore, SyncRotationStore, SyncShareStore, SyncStorageAdapter } from '../contract-types.js';
import type { AuthContext } from '../accounts/auth-handlers.js';
import { registerAuthRoutes } from '../accounts/register-auth-routes.js';
import { ADMIN_API_PREFIX, createAdminRoutes, type AdminLinkBases } from './admin-routes.js';
import { createAdminAuthMiddleware } from './admin-auth.js';
import { registerSyncRoutes } from './register-routes.js';
import { SHARE_API_PREFIXES, registerShareRoutes } from './share-routes.js';
import { RESEARCH_API_PREFIXES, registerResearchRoutes } from './research-routes.js';
import { registerRotateDekRoute } from './rotate-dek-route.js';
import { CHAT_COMPLETIONS_PATH, registerAiRoute } from '../ai/register-ai-route.js';
import type { AiQuotaStore } from '../ai/quota-store.js';
import type { AiUpstreamConfig } from '../ai/proxy.js';
import { createBearerAuthMiddleware, createEntitledUserResolver } from './bearer-auth.js';
import { createCorsMiddleware } from './cors.js';
import { createErrorMiddleware, handleNotFound } from './error-middleware.js';
import type { AdminMetadataStore } from '../admin/admin-store.js';
import type { InviteStore } from '../admin/invite-store.js';
import { createNoopMailer, type Mailer } from '../mail/mailer.js';
import type { ThrottleStore } from '../lib/throttle.js';
import type { Logger } from '../logger.js';
import { SERVICE_VERSION } from '../version.js';

/**
 * What the admin API needs to exist.
 *
 * It is REQUIRED now, not optional. Signup is invite-only and always has been
 * since M192, so an instance with no invite store is an instance nobody can
 * ever join; and the tree is mounted whether or not a static `ADMIN_TOKEN` is
 * configured, because an admin account's session is the other credential.
 * `token: null` is what "no static token" looks like, and
 * `server/admin-auth.ts` turns it into a 404 rather than a 401.
 */
export interface AdminSurfaceOptions {
  /** Already length-validated by `parseConfig`, or `null` for an instance with no break-glass credential. */
  token: string | null;
  /** Metadata reads. Erasure goes through `authContext.store`, the same method the self-service path calls. */
  metadata: AdminMetadataStore;
  /** Invite minting and revocation — the only door onto this service. */
  invites: InviteStore;
  /** Where a join link points, or `null` when this instance cannot build one. */
  links?: AdminLinkBases | null;
}

/** What the AI proxy needs to exist. Absent is a 404 on its path, exactly as an absent share store is. */
export interface AiSurfaceOptions {
  upstream: AiUpstreamConfig;
  quota: AiQuotaStore;
  /** Requests per account in any trailing 60 seconds (`AI_RATE_LIMIT_PER_MINUTE`). */
  perMinute: number;
  /** The largest body the proxy route accepts, in bytes (`AI_MAX_REQUEST_BYTES`, default 8 MB). */
  maxRequestBytes: number;
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
   * The operator's message, published on the health handshake, or
   * `null`/absent for an instance with nothing to say — the default. Static
   * config (`SYNC_NOTICE`), never a stored record: see `config.ts`.
   */
  notice?: OperatorNotice | null;
  /** The operator's API. Required — see {@link AdminSurfaceOptions}. */
  admin: AdminSurfaceOptions;
  /**
   * What this instance calls itself on the handshake. Absent means the
   * `instance` field is omitted entirely, which is what a client older than
   * protocol 2 expects to see.
   */
  instance?: InstanceInfo | null;
  /**
   * The two letters this service sends. Absent means a no-op mailer, which is
   * what an instance with no mail configuration gets — invites come back as
   * links instead (`mail/mailer.ts`).
   */
  mailer?: Mailer;
  /**
   * Whether mail is CONFIGURED, which the mailer cannot report: the no-op
   * resolves, so a send that did nothing looks like one that worked. Every
   * `emailed` this service returns is this AND a successful send.
   */
  mailConfigured?: boolean;
  /** Injected, like every clock in this repo, so a test can pin "today" for a quota and an invite's status. */
  now?: () => Date;
  /**
   * The AI proxy, or `null`/absent for "this instance offers no AI" — the
   * default, and what every deployment without `UPSTREAM_API_KEY` gets.
   * Absence is a 404 on `POST /v1/chat/completions`, not a mounted-but-refusing
   * surface: see the module header on the same bargain for the admin and share
   * trees.
   */
  ai?: AiSurfaceOptions | null;
  /**
   * The share graph's storage, or `null`/absent for "this instance does not
   * do sharing" — which is the default and what every deployment without
   * `SYNC_SHARING` gets. Absence is a 404 on both share subtrees, not a
   * mounted-but-refusing surface.
   */
  shares?: SyncShareStore | null;
  /**
   * The study graph's storage, or `null`/absent for "this instance does not
   * host research contributions" — the default, and what every deployment
   * without `SYNC_RESEARCH` gets. Absence is a 404 on both contribution
   * subtrees, not a mounted-but-refusing surface, and it is decided
   * independently of `shares`.
   */
  research?: SyncResearchStore | null;
}

export function createApp(options: CreateAppOptions): Express {
  const app = express();
  const mailer = options.mailer ?? createNoopMailer();
  const now = options.now ?? ((): Date => new Date());
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
    // What this instance calls itself, and what it can do. Descriptive, never
    // a grant: `ai` says an upstream key is configured, not that the caller may
    // use it. Omitted entirely when absent, so a client older than protocol 2
    // parses the response exactly as before. See `InstanceInfo`.
    if (options.instance != null) handshake.instance = options.instance;
    // The operator's notice rides on this same /health body, and only when
    // there is one: an instance with nothing to say sends no field at all, so
    // a client older than M181 parses the response exactly as before. It is
    // PULL — this service holds no addresses and never initiates.
    if (options.notice != null) handshake.notice = options.notice;
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

  // THE RESEARCH TERMINATOR — same placement, same reason, SEPARATE FLAG.
  //
  // `SYNC_RESEARCH` is unset on every deployment that has not deliberately
  // turned research contributions on, and it is decided independently of
  // `SYNC_SHARING`: neither flag implies the other. Both contribution
  // subtrees then answer the ordinary unknown-path 404, to everybody,
  // credentialed or not.
  //
  // Mounted HERE, ahead of the bearer middleware below, for exactly the
  // reason the share terminator is: these paths live inside
  // `SYNC_API_PREFIX`, so a merely-unmounted tree would be reached by
  // `requireAuth` first and answer 401 to an anonymous probe — announcing
  // that a credential exists worth guessing, on a tree whose very existence
  // would tell a prober this deployment holds a cohort.
  const research = options.research ?? null;
  if (research === null) {
    // No SYNC_RESEARCH on this instance: an explicit 404, never a bare absence.
    for (const prefix of RESEARCH_API_PREFIXES) {
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
    // A rotation mints a new recovery code, so this route needs the same two
    // subkeys the auth handlers hold to store it (M192 addendum).
    recoveryCredentials: {
      pepper: options.authContext.pepper,
      escrowKey: options.authContext.escrowKey,
    },
  });

  // The share family, when this instance has one. It is handed the same
  // caller resolver, and deliberately NOT a way to turn a caller into a
  // target — see `share-routes.ts`'s header on the confused deputy that
  // reusing this resolver for target selection would create.
  if (shares !== null) {
    registerShareRoutes(app, { shares, storage: options.storage, resolveEntitledUser });
  }

  // The research family, when this instance has one. It is deliberately NOT
  // handed `storage`: this lane never reads a blob, and giving it the adapter
  // would create the one seam a study-side route could use to reach a
  // contributor's diary — the "share with a smaller UI" ADR-0003 forbids.
  if (research !== null) {
    registerResearchRoutes(app, { research, resolveEntitledUser });
  }

  // THE AI PROXY, OR NOTHING THAT ADMITS TO BEING ONE.
  //
  // `UPSTREAM_API_KEY` is unset on every deployment that has not deliberately
  // pointed this service at a provider. `POST /v1/chat/completions` then
  // answers the ordinary unknown-path 404, to everybody, credentialed or not —
  // the same bargain the admin and share trees make, for the same reason (this
  // service auto-deploys on push).
  //
  // The terminator is mounted whether or not the route is, so the answer for
  // that path is pinned to the 404 and cannot be turned into a 401 by some
  // future middleware between here and the fallthrough below.
  const ai = options.ai ?? null;
  if (ai === null) {
    app.use(CHAT_COMPLETIONS_PATH, handleNotFound);
  } else {
    registerAiRoute(app, {
      upstream: ai.upstream,
      quota: ai.quota,
      accounts: options.authContext.store,
      logger: options.logger,
      now,
      requireAuth,
      perMinute: ai.perMinute,
      maxRequestBytes: ai.maxRequestBytes,
    });
  }

  // The admin API — ALWAYS mounted, and its middleware decides what to admit
  // to. An instance with no `ADMIN_TOKEN` and no admin account is
  // indistinguishable from one where the feature was never written, because
  // `createAdminAuthMiddleware` answers the ordinary unknown-path 404 in that
  // case rather than a 401. See its header and this module's.
  app.use(
    ADMIN_API_PREFIX,
    createAdminAuthMiddleware({
      adminToken: options.admin.token,
      authContext: options.authContext,
      logger: options.logger,
    }),
    createAdminRoutes({
      metadata: options.admin.metadata,
      invites: options.admin.invites,
      accounts: options.authContext.store,
      mailer,
      // The mailer itself cannot answer this: the no-op resolves, so a send
      // that did nothing is indistinguishable from one that worked.
      mailConfigured: options.mailConfigured ?? false,
      links: options.admin.links ?? null,
      // The SAME minter the auth handlers use, so an operator-sent reset and a
      // self-service one produce tokens of the same shape.
      mintResetToken: options.authContext.mintResetToken,
      now,
      logger: options.logger,
    }),
  );

  app.use(handleNotFound);
  app.use(createErrorMiddleware(options.logger));

  return app;
}
