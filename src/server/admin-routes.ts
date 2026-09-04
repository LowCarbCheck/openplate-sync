/**
 * The operator's API: account metadata, aggregate storage, and erasure.
 *
 * Specified by `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`,
 * which is the document to read before adding anything here. The three rules
 * that shape this file:
 *
 * ── 404 WHEN THERE IS NO ADMIN CREDENTIAL, NOT 401 ──────────────────────────
 * That decision is not made here — it belongs to `server/admin-auth.ts`, which
 * answers the ordinary unknown-path 404 for the whole `/v1/admin` tree when no
 * `ADMIN_TOKEN` is configured and the caller is not an admin ACCOUNT. A 401
 * would confirm that an admin surface exists on this host and is merely
 * locked, which is an invitation to come back with a wordlist. This service
 * auto-deploys on push, so an unconfigured deployment must be
 * indistinguishable from one where the feature was never written.
 *
 * M192 moved that judgement from the mount (`create-app.ts` used to leave the
 * router off entirely) into the middleware, because the tree is now mounted
 * ALWAYS: an admin account's own access token authenticates it, and whether
 * one exists is not something a mount-time branch can know.
 *
 * ── NOTHING SECRET IS EVER IN A RESPONSE, BY PROJECTION ─────────────────────
 * No ciphertext, no verifier, no KDF descriptor, no wrapped DEK, no token and
 * no token digest. `toAccountView` is the only thing that builds an account
 * body, and it names every field it emits — the way `toMemberView` does in the
 * gateway. The store beneath it (`db/admin-store.ts`) never SELECTs the
 * forbidden columns in the first place, so this is a second wall rather than
 * the only one. `tests/unit/admin-no-forbidden-fields.test.ts` walks the full
 * serialized body of every endpoint against a seeded account and fails if any
 * of it appears.
 *
 * A blob is reported as a byte count and a timestamp because that is what an
 * operator can act on: a storage bill, a capacity plan, an answer to "did my
 * data reach the server". The bytes themselves are a data subject's, and the
 * only path that yields them is the one that goes through their passphrase.
 *
 * ── DELETION REUSES THE STORE, NOT THE HANDLER ──────────────────────────────
 * `AccountStore.deleteAccount` is called here, and it is the SAME method
 * `handleDeleteAccount` calls for a self-service deletion — so DSAR erasure
 * and self-erasure cannot drift apart and be found to differ during an audit.
 *
 * The self-service handler itself cannot be reused, and the reason is the
 * interesting part: it requires the caller's `authHash` and checks it with
 * `verifierMatches` first. An admin cannot supply that — not for want of a
 * permission, but because the admin genuinely does not know the passphrase,
 * which is the property this whole service is built on. Adding a bypass flag
 * to that handler was considered and rejected in the ADR: it would put the
 * bypass inside the function every self-service deletion runs through.
 * Authorisation is what differs between the two paths; the erasure itself is
 * one line, called from both.
 *
 * ── NO ENDPOINT HERE MUTATES AUTHENTICATION ─────────────────────────────────
 * There is still no admin password reset: the passphrase wraps the data key on
 * the client, so a server-side credential change would produce an account that
 * logs in and decrypts nothing. What M192 adds is a mailed reset the ACCOUNT
 * HOLDER runs (`POST /v1/auth/reset/request`), which hands them the escrowed
 * recovery code so they can run the ordinary ceremony themselves. The admin's
 * part of it is `POST /accounts/:id/reset-mail` — spec 03 — and it sends the
 * letter rather than changing anything.
 */
import express from 'express';
import type { Request, Response, Router } from 'express';
import { asyncHandler } from './async-handler.js';
import type { AccountStore } from '../accounts/account-store.js';
import type { AdminAccountSummary, AdminMetadataStore, AdminStats } from '../admin/admin-store.js';
import { inviteStatus, type InviteStatus, type InviteStore, type InviteSummary } from '../admin/invite-store.js';
import { isAccountRole, type AccountRole, type AccountView, type SyncKeyRecordKind } from '../protocol.js';
import type { Logger } from '../logger.js';
import type { Mailer } from '../mail/mailer.js';
import { parseDisplayName, parseEmail } from '../accounts/auth-input.js';
import { computeExpiry, RESET_TOKEN_TTL_MS, type GeneratedToken } from '../lib/tokens.js';
import { utcDayKey } from '../lib/utc-day.js';
import { asBoolean, asNumber, asObject, type JsonValue } from '../lib/json.js';
import { getAdminPrincipal } from './admin-auth.js';

/** Mount prefix for the operator endpoints. The user-facing families live under `/v1/auth` and `/v1/sync`. */
export const ADMIN_API_PREFIX = '/v1/admin';

/** Page size when the caller does not ask for one. */
export const DEFAULT_ADMIN_PAGE_LIMIT = 50;

/**
 * A ceiling, not a policy: it stops a mistyped `limit=100000` turning one
 * operator's curiosity into a full-table read with a per-row fan-out.
 */
export const MAX_ADMIN_PAGE_LIMIT = 200;

/**
 * The wire shape of one account. Every field is named here; nothing is spread
 * in from a row.
 *
 * It EXTENDS the protocol's `AccountView` rather than redefining it, so the
 * contract's "`accounts: AccountView[]`" is satisfied by construction and a
 * field added to one is a compile error until it is added here too. The two
 * extra fields are ADR-0001's operator facts — see `admin/admin-store.ts`.
 */
interface AdminAccountView extends AccountView {
  blob: { sizeBytes: number; updatedAt: string } | null;
  keyRecordKinds: SyncKeyRecordKind[];
}

interface AdminStatsView {
  accounts: number;
  accountsWithBlob: number;
  blobVersions: number;
  keyRecords: number;
  blobBytes: number;
  pendingInvites: number;
  admins: number;
  aiRequestsToday: number;
}

/** The ONLY function that turns an account into a response body. See the module header. */
function toAccountView(summary: AdminAccountSummary): AdminAccountView {
  return {
    id: summary.id,
    email: summary.email,
    displayName: summary.displayName,
    role: summary.role,
    dailyAiLimit: summary.dailyAiLimit,
    aiUsedToday: summary.aiUsedToday,
    suspendedAt: summary.suspendedAt?.toISOString() ?? null,
    createdAt: summary.createdAt.toISOString(),
    blob:
      summary.blob === null
        ? null
        : { sizeBytes: summary.blob.sizeBytes, updatedAt: summary.blob.updatedAt.toISOString() },
    keyRecordKinds: summary.keyRecordKinds,
  };
}

function toStatsView(stats: AdminStats): AdminStatsView {
  return {
    accounts: stats.accounts,
    accountsWithBlob: stats.accountsWithBlob,
    blobVersions: stats.blobVersions,
    keyRecords: stats.keyRecords,
    blobBytes: stats.blobBytes,
    pendingInvites: stats.pendingInvites,
    admins: stats.admins,
    aiRequestsToday: stats.aiRequestsToday,
  };
}

/**
 * Reads one query parameter as a string.
 *
 * Express's `req.query` is a `ParsedQs` whose values are strings, arrays or
 * nested objects depending on what the caller sent, which is exactly the
 * "unproven shape" `lib/json.ts` exists to keep out of the code. Re-parsing
 * the URL gives a `URLSearchParams`, whose `get` is `string | null` by
 * contract — a decoded value, not a representation to inspect. A repeated
 * parameter yields its first occurrence, which is the same answer as picking
 * one out of an array and needs no branch.
 */
function queryValue(req: Request, name: string): string | null {
  return new URL(req.originalUrl, 'http://placeholder.invalid').searchParams.get(name);
}

type PagingParameter = { ok: true; value: number } | { ok: false };

/** A non-negative integer in range, or a rejection. An out-of-range value is a `400`, never a silent clamp. */
function parseBoundedInteger(raw: string | null, fallback: number, max: number): PagingParameter {
  if (raw === null || raw === '') return { ok: true, value: fallback };
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > max) return { ok: false };
  return { ok: true, value: parsed };
}

/** A path `:id` is an account's serial primary key: a positive integer and nothing else. */
function parseAccountId(raw: string): number | null {
  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : null;
}

function sendNotFound(res: Response): void {
  // The same sentence for "no such account" everywhere, and never the id or
  // the address that was asked about.
  res.status(404).json({ error: 'no such account' });
}

/**
 * Parses the optional `expiresInDays` field into a lifetime in milliseconds.
 *
 * An out-of-range value is REFUSED rather than clamped: clamping would hand
 * back a capability with a lifetime the operator did not ask for and would
 * have no reason to re-read.
 */
function parseInviteTtl(value: JsonValue | undefined): { ok: true; value: number } | { ok: false } {
  if (value === undefined || value === null) return { ok: true, value: DEFAULT_INVITE_TTL_MS };
  const days = asNumber(value);
  if (days === null || !Number.isInteger(days) || days <= 0 || days > MAX_INVITE_TTL_DAYS) return { ok: false };
  return { ok: true, value: days * 24 * 60 * 60 * 1000 };
}

/**
 * Default invite lifetime: one week. Long enough to survive a holiday, short
 * enough that a letter forgotten in an inbox is not a live capability next
 * month. It came down from fourteen days in M192, because an invite now names
 * a person and lives in their mailbox rather than in the operator's notes.
 */
export const DEFAULT_INVITE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * A ceiling on `expiresInDays`, so a typo cannot mint a capability that
 * outlives the operator's memory of it. Thirty days rather than M166's year,
 * for the same reason the default shortened.
 */
export const MAX_INVITE_TTL_DAYS = 30;

/** Default daily AI allowance for an invite that does not name one: none. */
export const DEFAULT_INVITE_DAILY_AI_LIMIT = 0;

/** A ceiling on `dailyAiLimit`, so a mistyped allowance cannot become an unbounded bill. */
export const MAX_DAILY_AI_LIMIT = 10_000;

/**
 * The wire shape of one invite. Every field is named here, and `tokenHash` is
 * not among them — nor is it fetched (`db/invite-store.ts`).
 */
interface AdminInviteView {
  id: number;
  email: string;
  displayName: string | null;
  role: AccountRole;
  dailyAiLimit: number;
  expiresAt: string;
  /** Derived from the three lifecycle columns in ONE place (`admin/invite-store.ts`). */
  status: InviteStatus;
  createdAt: string;
  redeemedAccountId: number | null;
}

function toInviteView(invite: InviteSummary, now: Date): AdminInviteView {
  return {
    id: invite.id,
    email: invite.email,
    displayName: invite.displayName,
    role: invite.role,
    dailyAiLimit: invite.dailyAiLimit,
    expiresAt: invite.expiresAt.toISOString(),
    status: inviteStatus(invite, now),
    createdAt: invite.createdAt.toISOString(),
    redeemedAccountId: invite.redeemedAccountId,
  };
}

/**
 * The link an invited person clicks, or `null` when this instance cannot build
 * one.
 *
 * A FRAGMENT, NEVER A QUERY STRING. Everything after the `#` stays in the
 * browser: it is not sent to the server, does not reach an access log, and does
 * not land in a `Referer` header when the page loads a third-party asset. The
 * token is a capability that creates an account, so where it travels matters
 * as much as how long it lives.
 *
 * `null` when the operator configured neither a public URL for this service nor
 * a base URL for the client — a self-hosted instance may legitimately have
 * neither, and inventing one would produce a link that goes nowhere. The raw
 * token is returned in its own field then, so the capability always reaches
 * somebody.
 */
function buildJoinLink(input: { links: AdminLinkBases | null; token: string }): string | null {
  if (input.links === null) return null;
  const server = encodeURIComponent(input.links.serverPublicUrl);
  return `${input.links.clientBaseUrl.replace(/\/+$/, '')}/join#server=${server}&invite=${input.token}`;
}

/**
 * The link a password-reset letter carries, and the one
 * `POST /accounts/:id/reset-mail` hands an operator when no letter went.
 *
 * A fragment, for the reason {@link buildJoinLink} gives: the token is a
 * capability, and a fragment reaches no server's access log.
 */
function buildResetLink(input: { links: AdminLinkBases | null; token: string }): string | null {
  if (input.links === null) return null;
  const server = encodeURIComponent(input.links.serverPublicUrl);
  return `${input.links.clientBaseUrl.replace(/\/+$/, '')}/reset#server=${server}&token=${input.token}`;
}

/** The two absolute URLs a join link is built from. Both or neither — see `config.ts`. */
export interface AdminLinkBases {
  clientBaseUrl: string;
  serverPublicUrl: string;
}

/** The mint response. `token` is present ONLY when `link` is `null` — see the route. */
interface MintInviteResponse {
  invite: AdminInviteView;
  emailed: boolean;
  link: string | null;
  token?: string;
}

/**
 * The four fields an operator may change on an account, each optional and each
 * meaning "leave it alone" when absent.
 *
 * `email` IS DELIBERATELY NOT HERE. It is the account's identity and what every
 * mail is addressed to; moving it would silently redirect a person's password
 * reset to somebody else's mailbox. An address change is a new invitation.
 */
interface AccountPatch {
  role?: AccountRole;
  dailyAiLimit?: number;
  suspended?: boolean;
  displayName?: string | null;
}

type ParseAccountPatchResult = { ok: true; value: AccountPatch } | { ok: false; reason: string };

/** Decodes a PATCH body. Absent means untouched; present and malformed is a `400` that names the field. */
function parseAccountPatch(body: JsonValue): ParseAccountPatchResult {
  const fields = asObject(body) ?? {};
  const patch: AccountPatch = {};

  if (fields.role !== undefined) {
    if (!isAccountRole(fields.role)) return { ok: false, reason: 'role must be "admin" or "member"' };
    patch.role = fields.role;
  }
  if (fields.dailyAiLimit !== undefined) {
    const limit = asNumber(fields.dailyAiLimit);
    if (limit === null || !Number.isInteger(limit) || limit < 0 || limit > MAX_DAILY_AI_LIMIT) {
      return { ok: false, reason: `dailyAiLimit must be an integer between 0 and ${MAX_DAILY_AI_LIMIT}` };
    }
    patch.dailyAiLimit = limit;
  }
  if (fields.suspended !== undefined) {
    const suspended = asBoolean(fields.suspended);
    if (suspended === null) return { ok: false, reason: 'suspended must be true or false' };
    patch.suspended = suspended;
  }
  if (fields.displayName !== undefined) {
    const displayName = parseDisplayName(fields.displayName);
    if (!displayName.ok) return { ok: false, reason: displayName.reason };
    patch.displayName = displayName.value;
  }

  return { ok: true, value: patch };
}

/**
 * The self-change guard.
 *
 * An admin ACCOUNT may not suspend, demote or delete itself: an organization
 * with one administrator who demotes their own account has locked everybody out
 * of `/v1/admin`, and the remedy is a shell on the container. Every other change
 * to their own row is allowed — a display name is not a lockout.
 *
 * THE STATIC TOKEN IS EXEMPT BY CONSTRUCTION rather than by an exception: it
 * belongs to whoever runs the container, it is not an account, and it has no
 * self to change. It is also the credential that exists for exactly the
 * situation this guard prevents.
 */
function isSelfLockout(input: { req: Request; targetAccountId: number; lockingOut: boolean }): boolean {
  if (!input.lockingOut) return false;
  const principal = getAdminPrincipal(input.req);
  return principal?.kind === 'account' && principal.accountId === input.targetAccountId;
}

export interface AdminRoutesOptions {
  /** Metadata reads. Deliberately not the account store — see `admin/admin-store.ts`. */
  metadata: AdminMetadataStore;
  /** Invite minting, reissue and revocation — see `admin/invite-store.ts`. */
  invites: InviteStore;
  /** The SAME store the self-service delete path uses. `deleteAccount` and the reset-mail write. */
  accounts: AccountStore;
  /** The two letters. A no-op on an instance with no mail, which is what makes `link` load-bearing. */
  mailer: Mailer;
  /**
   * Whether mail is CONFIGURED, which the mailer itself cannot tell a caller:
   * `createNoopMailer` resolves, so a send that did nothing looks exactly like
   * a send that worked. `emailed` in every response below is this AND a
   * successful send, never one of the two.
   */
  mailConfigured: boolean;
  /** Where a join link points, or `null` when this instance cannot build one. */
  links: AdminLinkBases | null;
  /** Mints the `sr_` token `POST /accounts/:id/reset-mail` writes. Injected so a test can name it. */
  mintResetToken(): GeneratedToken;
  /** Injected, like every clock in this repo, so a test can pin "today" and an invite's status. */
  now(): Date;
  logger: Logger;
}

/**
 * Builds the admin router. It does NOT include authentication — `create-app.ts`
 * mounts `createAdminAuthMiddleware` in front of it, in the same branch that
 * decides whether to mount anything at all.
 */
export function createAdminRoutes(options: AdminRoutesOptions): Router {
  const { metadata, accounts, invites, mailer, links, logger } = options;
  const router = express.Router();

  /**
   * Sends one letter and reports whether it went, without ever failing the
   * request that triggered it.
   *
   * THE ROW IS ALREADY WRITTEN by the time this is called, and the link is in
   * the response either way, so a send failure is a degradation and not an
   * outage: the operator pastes the link instead. Turning it into a 500 would
   * throw away a capability that was successfully minted.
   *
   * The log line carries the row id and NOTHING else. Not the address, not the
   * subject, not the link, which is a credential.
   */
  async function trySend(input: { send: () => Promise<void>; what: string; id: number }): Promise<boolean> {
    if (!options.mailConfigured) return false;
    try {
      await input.send();
      return true;
    } catch (cause) {
      logger.warn('Mail send failed', {
        what: input.what,
        id: input.id,
        error: cause instanceof Error ? cause.message : 'unknown error',
      });
      return false;
    }
  }

  router.get(
    '/accounts',
    asyncHandler(async (req, res) => {
      const limit = parseBoundedInteger(queryValue(req, 'limit'), DEFAULT_ADMIN_PAGE_LIMIT, MAX_ADMIN_PAGE_LIMIT);
      const offset = parseBoundedInteger(queryValue(req, 'offset'), 0, Number.MAX_SAFE_INTEGER);
      if (!limit.ok || !offset.ok) {
        res.status(400).json({ error: `limit must be 0–${MAX_ADMIN_PAGE_LIMIT} and offset a non-negative integer` });
        return;
      }

      const page = await metadata.listAccounts({
        limit: limit.value,
        offset: offset.value,
        day: utcDayKey(options.now()),
      });
      res.status(200).json({
        accounts: page.accounts.map(toAccountView),
        total: page.total,
        limit: limit.value,
        offset: offset.value,
      });
    }),
  );

  router.get(
    '/accounts/:id',
    asyncHandler(async (req, res) => {
      const accountId = parseAccountId(req.params.id ?? '');
      if (accountId === null) {
        sendNotFound(res);
        return;
      }

      const summary = await metadata.getAccount({ accountId, day: utcDayKey(options.now()) });
      if (summary === null) {
        sendNotFound(res);
        return;
      }
      res.status(200).json({ account: toAccountView(summary) });
    }),
  );

  router.patch(
    '/accounts/:id',
    express.json({ limit: 4 * 1024 }),
    asyncHandler(async (req, res) => {
      const accountId = parseAccountId(req.params.id ?? '');
      if (accountId === null) {
        sendNotFound(res);
        return;
      }

      // SAFETY: `express.json()` above has already parsed this body, so it is
      // JSON-shaped by construction; `asObject` re-establishes that at the type
      // level and yields `null` for anything that is not an object.
      const body = asObject(req.body as JsonValue) ?? {};
      const patch = parseAccountPatch(body);
      if (!patch.ok) {
        res.status(400).json({ error: patch.reason });
        return;
      }
      if (Object.keys(patch.value).length === 0) {
        // An empty PATCH is a caller that believes it changed something. Same
        // rule the auth-side `PATCH /v1/auth/account` applies to an absent key:
        // silence must never read as consent.
        res.status(400).json({ error: 'a patch must name at least one of role, dailyAiLimit, suspended, displayName' });
        return;
      }

      const { displayName, role, dailyAiLimit, suspended } = patch.value;
      // Demoting or suspending oneself is the lockout; a rename is not.
      if (isSelfLockout({ req, targetAccountId: accountId, lockingOut: suspended === true || role === 'member' })) {
        res.status(400).json({ error: 'self-change' });
        return;
      }

      const now = options.now();
      // Standing first, so a request that both suspends and renames leaves the
      // account suspended even if a later write were to fail.
      if (suspended === true) {
        const changed = await accounts.suspendAccount({ accountId, suspendedAt: now });
        if (changed === null) {
          sendNotFound(res);
          return;
        }
      }
      if (suspended === false) {
        const changed = await accounts.reactivateAccount(accountId);
        if (changed === null) {
          sendNotFound(res);
          return;
        }
      }
      if (role !== undefined || dailyAiLimit !== undefined || displayName !== undefined) {
        const changed = await accounts.updateStanding({ accountId, role, dailyAiLimit, displayName });
        if (changed === null) {
          sendNotFound(res);
          return;
        }
      }

      const summary = await metadata.getAccount({ accountId, day: utcDayKey(now) });
      if (summary === null) {
        sendNotFound(res);
        return;
      }
      // The account id, never the values: a display name is personal data and a
      // role change is already legible from the row.
      logger.info('Account changed by admin', { accountId });
      res.status(200).json({ account: toAccountView(summary) });
    }),
  );

  router.delete(
    '/accounts/:id',
    asyncHandler(async (req, res) => {
      const accountId = parseAccountId(req.params.id ?? '');
      if (accountId === null) {
        sendNotFound(res);
        return;
      }

      // Deleting oneself is the most complete lockout there is, and unlike a
      // suspension it cannot be undone.
      if (isSelfLockout({ req, targetAccountId: accountId, lockingOut: true })) {
        res.status(400).json({ error: 'self-change' });
        return;
      }

      // Read first, so a deletion of an id that never existed is a 404 rather
      // than a 204 that an operator would read as "erased".
      const summary = await metadata.getAccount({ accountId, day: utcDayKey(options.now()) });
      if (summary === null) {
        sendNotFound(res);
        return;
      }

      // THE SHARED ERASURE PATH. See the module header.
      await accounts.deleteAccount(accountId);
      // The account id is the correlation handle; the address is not logged,
      // here or anywhere (`logger.ts`).
      logger.info('Account deleted by admin with all sync data', { accountId });
      res.status(204).end();
    }),
  );

  router.post(
    '/accounts/:id/reset-mail',
    asyncHandler(async (req, res) => {
      const accountId = parseAccountId(req.params.id ?? '');
      if (accountId === null) {
        sendNotFound(res);
        return;
      }

      const account = await accounts.findAccountById(accountId);
      if (account === null) {
        sendNotFound(res);
        return;
      }

      // THE SAME WRITE `POST /v1/auth/reset/request` PERFORMS, through the
      // same store method, so the two paths cannot drift about the TTL or
      // about superseding an older live token. What differs is only who asked:
      // there, the person; here, an operator on their behalf.
      //
      // It is NOT throttled and does not need to be: reaching this route
      // already requires the admin credential.
      const now = options.now();
      const token = options.mintResetToken();
      const expiresAt = computeExpiry(now, RESET_TOKEN_TTL_MS);
      await accounts.createPasswordReset({ accountId, tokenHash: token.hash, expiresAt, now });

      const emailed = await trySend({
        what: 'reset',
        id: accountId,
        send: () =>
          mailer.sendReset({ email: account.email, resetToken: token.raw, expiresAt: expiresAt.toISOString() }),
      });

      // THE LINK ONLY WHEN NO LETTER WENT. On an instance with mail the
      // operator has no business holding a capability that opens somebody
      // else's recovery code; on one without, handing it over is the only way
      // the person gets back in.
      const link = emailed ? null : buildResetLink({ links, token: token.raw });
      logger.info('Password reset mailed by admin', { accountId, emailed });
      res.status(202).json({ emailed, link });
    }),
  );

  router.get(
    '/stats',
    asyncHandler(async (_req, res) => {
      res.status(200).json({ stats: toStatsView(await metadata.stats({ now: options.now() })) });
    }),
  );

  // ---------------------------------------------------------------------------
  // Invites (M166)
  // ---------------------------------------------------------------------------

  router.post(
    '/invites',
    express.json({ limit: 4 * 1024 }),
    asyncHandler(async (req, res) => {
      // SAFETY: `express.json()` above has already parsed this body, so it is
      // JSON-shaped by construction; `asObject` re-establishes that at the type
      // level and yields `null` for anything that is not an object.
      const body = asObject(req.body as JsonValue) ?? {};

      // THE SAME PARSER THE SIGNUP PATH USES. An address canonicalised one way
      // at mint and another way at lookup is an invite for an account nobody
      // can find, so there is exactly one `parseEmail` in this repo.
      const email = parseEmail(body.email);
      if (!email.ok) {
        res.status(400).json({ error: email.reason });
        return;
      }
      const displayName = parseDisplayName(body.displayName);
      if (!displayName.ok) {
        res.status(400).json({ error: displayName.reason });
        return;
      }

      const role = body.role ?? 'member';
      if (!isAccountRole(role)) {
        res.status(400).json({ error: 'role must be "admin" or "member"' });
        return;
      }

      const dailyAiLimit = body.dailyAiLimit ?? DEFAULT_INVITE_DAILY_AI_LIMIT;
      const limit = asNumber(dailyAiLimit);
      if (limit === null || !Number.isInteger(limit) || limit < 0 || limit > MAX_DAILY_AI_LIMIT) {
        res.status(400).json({ error: `dailyAiLimit must be an integer between 0 and ${MAX_DAILY_AI_LIMIT}` });
        return;
      }

      const ttl = parseInviteTtl(body.expiresInDays);
      if (!ttl.ok) {
        res.status(400).json({ error: `expiresInDays must be an integer between 1 and ${MAX_INVITE_TTL_DAYS}` });
        return;
      }

      const now = options.now();
      const minted = await invites.mint({
        email: email.value,
        displayName: displayName.value,
        role,
        dailyAiLimit: limit,
        expiresAt: new Date(now.getTime() + ttl.value),
        now,
      });
      if (!minted.ok) {
        // The one place this service confirms that an address holds an account,
        // and it is behind the admin credential rather than in front of a
        // stranger. Refusing is right: an invite for an existing account would
        // redeem into a `409` the invited person could do nothing about.
        res.status(409).json({ error: 'an account already exists for this email' });
        return;
      }

      const link = buildJoinLink({ links, token: minted.minted.token });
      const emailed = await trySend({
        what: 'invite',
        id: minted.minted.invite.id,
        send: () =>
          mailer.sendInvite({
            email: email.value,
            displayName: displayName.value,
            inviteToken: minted.minted.token,
            expiresAt: minted.minted.invite.expiresAt.toISOString(),
          }),
      });

      // THE ONE RESPONSE IN THIS SERVICE THAT CARRIES A FRESH SECRET. It is an
      // operator-born capability, born here and stored only as a digest — see
      // ADR-0001. The token is never logged, here or in `logger.ts`.
      logger.info('Signup invite minted', { inviteId: minted.minted.invite.id });

      // THE RAW TOKEN ONLY WHEN THERE IS NO LINK TO CARRY IT. An instance with
      // a link has already put the capability in a form the operator can paste;
      // returning it twice would put the same secret in one more place. Built
      // in two statements rather than as a conditional spread, so the omission
      // is a line a reader sees rather than a `{}` they have to decode.
      const mintResponse: MintInviteResponse = {
        invite: toInviteView(minted.minted.invite, now),
        emailed,
        link,
      };
      if (link === null) mintResponse.token = minted.minted.token;
      res.status(201).json(mintResponse);
    }),
  );

  router.get(
    '/invites',
    asyncHandler(async (req, res) => {
      const limit = parseBoundedInteger(queryValue(req, 'limit'), DEFAULT_ADMIN_PAGE_LIMIT, MAX_ADMIN_PAGE_LIMIT);
      const offset = parseBoundedInteger(queryValue(req, 'offset'), 0, Number.MAX_SAFE_INTEGER);
      if (!limit.ok || !offset.ok) {
        res.status(400).json({ error: `limit must be 0–${MAX_ADMIN_PAGE_LIMIT} and offset a non-negative integer` });
        return;
      }

      const now = options.now();
      const page = await invites.list({ limit: limit.value, offset: offset.value });
      res.status(200).json({
        invites: page.invites.map((invite) => toInviteView(invite, now)),
        total: page.total,
        limit: limit.value,
        offset: offset.value,
      });
    }),
  );

  router.post(
    '/invites/:id/resend',
    asyncHandler(async (req, res) => {
      const inviteId = parseAccountId(req.params.id ?? '');
      if (inviteId === null) {
        res.status(404).json({ error: 'no such invite' });
        return;
      }

      const now = options.now();
      // A NEW token on the SAME row, which kills the old link: an operator
      // resending is saying the first letter did not arrive, not "invite this
      // person twice". The expiry restarts from now, because a link that
      // arrives on the day the original would have died is not a resend.
      const reissued = await invites.reissue({
        inviteId,
        expiresAt: new Date(now.getTime() + DEFAULT_INVITE_TTL_MS),
      });
      if (reissued === null) {
        // Never existed, already redeemed, or already revoked. One answer for
        // all three: a redeemed invite is an audit record with no capability
        // left in it, and there is nothing to resend either way.
        res.status(404).json({ error: 'no such unredeemed invite' });
        return;
      }

      const link = buildJoinLink({ links, token: reissued.token });
      const emailed = await trySend({
        what: 'invite',
        id: reissued.invite.id,
        send: () =>
          mailer.sendInvite({
            email: reissued.invite.email,
            displayName: reissued.invite.displayName,
            inviteToken: reissued.token,
            expiresAt: reissued.invite.expiresAt.toISOString(),
          }),
      });

      logger.info('Signup invite resent', { inviteId: reissued.invite.id });
      const resendResponse: MintInviteResponse = {
        invite: toInviteView(reissued.invite, now),
        emailed,
        link,
      };
      // The raw token ONLY when there is no link to carry it, exactly as the
      // mint route decides it.
      if (link === null) resendResponse.token = reissued.token;
      res.status(202).json(resendResponse);
    }),
  );

  router.delete(
    '/invites/:id',
    asyncHandler(async (req, res) => {
      const inviteId = parseAccountId(req.params.id ?? '');
      if (inviteId === null) {
        res.status(404).json({ error: 'no such invite' });
        return;
      }

      // `false` covers "never existed", "already redeemed" and "already
      // revoked". A spent invite is kept as the audit record of where an
      // account came from, and there is no capability left in it to withdraw.
      const revoked = await invites.revoke({ inviteId, revokedAt: options.now() });
      if (!revoked) {
        res.status(404).json({ error: 'no such unredeemed invite' });
        return;
      }
      logger.info('Signup invite revoked', { inviteId });
      res.status(204).end();
    }),
  );

  return router;
}
