/**
 * The operator's API: account metadata, aggregate storage, and erasure.
 *
 * Specified by `docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`,
 * which is the document to read before adding anything here. The three rules
 * that shape this file:
 *
 * ── 404 WHEN THERE IS NO ADMIN TOKEN, NOT 401 ───────────────────────────────
 * That decision is not made here — `create-app.ts` mounts this router only
 * when a token is configured, and answers the ordinary unknown-path 404 for
 * the whole `/v1/admin` tree when it is not. A 401 would confirm that an admin
 * surface exists on this host and is merely locked, which is an invitation to
 * come back with a wordlist. This service auto-deploys on push, so an
 * unconfigured deployment must be indistinguishable from one where the feature
 * was never written.
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
 * NO ENDPOINT HERE MUTATES AUTHENTICATION, AND NONE SENDS MAIL. There is no
 * admin password reset and there cannot be a meaningful one — the passphrase
 * wraps the data key on the client, so a server-side credential change would
 * produce an account that logs in and decrypts nothing. See the ADR.
 */
import express from 'express';
import type { Request, Response, Router } from 'express';
import { asyncHandler } from './async-handler.js';
import type { AccountStore } from '../accounts/account-store.js';
import type { AdminAccountSummary, AdminMetadataStore, AdminStats } from '../admin/admin-store.js';
import type { InviteStore, InviteSummary } from '../admin/invite-store.js';
import type { SyncKeyRecordKind } from '../protocol.js';
import type { Logger } from '../logger.js';
import { asNumber, asObject, asString, type JsonValue } from '../lib/json.js';

/** Mount prefix for the operator endpoints. The user-facing families live under `/v1/auth` and `/v1/sync`. */
export const ADMIN_API_PREFIX = '/v1/admin';

/** Page size when the caller does not ask for one. */
export const DEFAULT_ADMIN_PAGE_LIMIT = 50;

/**
 * A ceiling, not a policy: it stops a mistyped `limit=100000` turning one
 * operator's curiosity into a full-table read with a per-row fan-out.
 */
export const MAX_ADMIN_PAGE_LIMIT = 200;

/** The wire shape of one account. Every field is named here; nothing is spread in from a row. */
interface AdminAccountView {
  id: number;
  handle: string;
  createdAt: string;
  blob: { sizeBytes: number; updatedAt: string } | null;
  keyRecordKinds: SyncKeyRecordKind[];
}

interface AdminStatsView {
  accounts: number;
  accountsWithBlob: number;
  blobVersions: number;
  keyRecords: number;
  blobBytes: number;
}

/** The ONLY function that turns an account into a response body. See the module header. */
function toAccountView(summary: AdminAccountSummary): AdminAccountView {
  return {
    id: summary.id,
    handle: summary.handle,
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

/** Default invite lifetime. Long enough to survive a slow reply, short enough that a forgotten link expires. */
export const DEFAULT_INVITE_TTL_MS = 14 * 24 * 60 * 60 * 1000;

/** A ceiling on `expiresInDays`, so a typo cannot mint a capability that outlives the operator's memory of it. */
export const MAX_INVITE_TTL_DAYS = 365;

/**
 * The wire shape of one invite. Every field is named here, and `tokenHash` is
 * not among them — nor is it fetched (`db/invite-store.ts`).
 */
interface AdminInviteView {
  id: number;
  note: string | null;
  createdAt: string;
  expiresAt: string;
  redeemedAt: string | null;
  redeemedAccountId: number | null;
}

function toInviteView(invite: InviteSummary): AdminInviteView {
  return {
    id: invite.id,
    note: invite.note,
    createdAt: invite.createdAt.toISOString(),
    expiresAt: invite.expiresAt.toISOString(),
    redeemedAt: invite.redeemedAt?.toISOString() ?? null,
    redeemedAccountId: invite.redeemedAccountId,
  };
}

export interface AdminRoutesOptions {
  /** Metadata reads. Deliberately not the account store — see `admin/admin-store.ts`. */
  metadata: AdminMetadataStore;
  /** Invite minting and revocation — see `admin/invite-store.ts`. */
  invites: InviteStore;
  /** The SAME store the self-service delete path uses. Only `deleteAccount` is called. */
  accounts: AccountStore;
  logger: Logger;
}

/**
 * Builds the admin router. It does NOT include authentication — `create-app.ts`
 * mounts `createAdminAuthMiddleware` in front of it, in the same branch that
 * decides whether to mount anything at all.
 */
export function createAdminRoutes(options: AdminRoutesOptions): Router {
  const { metadata, accounts, invites, logger } = options;
  const router = express.Router();

  router.get(
    '/accounts',
    asyncHandler(async (req, res) => {
      const limit = parseBoundedInteger(queryValue(req, 'limit'), DEFAULT_ADMIN_PAGE_LIMIT, MAX_ADMIN_PAGE_LIMIT);
      const offset = parseBoundedInteger(queryValue(req, 'offset'), 0, Number.MAX_SAFE_INTEGER);
      if (!limit.ok || !offset.ok) {
        res.status(400).json({ error: `limit must be 0–${MAX_ADMIN_PAGE_LIMIT} and offset a non-negative integer` });
        return;
      }

      const page = await metadata.listAccounts({ limit: limit.value, offset: offset.value });
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

      const summary = await metadata.getAccount(accountId);
      if (summary === null) {
        sendNotFound(res);
        return;
      }
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

      // Read first, so a deletion of an id that never existed is a 404 rather
      // than a 204 that an operator would read as "erased".
      const summary = await metadata.getAccount(accountId);
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

  router.get(
    '/stats',
    asyncHandler(async (_req, res) => {
      res.status(200).json({ stats: toStatsView(await metadata.stats()) });
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
      const note = asString(body.note);

      const ttl = parseInviteTtl(body.expiresInDays);
      if (!ttl.ok) {
        res.status(400).json({ error: `expiresInDays must be an integer between 1 and ${MAX_INVITE_TTL_DAYS}` });
        return;
      }
      const ttlMs = ttl.value;

      const minted = await invites.mint({ note, expiresAt: new Date(Date.now() + ttlMs) });
      // THE ONE RESPONSE IN THIS SERVICE THAT CARRIES A FRESH SECRET. It is an
      // operator-born capability, born here and stored only as a digest — see
      // ADR-0001. The token is never logged, here or in `logger.ts`.
      logger.info('Signup invite minted', { inviteId: minted.invite.id });
      res.status(201).json({ invite: toInviteView(minted.invite), token: minted.token });
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

      const page = await invites.list({ limit: limit.value, offset: offset.value });
      res.status(200).json({
        invites: page.invites.map(toInviteView),
        total: page.total,
        limit: limit.value,
        offset: offset.value,
      });
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

      // `false` covers both "never existed" and "already redeemed". A spent
      // invite is kept as the audit record of where an account came from, and
      // there is no capability left in it to withdraw.
      const revoked = await invites.revoke(inviteId);
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
