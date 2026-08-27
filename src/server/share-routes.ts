/**
 * The share endpoint family of ADR-0002 — the grantor's three routes and the
 * grantee's three — mounted under `SYNC_API_PREFIX`, behind the same bearer
 * gate as everything else there.
 *
 * They live in their own module, and their own router, for the same reason
 * `sync_shares` is its own table: nothing about a share belongs in the
 * owner-only blob/key-record path, and a reader auditing that path should not
 * have to hold this one in their head to be sure of it.
 *
 * THE SEAM THAT IS NOT USED, AND WHY. `bearer-auth.ts` advertises
 * `resolveEntitledUser`'s `null` branch as "the seam a future entitlement
 * rule would use", and it is the WRONG seam for this. Its type answers *who
 * is calling*, and every route in `register-routes.ts` then passes that one
 * id as the *target* (`handlePullBlob(user.userId, ...)`). Resolving a
 * grantee to the grantor's id would not grant read access — it would make the
 * grantee BECOME the grantor, for `POST /blob` and `PUT /key-records/:kind`
 * too. That is a confused deputy, not a read grant. So below, the caller and
 * the target are always two separate values: the caller comes from the
 * session, the target is named explicitly in the URL, and authorisation is a
 * live `(accountId = target, granteeAccountId = caller)` row lookup performed
 * on every single request.
 *
 * WHAT THE GRANTEE CAN REACH, EXHAUSTIVELY: their own share row (with its
 * wrap), the grantor's current blob ciphertext, and `grantorAccountId`. Never
 * the grantor's key records, KDF descriptor, verifier, email or display name,
 * and never blob history — a grantee who could pull the grantor's `recovery`
 * wrapped DEK would be one brute-forced recovery code away from rotation
 * authority over the account they were merely allowed to read. There is no
 * grantee write verb against the grantor at all.
 *
 * FOUR-OH-FOURS ARE IDENTICAL BY CONSTRUCTION. An unknown share, a share
 * belonging to somebody else, and a grantor who has never pushed a blob all
 * go through `sendShareNotFound`. Naming a counterpart in a URL is not an
 * enumeration oracle when absence answers the same thing presence-without-
 * permission does; absence of a share must not confirm that an account
 * exists.
 */
import express from 'express';
import type { Express, Request, Response } from 'express';
import type { SyncShareHostContext } from '../contract-types.js';
import { SYNC_API_PREFIX } from '../protocol.js';
import { asObject, asString, type JsonValue } from '../lib/json.js';
import { asyncHandler } from './async-handler.js';

/**
 * The two subtrees the share family occupies. Exported because
 * `create-app.ts` mounts a 404 terminator on both of them — BEFORE the bearer
 * middleware — on any instance where `SYNC_SHARING` is unset.
 */
export const SHARES_API_PREFIX = `${SYNC_API_PREFIX}/shares`;
export const SHARED_API_PREFIX = `${SYNC_API_PREFIX}/shared`;

/** Both subtrees, for the dark-instance terminator. Adding a route without adding its subtree here would leak a 401. */
export const SHARE_API_PREFIXES: readonly string[] = [SHARES_API_PREFIX, SHARED_API_PREFIX];

/**
 * The frozen size of ADR-0002's wrap: `ephPub(65, uncompressed SEC1) ‖ iv(12)
 * ‖ AES-256-GCM(KEK_share, DEK, aad)` where the DEK is 32 bytes and the GCM
 * tag is 16.
 *
 * Checking the LENGTH is not parsing the wrap — the service still never looks
 * inside it and still holds no key for it. It is worth checking because a
 * malformed wrap that is accepted here fails much later, on the clinician's
 * device, as an unexplainable tag failure. A future construction (a different
 * curve, say) is a new frozen label and a new protocol version, not a
 * loosened check here.
 */
export const SHARE_WRAPPED_DEK_BYTES = 125;

/** Enough for any reasonable fingerprint encoding; a bound exists so an unbounded string cannot be parked in a row. */
const MAX_FINGERPRINT_CHARS = 128;

/** The share bodies are ~200 bytes. Nothing on this family has any business carrying a blob-sized payload. */
const JSON_BODY_LIMIT = 8 * 1024;

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * The ONE 404 of this family. Every caller below routes through it, so a
 * missing share, a foreign share and an un-pushed grantor are identical on
 * the wire by construction rather than by three matching literals somebody
 * has to keep in step.
 */
function sendShareNotFound(res: Response): void {
  res.status(404).json({ error: 'no such share' });
}

function sendInvalidBody(res: Response): void {
  res.status(400).json({ error: 'invalid request body' });
}

/**
 * A counterpart account id from the URL. Serial ids are positive integers;
 * anything else is a malformed request rather than a lookup that will miss,
 * and is answered as one.
 */
function parseAccountId(raw: string | undefined): number | null {
  if (raw === undefined || !/^[1-9][0-9]{0,9}$/.test(raw)) return null;
  return Number(raw);
}

/** The wrap, or `null` when it is absent, not base64, or not the frozen length. */
function parseWrappedDek(value: JsonValue | undefined): Uint8Array | null {
  const encoded = asString(value);
  if (encoded === null) return null;
  const bytes = new Uint8Array(Buffer.from(encoded, 'base64'));
  return bytes.byteLength === SHARE_WRAPPED_DEK_BYTES ? bytes : null;
}

function parseFingerprint(value: JsonValue | undefined): string | null {
  const fingerprint = asString(value);
  if (fingerprint === null) return null;
  const trimmed = fingerprint.trim();
  if (trimmed.length === 0 || trimmed.length > MAX_FINGERPRINT_CHARS) return null;
  return trimmed;
}

/**
 * The CAS field, transplanted from `register-routes.ts` verbatim in meaning
 * (PROTOCOL.md §5.4): `null` asserts "no share to this grantee exists yet";
 * any other value asserts "the row I last read had exactly this
 * `updatedAt`". An ABSENT key is invalid, deliberately — a caller must not be
 * able to skip the concurrency check by forgetting a field.
 */
function parseExpectedUpdatedAt(value: JsonValue | undefined): { ok: true; value: Date | null } | { ok: false } {
  if (value === null) return { ok: true, value: null };
  const timestamp = asString(value);
  if (timestamp === null) return { ok: false };
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return { ok: false };
  return { ok: true, value: parsed };
}

/** The CALLER. Never the target — see the module header. */
async function requireCaller(
  req: Request,
  res: Response,
  context: SyncShareHostContext,
): Promise<{ userId: number } | null> {
  const caller = await context.resolveEntitledUser(req);
  if (caller === null) {
    res.status(403).json({ error: 'sync not enabled for this account' });
    return null;
  }
  return caller;
}

export function registerShareRoutes(app: Express, context: SyncShareHostContext): void {
  const router = express.Router();
  router.use(express.json({ limit: JSON_BODY_LIMIT }));

  // ---------------------------------------------------------------------------
  // Grantor side
  // ---------------------------------------------------------------------------

  router.put(
    SYNC_API_PREFIX + '/shares/:granteeAccountId',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const granteeAccountId = parseAccountId(req.params.granteeAccountId);
      const body = asObject(req.body) ?? {};
      const wrappedDek = parseWrappedDek(body.wrappedDek);
      const recipientKeyFingerprint = parseFingerprint(body.recipientKeyFingerprint);
      const expectedUpdatedAt = parseExpectedUpdatedAt(body.expectedUpdatedAt);
      if (granteeAccountId === null || wrappedDek === null || recipientKeyFingerprint === null) {
        sendInvalidBody(res);
        return;
      }
      if (!expectedUpdatedAt.ok) {
        sendInvalidBody(res);
        return;
      }
      // The database CHECK refuses this too; answering it here keeps the
      // failure a request error rather than a 500 from a constraint.
      if (granteeAccountId === caller.userId) {
        sendInvalidBody(res);
        return;
      }

      const result = await context.shares.putShare({
        accountId: caller.userId,
        granteeAccountId,
        wrappedDek,
        recipientKeyFingerprint,
        expectedUpdatedAt: expectedUpdatedAt.value,
      });

      if (!result.ok && 'reason' in result) {
        // A grant needs a real target — the foreign key cannot store one
        // otherwise — so this answer is unavoidable, and it is the same 404
        // the read paths give rather than a second, chattier shape.
        sendShareNotFound(res);
        return;
      }
      if (!result.ok) {
        res
          .status(409)
          .json({ currentUpdatedAt: result.currentUpdatedAt ? result.currentUpdatedAt.toISOString() : null });
        return;
      }
      // The wrap is NOT echoed: it is addressed to the grantee's key and the
      // grantor has no use for it.
      res.status(200).json({
        granteeAccountId: result.share.granteeAccountId,
        recipientKeyFingerprint: result.share.recipientKeyFingerprint,
        createdAt: result.share.createdAt.toISOString(),
        updatedAt: result.share.updatedAt.toISOString(),
      });
    }),
  );

  router.get(
    SYNC_API_PREFIX + '/shares',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const grants = await context.shares.listSharesByGrantor(caller.userId);
      res.status(200).json({
        shares: grants.map((grant) => ({
          granteeAccountId: grant.granteeAccountId,
          recipientKeyFingerprint: grant.recipientKeyFingerprint,
          createdAt: grant.createdAt.toISOString(),
          updatedAt: grant.updatedAt.toISOString(),
        })),
      });
    }),
  );

  router.delete(
    SYNC_API_PREFIX + '/shares/:granteeAccountId',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const granteeAccountId = parseAccountId(req.params.granteeAccountId);
      if (granteeAccountId === null) {
        sendInvalidBody(res);
        return;
      }
      // Tier 1 revocation (ADR-0002): a hard delete, effective on the next
      // request because the row is read on every one and never cached. It
      // cannot un-know — the wording that accompanies it must never claim it
      // does.
      await context.shares.deleteShare({ accountId: caller.userId, granteeAccountId });
      res.status(204).end();
    }),
  );

  // ---------------------------------------------------------------------------
  // Grantee side — read-only against the grantor, always
  // ---------------------------------------------------------------------------

  router.get(
    SYNC_API_PREFIX + '/shared',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const received = await context.shares.listSharesByGrantee(caller.userId);
      res.status(200).json({
        shares: received.map((share) => ({
          grantorAccountId: share.accountId,
          // The wrap DOES travel here: it is addressed to this caller's key,
          // and nobody else can open it.
          wrappedDek: toBase64(share.wrappedDek),
          recipientKeyFingerprint: share.recipientKeyFingerprint,
          createdAt: share.createdAt.toISOString(),
          updatedAt: share.updatedAt.toISOString(),
        })),
      });
    }),
  );

  router.get(
    SYNC_API_PREFIX + '/shared/:grantorAccountId/blob',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;
      const grantorAccountId = parseAccountId(req.params.grantorAccountId);
      if (grantorAccountId === null) {
        sendShareNotFound(res);
        return;
      }
      // The authorisation. Read every time, never cached, so a revoke that
      // committed a millisecond ago is already effective here. The caller and
      // the target are two separate values, and this row is the only thing
      // that joins them.
      const authorisation = { accountId: grantorAccountId, granteeAccountId: caller.userId };
      const share = await context.shares.getShare(authorisation);
      const blob = share === null ? null : await context.storage.getBlob(grantorAccountId);
      if (share === null || blob === null) {
        // Deliberately one branch: "you have no share here" and "the grantor
        // has never pushed" must not be tellable apart.
        sendShareNotFound(res);
        return;
      }
      // `grantorAccountId` IS PART OF THE CONTRACT, not a convenience echo:
      // the blob's own AAD binds it (PROTOCOL.md §3.2), so a grantee who does
      // not know it cannot decrypt what this response carries at all.
      res.status(200).json({
        grantorAccountId,
        blobVersion: blob.blobVersion,
        envelopeVersion: blob.envelopeVersion,
        ciphertext: toBase64(blob.ciphertext),
        createdAt: blob.createdAt.toISOString(),
      });
    }),
  );

  router.delete(
    SYNC_API_PREFIX + '/shared/:grantorAccountId',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const grantorAccountId = parseAccountId(req.params.grantorAccountId);
      if (grantorAccountId === null) {
        sendInvalidBody(res);
        return;
      }
      // Without this verb, anyone who knows an account id could park a wrap
      // in a clinician's list forever. Deleting from this end is the same
      // hard delete the grantor's end performs.
      await context.shares.deleteShare({ accountId: grantorAccountId, granteeAccountId: caller.userId });
      res.status(204).end();
    }),
  );

  app.use(router);
}
