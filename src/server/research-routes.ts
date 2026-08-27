/**
 * The research contribution family of ADR-0003 — the contributor's three
 * routes and the study's two — mounted under `SYNC_API_PREFIX`, behind the
 * same bearer gate as everything else there.
 *
 * THE TRAP THIS MODULE EXISTS TO AVOID. `share-routes.ts` is the structural
 * model for everything below, and its `GET /shared/:grantorAccountId/blob`
 * REQUIRES `grantorAccountId` in the response, because PROTOCOL.md §3.2's AAD
 * binds it and a grantee without it cannot decrypt at all. **This lane is the
 * exact inversion.** No study-side response may carry a contributor's account
 * id (ADR-0003 prohibition 2), and §3.5's AAD —
 * `{studyAccountId, pseudonym, contributionVersion, schemaTier,
 * studyKeyFingerprint}` — was designed so the identifier is never needed: four
 * of those ride in the study response and the fifth the researcher computes
 * locally from her own key. Anyone copying the shared-blob response shape into
 * this file imports a re-identification leak. `tests/integration/research.test.ts`
 * asserts the study-side key sets exactly, which is the form that fails when
 * somebody does.
 *
 * WHAT THE STUDY CAN REACH, EXHAUSTIVELY: the sealed bodies of contributions
 * pointed at it, their pseudonyms, versions, tiers and creation times, and the
 * pseudonyms that withdrew. There is no study-side write verb of any kind, no
 * path from here to a contributor's blob — this router is not even given the
 * storage adapter — and no way to ask "who is behind this pseudonym", because
 * the server cannot answer that question either: it never computes and never
 * verifies a pseudonym, it only stores the one the client supplied.
 *
 * FOUR-OH-FOURS ARE IDENTICAL BY CONSTRUCTION, as in the share family. A study
 * account that does not exist and one that simply has no relationship with the
 * caller both go through `sendContributionNotFound`. Naming an account in a
 * URL must not become an existence oracle.
 */
import express from 'express';
import type { Express, Request, Response } from 'express';
import type { SyncResearchHostContext } from '../contract-types.js';
import { SYNC_API_PREFIX } from '../protocol.js';
import { asObject, asPositiveInteger, asString, asTrimmedString, type JsonValue } from '../lib/json.js';
import { asyncHandler } from './async-handler.js';

/**
 * The two subtrees this family occupies. Exported because `create-app.ts`
 * mounts a 404 terminator on both of them — BEFORE the bearer middleware — on
 * any instance where `SYNC_RESEARCH` is unset.
 */
export const CONTRIBUTIONS_API_PREFIX = `${SYNC_API_PREFIX}/contributions`;
export const STUDY_API_PREFIX = `${SYNC_API_PREFIX}/study`;

/** Both subtrees, for the dark-instance terminator. Adding a route without adding its subtree here would leak a 401. */
export const RESEARCH_API_PREFIXES: readonly string[] = [CONTRIBUTIONS_API_PREFIX, STUDY_API_PREFIX];

/**
 * The one payload tier v1 defines (PROTOCOL.md §3.5, ADR-0003).
 *
 * IT IS A LIST IN THE SERVER'S SOURCE, and that is prohibition 1 made
 * mechanical: the schema is fixed by protocol revision, never by study
 * configuration. A study picks a tier by NAME and a date window; it never
 * supplies a field list, and it cannot introduce a tier by sending one. An
 * unknown name is a 400 here rather than an opaque row nobody classified.
 */
export const RESEARCH_SCHEMA_TIERS: readonly string[] = ['daily-intake:v1'];

/**
 * The floor of ADR-0003's envelope: `ephPub(65, uncompressed SEC1) ‖ iv(12) ‖
 * AES-256-GCM(...)`, whose tag alone is 16 bytes. Unlike the share wrap this
 * has no fixed size — the payload is a window of days, not a 32-byte DEK — so
 * only the floor is checkable.
 *
 * Checking the length is not parsing the envelope; the service still holds no
 * key for it. It is worth checking because a structurally impossible body
 * accepted here fails much later, on the researcher's machine, as an
 * unexplainable tag failure.
 */
export const RESEARCH_BODY_MIN_BYTES = 65 + 12 + 16;

/**
 * Cap on one sealed contribution. `daily-intake:v1` is seven small fields per
 * calendar day, so even a decade-long window is tens of kilobytes; this leaves
 * two orders of magnitude of headroom while keeping the lane far below
 * `MAX_BLOB_BYTES`. A contribution that needs more than this is a tier
 * question, not a limit question.
 */
export const MAX_CONTRIBUTION_BYTES = 256 * 1024;

/** Base64 inflates by 4/3, so the JSON limit must sit above the decoded cap or a legal maximum body 413s before a handler sees it. */
const JSON_BODY_LIMIT = 512 * 1024;

/**
 * A bound, not a validation. The pseudonym is
 * `HMAC-SHA-256(root, ...)` truncated to 128 bits and Crockford-base32
 * encoded, computed on the contributor's device from a root the server never
 * holds — so the server cannot verify it and must not pretend to (ADR-0003
 * prohibition 3). The only legitimate check is that an unbounded string cannot
 * be parked in a row.
 */
const MAX_PSEUDONYM_CHARS = 64;

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/**
 * The ONE 404 of this family, mirroring `share-routes.ts`'s: an unknown study
 * account and a study the caller has no relationship with are identical on the
 * wire by construction rather than by matching literals somebody has to keep
 * in step.
 */
function sendContributionNotFound(res: Response): void {
  res.status(404).json({ error: 'no such study' });
}

function sendInvalidBody(res: Response): void {
  res.status(400).json({ error: 'invalid request body' });
}

/** A counterpart account id from the URL. Serial ids are positive integers; anything else is malformed, not a miss. */
function parseAccountId(raw: string | undefined): number | null {
  if (raw === undefined || !/^[1-9][0-9]{0,9}$/.test(raw)) return null;
  return Number(raw);
}

/** The sealed envelope, or `null` when it is absent, not base64, or structurally impossible. */
function parseBody(value: JsonValue | undefined): Uint8Array | null {
  const encoded = asString(value);
  if (encoded === null) return null;
  const bytes = new Uint8Array(Buffer.from(encoded, 'base64'));
  if (bytes.byteLength < RESEARCH_BODY_MIN_BYTES) return null;
  return bytes;
}

/** A bounded, non-empty pseudonym. See {@link MAX_PSEUDONYM_CHARS} for why this is not a format check. */
function parsePseudonym(value: JsonValue | undefined): string | null {
  const pseudonym = asTrimmedString(value);
  if (pseudonym === null || pseudonym.length > MAX_PSEUDONYM_CHARS) return null;
  return pseudonym;
}

/** A tier this protocol revision defines. An unknown name never reaches a row — ADR-0003 prohibition 1. */
function parseSchemaTier(value: JsonValue | undefined): string | null {
  const tier = asString(value);
  if (tier === null || !RESEARCH_SCHEMA_TIERS.includes(tier)) return null;
  return tier;
}

/** The CALLER. Both sides of this family authenticate as themselves; the counterpart is always named in the URL. */
async function requireCaller(
  req: Request,
  res: Response,
  context: SyncResearchHostContext,
): Promise<{ userId: number } | null> {
  const caller = await context.resolveEntitledUser(req);
  if (caller === null) {
    res.status(403).json({ error: 'sync not enabled for this account' });
    return null;
  }
  return caller;
}

export function registerResearchRoutes(app: Express, context: SyncResearchHostContext): void {
  const router = express.Router();
  router.use(express.json({ limit: JSON_BODY_LIMIT }));

  // ---------------------------------------------------------------------------
  // Contributor side
  // ---------------------------------------------------------------------------

  router.put(
    SYNC_API_PREFIX + '/contributions/:studyAccountId',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const studyAccountId = parseAccountId(req.params.studyAccountId);
      const body = asObject(req.body) ?? {};
      const pseudonym = parsePseudonym(body.pseudonym);
      const schemaTier = parseSchemaTier(body.schemaTier);
      const sealed = parseBody(body.body);
      const contributionVersion = asPositiveInteger(body.contributionVersion);
      if (studyAccountId === null || pseudonym === null || schemaTier === null || sealed === null) {
        sendInvalidBody(res);
        return;
      }
      if (contributionVersion === null) {
        sendInvalidBody(res);
        return;
      }
      // The database CHECK refuses this too; answering it here keeps the
      // failure a request error rather than a 500 from a constraint.
      if (studyAccountId === caller.userId) {
        sendInvalidBody(res);
        return;
      }
      if (sealed.byteLength > MAX_CONTRIBUTION_BYTES) {
        res.status(413).json({ error: 'contribution too large' });
        return;
      }

      const result = await context.research.putContribution({
        contributorAccountId: caller.userId,
        studyAccountId,
        pseudonym,
        schemaTier,
        body: sealed,
        contributionVersion,
      });

      if (!result.ok && 'reason' in result) {
        // A contribution needs a real study account — the foreign key cannot
        // store one otherwise — and this is the same 404 the read paths give
        // rather than a second, chattier shape that would confirm existence.
        sendContributionNotFound(res);
        return;
      }
      if (!result.ok) {
        // The CAS did not hold: the submitted version was not strictly greater
        // than the stored one, and nothing was written.
        res.status(409).json({ currentVersion: result.currentVersion });
        return;
      }
      // The sealed body is NOT echoed: the contributor's own client holds the
      // source it was reduced from and has no use for its own ciphertext.
      res.status(200).json({
        studyAccountId: result.contribution.studyAccountId,
        pseudonym: result.contribution.pseudonym,
        schemaTier: result.contribution.schemaTier,
        contributionVersion: result.contribution.contributionVersion,
        createdAt: result.contribution.createdAt.toISOString(),
        updatedAt: result.contribution.updatedAt.toISOString(),
      });
    }),
  );

  router.get(
    SYNC_API_PREFIX + '/contributions',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const enrolments = await context.research.listContributionsByContributor(caller.userId);
      res.status(200).json({
        contributions: enrolments.map((contribution) => ({
          studyAccountId: contribution.studyAccountId,
          pseudonym: contribution.pseudonym,
          schemaTier: contribution.schemaTier,
          contributionVersion: contribution.contributionVersion,
          createdAt: contribution.createdAt.toISOString(),
          updatedAt: contribution.updatedAt.toISOString(),
        })),
      });
    }),
  );

  router.delete(
    SYNC_API_PREFIX + '/contributions/:studyAccountId',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const studyAccountId = parseAccountId(req.params.studyAccountId);
      if (studyAccountId === null) {
        sendInvalidBody(res);
        return;
      }
      // WITHDRAWAL. One transaction in the store: hard-delete the row, insert
      // the pseudonym-keyed tombstone. On this side it is genuine erasure — a
      // contribution the study has not yet pulled reaches nobody — and what
      // the study already pulled cannot be repossessed. No wording anywhere
      // may claim otherwise (ADR-0003).
      await context.research.withdrawContribution({
        contributorAccountId: caller.userId,
        studyAccountId,
      });
      res.status(204).end();
    }),
  );

  // ---------------------------------------------------------------------------
  // Study side — read-only, and carrying no contributor account id, ever
  // ---------------------------------------------------------------------------

  router.get(
    SYNC_API_PREFIX + '/study/contributions',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      const cohort = await context.research.listContributionsByStudy(caller.userId);
      // `studyAccountId` here is the CALLER'S OWN id, echoed once at the top
      // level so the researcher can rebuild §3.5's AAD without a second call.
      // It is not a contributor identifier and cannot become one — it is the
      // same value for every row in the response, and it is the value the
      // caller authenticated as.
      //
      // The per-row shape is §5.18's, exactly: pseudonym, version, tier, body,
      // createdAt. Adding an account id to it is the leak this whole lane is
      // shaped to prevent.
      res.status(200).json({
        studyAccountId: caller.userId,
        contributions: cohort.map((contribution) => ({
          pseudonym: contribution.pseudonym,
          contributionVersion: contribution.contributionVersion,
          schemaTier: contribution.schemaTier,
          body: toBase64(contribution.body),
          createdAt: contribution.createdAt.toISOString(),
        })),
      });
    }),
  );

  router.get(
    SYNC_API_PREFIX + '/study/withdrawals',
    asyncHandler(async (req, res) => {
      const caller = await requireCaller(req, res, context);
      if (!caller) return;

      // The purge instructions. Pseudonym and time — the tombstone table has
      // no contributor account id to leak even if this projection wanted one.
      // The study client must honour these before presenting or exporting
      // anything (ADR-0003 prohibition 8); that is enforced in the client, and
      // it is an ethics obligation this service states and cannot enforce.
      const withdrawals = await context.research.listWithdrawalsByStudy(caller.userId);
      res.status(200).json({
        withdrawals: withdrawals.map((withdrawal) => ({
          pseudonym: withdrawal.pseudonym,
          withdrawnAt: withdrawal.withdrawnAt.toISOString(),
        })),
      });
    }),
  );

  app.use(router);
}
