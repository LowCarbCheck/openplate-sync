/**
 * Express glue: mounts the sync blob/key-record HTTP routes documented in
 * `PROTOCOL.md` §5 onto a host-provided app. Every route resolves the caller
 * via `context.resolveEntitledUser` FIRST and responds 403 on `null`, so the
 * handler cores (`push-handler.ts` etc.) never see an unauthorized request.
 * Binary fields (`ciphertext`, `wrappedDek`) travel as base64 strings over
 * JSON.
 *
 * `express.json()` is applied ONLY to these routes (not globally) — the auth
 * router mounts its own, far smaller limit, and a 2 MiB body allowance has no
 * business anywhere near a login endpoint.
 *
 * THE TWO-STAGE 413 (M128 spec 01 review carry-over). `JSON_BODY_LIMIT` sits
 * DELIBERATELY ABOVE `MAX_BLOB_BYTES`: base64 inflates by 4/3, so a body
 * limit set at the raw cap would reject a legitimate maximum-size blob before
 * any handler saw it. The consequence is that body-parser alone cannot
 * enforce the protocol's cap — it only stops bodies that are absurd. The
 * DECODED length is therefore checked explicitly below, and both paths must
 * produce an identical `413` + `{"error": "..."}` on the wire
 * (`server/error-middleware.ts` handles body-parser's half).
 */
import express from 'express';
import type { Express, Request, Response } from 'express';
import type { SyncHostContext } from '../contract-types.js';
import { MAX_BLOB_BYTES, SYNC_API_PREFIX, isSyncKeyRecordKind } from '../protocol.js';
import { asNumber, asObject, asString, type JsonValue } from '../lib/json.js';
import { handlePushBlob } from './push-handler.js';
import { handlePullBlob } from './pull-handler.js';
import { handleDeleteKeyRecord, handleListKeyRecords, handlePutKeyRecord } from './key-records-handler.js';
import { blobCapacityPercent, shouldWarnBlobSize } from './blob-size-telemetry.js';

const SYNC_ROUTE_PREFIX = SYNC_API_PREFIX;
/**
 * Derived from the protocol's blob cap rather than restated, so raising one
 * can't leave the other behind. Base64 inflates by 4/3, plus a small margin
 * for the JSON envelope around it. See the module header for why this being
 * larger than `MAX_BLOB_BYTES` is intentional and what compensates for it.
 */
const JSON_BODY_LIMIT = Math.ceil((MAX_BLOB_BYTES * 4) / 3) + 4096;

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(value: JsonValue | undefined): Uint8Array | null {
  const encoded = asString(value);
  if (encoded === null) return null;
  return new Uint8Array(Buffer.from(encoded, 'base64'));
}

/**
 * Parses the CAS `expectedUpdatedAt` field (security review finding #2):
 * `null` is a valid, required-to-be-explicit assertion ("no record should
 * exist yet"); anything that isn't `null` or a well-formed ISO date string
 * is rejected — an ABSENT key (`undefined`) is deliberately treated as
 * invalid too, so a caller can never accidentally skip the CAS check by
 * simply forgetting the field.
 */
function parseExpectedUpdatedAt(value: JsonValue | undefined): { ok: true; value: Date | null } | { ok: false } {
  if (value === null) return { ok: true, value: null };
  const timestamp = asString(value);
  if (timestamp === null) return { ok: false };
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return { ok: false };
  return { ok: true, value: parsed };
}

async function requireEntitledUser(
  req: Request,
  res: Response,
  context: SyncHostContext,
): Promise<{ userId: number } | null> {
  const user = await context.resolveEntitledUser(req);
  if (user === null) {
    res.status(403).json({ error: 'sync not enabled for this account' });
    return null;
  }
  return user;
}

export function registerSyncRoutes(app: Express, context: SyncHostContext): void {
  const router = express.Router();
  router.use(express.json({ limit: JSON_BODY_LIMIT }));

  router.post(`${SYNC_ROUTE_PREFIX}/blob`, async (req, res, next) => {
    try {
      const user = await requireEntitledUser(req, res, context);
      if (!user) return;

      const body = asObject(req.body) ?? {};
      const baseVersion = asNumber(body.baseVersion);
      const envelopeVersion = asNumber(body.envelopeVersion);
      const ciphertext = fromBase64(body.ciphertext);
      if (baseVersion === null || envelopeVersion === null || ciphertext === null) {
        res.status(400).json({ error: 'invalid request body' });
        return;
      }

      // The protocol's actual cap, checked on the DECODED bytes — see the
      // module header on why body-parser's limit cannot stand in for this.
      if (ciphertext.byteLength > MAX_BLOB_BYTES) {
        res.status(413).json({ error: `blob exceeds the maximum of ${MAX_BLOB_BYTES} bytes` });
        return;
      }

      // Capacity-cliff telemetry (PROTOCOL.md §8): the months between the
      // first warning and the first hard rejection are the whole window in
      // which the chunked-blob work can be planned rather than scrambled.
      if (shouldWarnBlobSize(ciphertext.byteLength)) {
        context.logger?.warn('Blob approaching the size cap', {
          accountId: user.userId,
          sizeBytes: ciphertext.byteLength,
          maxBytes: MAX_BLOB_BYTES,
          percentOfCap: blobCapacityPercent(ciphertext.byteLength),
        });
      }

      const result = await handlePushBlob(
        { accountId: user.userId, baseVersion, envelopeVersion, ciphertext },
        context.storage,
      );

      if (result.status === 'accepted') {
        res.status(200).json({ newVersion: result.newVersion });
      } else if (result.status === 'conflict') {
        res.status(409).json({ currentVersion: result.currentVersion });
      } else {
        res.status(400).json({ error: result.reason });
      }
    } catch (error) {
      next(error);
    }
  });

  router.get(`${SYNC_ROUTE_PREFIX}/blob`, async (req, res, next) => {
    try {
      const user = await requireEntitledUser(req, res, context);
      if (!user) return;

      const result = await handlePullBlob(user.userId, context.storage);
      if (result.status === 'not-found') {
        res.status(404).json({ error: 'no blob for this account yet' });
        return;
      }
      res.status(200).json({
        blobVersion: result.blob.blobVersion,
        envelopeVersion: result.blob.envelopeVersion,
        ciphertext: toBase64(result.blob.ciphertext),
        createdAt: result.blob.createdAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  router.get(`${SYNC_ROUTE_PREFIX}/key-records`, async (req, res, next) => {
    try {
      const user = await requireEntitledUser(req, res, context);
      if (!user) return;

      const records = await handleListKeyRecords(user.userId, context.storage);
      res.status(200).json({
        records: records.map((record) => ({
          kind: record.kind,
          kdfDescriptor: record.kdfDescriptor,
          wrappedDek: toBase64(record.wrappedDek),
          updatedAt: record.updatedAt.toISOString(),
        })),
      });
    } catch (error) {
      next(error);
    }
  });

  router.put(`${SYNC_ROUTE_PREFIX}/key-records/:kind`, async (req, res, next) => {
    try {
      const user = await requireEntitledUser(req, res, context);
      if (!user) return;

      const kind = req.params.kind;
      if (!isSyncKeyRecordKind(kind)) {
        res.status(400).json({ error: 'invalid key record kind' });
        return;
      }
      const body = asObject(req.body) ?? {};
      const wrappedDek = fromBase64(body.wrappedDek);
      const expectedUpdatedAt = parseExpectedUpdatedAt(body.expectedUpdatedAt);
      if (wrappedDek === null || !expectedUpdatedAt.ok) {
        res.status(400).json({ error: 'invalid request body' });
        return;
      }
      const kdfDescriptor = asObject(body.kdfDescriptor);

      const result = await handlePutKeyRecord(
        { accountId: user.userId, kind, kdfDescriptor, wrappedDek, expectedUpdatedAt: expectedUpdatedAt.value },
        context.storage,
      );
      if (result.status === 'invalid') {
        res.status(400).json({ error: result.reason });
        return;
      }
      if (result.status === 'conflict') {
        res
          .status(409)
          .json({ currentUpdatedAt: result.currentUpdatedAt ? result.currentUpdatedAt.toISOString() : null });
        return;
      }
      res.status(200).json({
        kind: result.record.kind,
        kdfDescriptor: result.record.kdfDescriptor,
        wrappedDek: toBase64(result.record.wrappedDek),
        updatedAt: result.record.updatedAt.toISOString(),
      });
    } catch (error) {
      next(error);
    }
  });

  router.delete(`${SYNC_ROUTE_PREFIX}/key-records/:kind`, async (req, res, next) => {
    try {
      const user = await requireEntitledUser(req, res, context);
      if (!user) return;

      const kind = req.params.kind;
      if (!isSyncKeyRecordKind(kind)) {
        res.status(400).json({ error: 'invalid key record kind' });
        return;
      }
      await handleDeleteKeyRecord({ accountId: user.userId, kind }, context.storage);
      res.status(204).end();
    } catch (error) {
      next(error);
    }
  });

  app.use(router);
}
