/**
 * Table definitions — the source of truth for this service's schema.
 *
 * Every change here must ship a generated migration: run `pnpm drizzle:generate`
 * and commit the resulting `drizzle/migrations/<n>_<name>.sql` +
 * `meta/_journal.json` alongside the edit. `pnpm drizzle:push` is a dev-only
 * convenience for a throwaway local database — it never reaches
 * `drizzle/migrations/`, so it never ships to anything that boots via the
 * migrator (which every deployment does; see `src/main.ts`). Never hand-edit
 * `when` timestamps in the journal: the migrator applies only migrations
 * newer than the last applied one, so an out-of-order value causes a later
 * migration to be SILENTLY skipped at boot with no error.
 *
 * `sync_blobs` and `sync_key_records` were relocated here from the openplate
 * app in M128 spec 02, together with the security-reviewed CAS adapter that
 * writes them (`db/storage-adapter.ts`). The migrations are a fresh baseline
 * rather than a port of the app's history: zero production blobs ever
 * existed, so there was nothing to migrate — only DDL to re-home.
 */
import { relations, sql, type InferInsertModel, type InferSelectModel } from 'drizzle-orm';
import {
  check,
  customType,
  index,
  integer,
  jsonb,
  pgTable,
  serial,
  text,
  timestamp,
  uniqueIndex,
} from 'drizzle-orm/pg-core';
import type { SyncKeyRecordKind } from '../protocol.js';
import type { AccountTokenKind } from '../lib/tokens.js';
import type { KdfDescriptor } from '../lib/kdf-descriptor.js';
import type { JsonObject } from '../lib/json.js';

/**
 * Raw binary column (Postgres `bytea`). drizzle-orm's `pg-core` has no
 * built-in helper, so this is the documented `customType` pattern. Used for
 * opaque ciphertext only: the service stores and returns these bytes
 * verbatim and never parses them (PROTOCOL.md §10.5).
 */
const bytea = customType<{ data: Buffer; driverData: Buffer }>({
  dataType() {
    return 'bytea';
  },
});

// =============================================================================
// Accounts
// =============================================================================

/**
 * DELIBERATELY MINIMAL. An account is an identity plus the material needed to
 * authenticate it — nothing else. There is no profile, no display avatar, no
 * settings blob, because everything a user actually owns lives inside the
 * encrypted sync blob that this service cannot read.
 *
 * Future community features do NOT extend this table with a second set of
 * credentials; they authenticate through a separate lane that shares only the
 * `id` space. See `docs/adr/001-community-auth-lane.md` for why the vault
 * KDF/verifier material stays isolated.
 */
export const accounts = pgTable(
  'accounts',
  {
    id: serial('id').primaryKey(),
    email: text('email').notNull(),
    /** Optional, cosmetic, and the ONLY non-authentication field here on purpose (see the table doc). */
    displayName: text('display_name'),
    /**
     * `HMAC-SHA-256(serverPepper, clientAuthHash)`, hex — never the auth-hash
     * itself and never anything that can decrypt a blob. See
     * `lib/verifier.ts` for why this is a fast keyed hash and not a second
     * slow KDF.
     */
    verifier: text('verifier').notNull(),
    /**
     * Argon2id salt + cost parameters, served UNAUTHENTICATED to a new device
     * before login (PROTOCOL.md §5.7). Non-secret by construction — a salt
     * that has to be handed out cannot be a secret, and cost parameters are
     * published in the protocol anyway.
     */
    kdfDescriptor: jsonb('kdf_descriptor').$type<KdfDescriptor>().notNull(),
    /** NULL means unverified. Only enforced at login when `REQUIRE_EMAIL_VERIFICATION` is on. */
    emailVerifiedAt: timestamp('email_verified_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at')
      .defaultNow()
      .$onUpdate(() => new Date())
      .notNull(),
  },
  // Emails are stored already-normalized (`lib/verifier.ts`'s `normalizeEmail`),
  // so a plain unique index is a true case-insensitive uniqueness guarantee.
  (table) => [uniqueIndex('accounts_email_idx').on(table.email)],
);

export type InsertAccount = InferInsertModel<typeof accounts>;
export type SelectAccount = InferSelectModel<typeof accounts>;

// =============================================================================
// Account tokens
// =============================================================================

/**
 * Every opaque token this service issues — session pairs and single-use link
 * tokens alike (`lib/tokens.ts` owns the kinds and their TTLs).
 *
 * Only digests are stored, so this table is not replayable if dumped. Rows
 * are retained after revocation rather than deleted: a presented-but-revoked
 * refresh token is the reuse signal that revokes its whole family, and you
 * cannot detect reuse of a row you deleted.
 */
export const accountTokens = pgTable(
  'account_tokens',
  {
    id: serial('id').primaryKey(),
    accountId: integer('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    kind: text('kind').$type<AccountTokenKind>().notNull(),
    /** SHA-256 hex of the raw token. The raw value exists only in the client's memory or in one email. */
    tokenHash: text('token_hash').notNull(),
    /**
     * Links an access token to the refresh token that minted it, and survives
     * rotation. `logout` revokes one family (one device); reuse detection
     * revokes the family of a replayed refresh token. NULL for link tokens,
     * which have no lineage.
     */
    familyId: text('family_id'),
    expiresAt: timestamp('expires_at').notNull(),
    /** Set once, never cleared. Revocation is permanent — a re-login mints new rows. */
    revokedAt: timestamp('revoked_at'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => [
    // Lookup is always by digest, and a digest collision across accounts would
    // be an authentication bypass — so uniqueness here is a security property,
    // not an optimization.
    uniqueIndex('account_tokens_hash_idx').on(table.tokenHash),
    index('account_tokens_account_kind_idx').on(table.accountId, table.kind),
    index('account_tokens_family_idx').on(table.familyId),
    // Supports the periodic sweep of long-dead rows.
    index('account_tokens_expires_idx').on(table.expiresAt),
  ],
);

export type InsertAccountToken = InferInsertModel<typeof accountTokens>;
export type SelectAccountToken = InferSelectModel<typeof accountTokens>;

// =============================================================================
// Sync blobs (relocated from the openplate app, M128 spec 02)
// =============================================================================

export const syncBlobs = pgTable(
  'sync_blobs',
  {
    id: serial('id').primaryKey(),
    /**
     * `onDelete: 'cascade'` is the self-serve DSAR mechanism: deleting an
     * account removes every blob it ever pushed in the same statement, with
     * no cleanup job to forget to run and no window where orphaned ciphertext
     * survives its owner. This closed the M118 privacy blocker.
     */
    accountId: integer('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    /**
     * Monotonic per-account version — the CAS token (PROTOCOL.md §5.1). A
     * push is accepted only when its `baseVersion` equals the current max;
     * a stale push is a `409`, never a blind overwrite that would silently
     * discard another device's unsynced changes.
     */
    blobVersion: integer('blob_version').notNull(),
    /** The envelope's wire-format version (`ENVELOPE_VERSION`), independent of the payload's own schema version. */
    envelopeVersion: integer('envelope_version').notNull(),
    /** Opaque ciphertext: `iv ‖ AES-256-GCM(...)` as one packed blob. The service never parses it and holds no key for it. */
    ciphertext: bytea('ciphertext').notNull(),
    /** Redundant with `ciphertext`'s length, but avoids reading a 2 MiB blob just to report storage usage. */
    sizeBytes: integer('size_bytes').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
  },
  (table) => [
    // The CAS guarantee itself: two concurrent pushes off the same
    // `baseVersion` can both pass the read, but only one INSERT of the same
    // (account, version) pair can survive. Retention (N=5) is enforced by the
    // adapter's prune step — Postgres has no native "keep last N rows" rule.
    uniqueIndex('sync_blobs_account_version_idx').on(table.accountId, table.blobVersion),
    index('sync_blobs_account_idx').on(table.accountId),
  ],
);

export type InsertSyncBlob = InferInsertModel<typeof syncBlobs>;
export type SelectSyncBlob = InferSelectModel<typeof syncBlobs>;

// =============================================================================
// Sync key records (relocated from the openplate app, M128 spec 02)
// =============================================================================

export const syncKeyRecords = pgTable(
  'sync_key_records',
  {
    id: serial('id').primaryKey(),
    accountId: integer('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    /** Which KEK this record wraps the account's DEK under — `passphrase` or `recovery`. */
    kind: text('kind').$type<SyncKeyRecordKind>().notNull(),
    /** Argon2id salt + params for the `passphrase` kind; NULL for `recovery` (HKDF-only, nothing to record). */
    kdfDescriptor: jsonb('kdf_descriptor').$type<JsonObject>(),
    /** The account's DEK wrapped under this record's KEK, one packed `iv ‖ ciphertext‖tag` blob. Never unwrapped here. */
    wrappedDek: bytea('wrapped_dek').notNull(),
    /**
     * MILLISECOND precision, deliberately — `timestamp(3)`, not the `timestamp(6)`
     * a bare `timestamp()` gives you. Kept identical to `updatedAt` below so the
     * two are comparable; see that column for the whole reason.
     */
    createdAt: timestamp('created_at', { precision: 3 }).defaultNow().notNull(),
    /**
     * Also this row's CAS token: `PUT /v1/sync/key-records/:kind` requires the
     * caller's `expectedUpdatedAt` to match exactly (or be `null`, asserting
     * no row exists yet) before a write is accepted.
     *
     * MILLISECOND precision is therefore LOAD-BEARING, not cosmetic. The token
     * leaves here as an ISO-8601 string, which carries milliseconds; Postgres's
     * `now()` carries MICROSECONDS. While this column was a bare `timestamp`
     * (= `timestamp(6)`) an INSERT that let `defaultNow()` supply the value
     * stored a µs tail the wire could not express, so the token a client read
     * back was a truncation of the stored value and the exact-equality CAS
     * matched zero rows — every rotation 409'd forever (M160 spec 06).
     *
     * Declaring the precision fixes the CLASS rather than the instance: the
     * database now refuses to hold anything the protocol cannot round-trip, so
     * the next writer who reaches for `defaultNow()` here cannot reintroduce
     * the trap. `sync_shares` solves the same problem the other way, by writing
     * JS `Date`s on insert — that works, but only for as long as every future
     * insert remembers to.
     */
    updatedAt: timestamp('updated_at', { precision: 3 })
      .defaultNow()
      .$onUpdate(() => new Date())
      .notNull(),
  },
  (table) => [uniqueIndex('sync_key_records_account_kind_idx').on(table.accountId, table.kind)],
);

export type InsertSyncKeyRecord = InferInsertModel<typeof syncKeyRecords>;
export type SelectSyncKeyRecord = InferSelectModel<typeof syncKeyRecords>;

// =============================================================================
// Sync shares (ADR-0002 — sharing a diary without giving the server a key)
// =============================================================================

/**
 * A THIRD WRAP of an account's DEK, addressed to another account's public key.
 *
 * The server's position is unchanged by this table: it holds one more blob it
 * has no key for. `wrappedDek` here is the ADR's frozen 125-byte
 * `ephPub(65) ‖ iv(12) ‖ AES-256-GCM(KEK_share, DEK, aad=...)` construction,
 * and the AAD binds the wrap to its grantor and its recipient key — so a
 * malicious server splicing one patient's wrap into another patient's row
 * produces a tag failure rather than a misattributed diary.
 *
 * WHY THIS IS NOT A `kind` ON `sync_key_records`. That table's invariant is
 * one row per (account, kind), both kinds owner-held, both rotating together
 * through the atomic credential change of PROTOCOL.md §5.14. A share is
 * multi-valued, is held by a DIFFERENT principal, has a grant/revoke
 * lifecycle rather than create/rotate, and must never ride through
 * change-passphrase or reset — those rotate KEKs, and a share has no KEK to
 * rotate. A nullable discriminator would make the unique index partial and
 * fork every kind-validation branch.
 *
 * THE GRANTEE'S PUBLIC KEY IS NOT STORED HERE, only a fingerprint used for
 * pinning. Storing the key would make this service the clinician key
 * directory ADR-0002 rejects outright — a trust role a zero-knowledge service
 * does not have. The full public key is pinned inside the grantor's own
 * encrypted snapshot.
 *
 * REVOCATION IS A HARD DELETE. There is deliberately no tombstone column: a
 * whole-database restore predates the revoke and so lacks the tombstone too,
 * which means it cannot prevent what it never contains, and re-creating a row
 * needs the grantor's own bearer token AND a fresh wrap only the grantor's
 * client can produce — a re-grant, which is a legitimate act. Against that
 * zero defensive value stands a permanent server-side assertion that a named
 * patient was under a named clinician's care, outliving its own revocation.
 */
export const syncShares = pgTable(
  'sync_shares',
  {
    id: serial('id').primaryKey(),
    /** The grantor — the account whose blob is being shared. Cascades: deleting it kills every grant it made. */
    accountId: integer('account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    /** The grantee — the account the wrap is addressed to. Cascades: deleting it kills every wrap aimed at it. */
    granteeAccountId: integer('grantee_account_id')
      .notNull()
      .references(() => accounts.id, { onDelete: 'cascade' }),
    /** The grantor's DEK wrapped to the grantee's public key. Opaque here; the service holds no key for it. */
    wrappedDek: bytea('wrapped_dek').notNull(),
    /** Pinning metadata only (see the table doc) — never a key, and never served as one. */
    recipientKeyFingerprint: text('recipient_key_fingerprint').notNull(),
    /** Millisecond precision, for the reason recorded on `updatedAt` below. */
    createdAt: timestamp('created_at', { precision: 3 }).defaultNow().notNull(),
    /**
     * Also this row's CAS token, exactly as for `sync_key_records`: a
     * re-wrap after a DEK rotation can race a re-grant, so
     * `PUT /v1/sync/shares/:granteeAccountId` requires the caller's
     * `expectedUpdatedAt` to match (or be `null`, asserting no row yet).
     *
     * MILLISECOND PRECISION, DECLARED, NOT MERELY WRITTEN. A bare `timestamp`
     * is `timestamp(6)`, and the wire carries ISO-8601 at millisecond
     * precision — so a token read back over the wire is a TRUNCATION of what
     * is stored, the exact `eq()` below it never matches, and every rotation
     * 409s forever. That is not hypothetical: it shipped on
     * `sync_key_records` and made "Regenerate recovery code" permanently
     * impossible, with an error blaming another device.
     *
     * `putShare` also writes millisecond `Date`s, which is what kept this
     * table correct before this line existed. That fixes the instance; this
     * line fixes the class, because it stops the next writer who reaches for
     * `defaultNow()` from bringing the trap back.
     */
    updatedAt: timestamp('updated_at', { precision: 3 })
      .defaultNow()
      .$onUpdate(() => new Date())
      .notNull(),
  },
  (table) => [
    // The stable identity of a share is the (grantor, grantee) PAIR — that is
    // what has to survive a DEK rotation, and it is why both sides of the API
    // address a share by the counterpart's account id and never by `id`.
    uniqueIndex('sync_shares_pair_idx').on(table.accountId, table.granteeAccountId),
    // The grantee's "what has been shared with me" read.
    index('sync_shares_grantee_idx').on(table.granteeAccountId),
    // A self-share is nonsense the schema can refuse outright: the wrap would
    // be addressed to a key the account already has a plainer route to.
    check('sync_shares_not_self', sql`${table.accountId} <> ${table.granteeAccountId}`),
  ],
);

export type InsertSyncShare = InferInsertModel<typeof syncShares>;
export type SelectSyncShare = InferSelectModel<typeof syncShares>;

// =============================================================================
// Relations
// =============================================================================

export const accountsRelations = relations(accounts, ({ many }) => ({
  tokens: many(accountTokens),
  blobs: many(syncBlobs),
  keyRecords: many(syncKeyRecords),
  // Both directions of the share graph hang off the same account row; the
  // relation names say which end this account is standing at.
  sharesGranted: many(syncShares, { relationName: 'sharesGranted' }),
  sharesReceived: many(syncShares, { relationName: 'sharesReceived' }),
}));

export const accountTokensRelations = relations(accountTokens, ({ one }) => ({
  account: one(accounts, { fields: [accountTokens.accountId], references: [accounts.id] }),
}));

export const syncBlobsRelations = relations(syncBlobs, ({ one }) => ({
  account: one(accounts, { fields: [syncBlobs.accountId], references: [accounts.id] }),
}));

export const syncKeyRecordsRelations = relations(syncKeyRecords, ({ one }) => ({
  account: one(accounts, { fields: [syncKeyRecords.accountId], references: [accounts.id] }),
}));

export const syncSharesRelations = relations(syncShares, ({ one }) => ({
  grantor: one(accounts, {
    fields: [syncShares.accountId],
    references: [accounts.id],
    relationName: 'sharesGranted',
  }),
  grantee: one(accounts, {
    fields: [syncShares.granteeAccountId],
    references: [accounts.id],
    relationName: 'sharesReceived',
  }),
}));
