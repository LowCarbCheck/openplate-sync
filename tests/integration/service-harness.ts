/**
 * Boots the REAL Express app (`createApp`) against a real Postgres on an
 * ephemeral loopback port, and hands back a small typed HTTP client.
 *
 * TWO dependencies are substituted, for reasons that are about determinism
 * rather than avoidance: the clock, so token expiry is assertable without
 * sleeping, and the mailer, so a suite can assert that a letter was ASKED for
 * without a relay. The store, the storage adapter, the router, the bearer
 * middleware, the CORS layer and the error handler are all production code,
 * and the schema is the committed migrations.
 *
 * `signupThroughInvite` is the only way to create an account here, and that is
 * the point rather than a convenience: since M192 there is no other door on
 * the service either, so a helper that reached around the invite would be
 * testing a path that does not exist.
 */
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/server/create-app.js';
import { createDrizzleAccountStore } from '../../src/db/account-store.js';
import { createDrizzleInviteStore as createInviteStore } from '../../src/db/invite-store.js';
import { createDrizzleStorageAdapter } from '../../src/db/storage-adapter.js';
import { createDrizzleAdminStore } from '../../src/db/admin-store.js';

import { createDrizzleShareStore } from '../../src/db/share-store.js';
import { createDrizzleRotationStore } from '../../src/db/rotation-store.js';
import { createDrizzleResearchStore } from '../../src/db/research-store.js';
import { createDrizzleAiQuotaStore } from '../../src/ai/quota-store.js';
import { createSilentLogger } from '../../src/logger.js';
import { createThrottleStore, type ThrottleConfig } from '../../src/lib/throttle.js';
import { generateFamilyId, generatePasswordResetToken, generateToken } from '../../src/lib/tokens.js';
import { deriveServerSecrets } from '../../src/lib/server-secrets.js';
import type { AuthContext, SessionResponse } from '../../src/accounts/auth-handlers.js';
import type { Mailer, SendInviteInput, SendResetInput } from '../../src/mail/mailer.js';
import type { SyncKeyRecordKind } from '../../src/protocol.js';
import type { Database } from '../../src/db/client.js';
import { SHARE_WRAPPED_DEK_BYTES } from '../../src/server/share-routes.js';
import { RESEARCH_BODY_MIN_BYTES } from '../../src/server/research-routes.js';

export interface HttpResponse<T> {
  status: number;
  body: T;
  headers: Headers;
}

export interface HttpRequestInput {
  method: string;
  path: string;
  body?: unknown;
  accessToken?: string;
  /** An admin bearer credential, for the `/v1/admin` routes. Mutually exclusive with `accessToken` in practice. */
  adminToken?: string;
}

/** Every letter the service asked for, in order. Substituted so a suite can assert a send without a relay. */
export interface RecordingMailer extends Mailer {
  invites: SendInviteInput[];
  resets: SendResetInput[];
}

function createRecordingMailer(): RecordingMailer {
  const invites: SendInviteInput[] = [];
  const resets: SendResetInput[] = [];
  return {
    invites,
    resets,
    async sendInvite(input: SendInviteInput): Promise<void> {
      invites.push(input);
    },
    async sendReset(input: SendResetInput): Promise<void> {
      resets.push(input);
    },
  };
}

/** What a test asks for when it needs an account. Everything but the address has a default. */
export interface SignupThroughInviteInput {
  email: string;
  displayName?: string | null;
  role?: 'admin' | 'member';
  dailyAiLimit?: number;
  authHash?: string;
  recoveryAuthHash?: string;
  recoveryCode?: string;
}

export interface ServiceHarness {
  baseUrl: string;
  authContext: AuthContext;
  mailer: RecordingMailer;
  advance(ms: number): void;
  request<T>(input: HttpRequestInput): Promise<HttpResponse<T>>;
  /**
   * Mints an invite through the REAL invite store and redeems it through the
   * REAL `POST /v1/auth/signup`.
   *
   * It goes through the store rather than through `POST /v1/admin/invites` so
   * a suite that is not about the admin API does not have to configure one;
   * everything after the mint is production code on the production path.
   */
  signupThroughInvite(input: SignupThroughInviteInput): Promise<SessionResponse>;
  /**
   * The CAS token a key record currently carries, read the way a real client
   * reads it: out of the LIST response, over the wire.
   *
   * EVERY KEY-RECORD PUT IS A ROTATION NOW. Since M192 signup writes both
   * records itself, so `expectedUpdatedAt: null` — the first-time assertion —
   * is a genuine `409` on any account this harness created. A fixture that
   * wants to replace a wrap with a named one has to present the current token,
   * exactly as the client does.
   */
  currentKeyRecordToken(input: { accessToken: string; kind: SyncKeyRecordKind }): Promise<string | null>;
  close(): Promise<void>;
}

/**
 * Every request in a test file arrives from 127.0.0.1, so the production
 * throttle would lock the suite out of `/v1/auth/signup` after five accounts.
 * Suites that are not ABOUT abuse control therefore run with a permissive
 * config; `abuse-controls.test.ts` opts back in to the real defaults and
 * asserts the lockout deliberately.
 */
/** The production default (`AI_MAX_REQUEST_BYTES`), so a fixture exercises the real bound. */
export const DEFAULT_AI_MAX_REQUEST_BYTES = 8_000_000;

export const PERMISSIVE_THROTTLE: ThrottleConfig = {
  freeAttempts: 10_000,
  baseLockoutMs: 1,
  maxLockoutMs: 1,
  attemptResetMs: 1,
};

export interface StartServiceOptions {
  db: Database;
  throttleConfig?: ThrottleConfig;
  /**
   * Absent (the default) boots the service the way every deployment boots
   * today: no static break-glass credential, and `/v1/admin/*` answering the
   * ordinary unknown-path 404 to everybody who is not an admin account.
   * `admin-api.test.ts` opts in.
   */
  adminToken?: string | null;
  /** Where a join link points. Absent means this instance builds none. */
  links?: { clientBaseUrl: string; serverPublicUrl: string } | null;
  /**
   * Absent (the default) boots the service the way every deployment boots
   * today: `SYNC_SHARING` unset, and both share subtrees answering the
   * ordinary unknown-path 404. `sharing.test.ts` opts in.
   */
  sharing?: boolean;
  /**
   * Absent (the default) boots the service the way every deployment boots
   * today: `SYNC_RESEARCH` unset, and both contribution subtrees answering
   * the ordinary unknown-path 404. `research.test.ts` opts in. Independent of
   * `sharing` — neither implies the other.
   */
  research?: boolean;
  /**
   * Absent (the default) boots the service with NO provider key configured,
   * which is every deployment that has not bought one: `POST
   * /v1/chat/completions` answers the ordinary unknown-path 404 to everybody,
   * signed in or not. `ai-proxy.test.ts` opts in and points it at a fake
   * upstream on an ephemeral port.
   */
  ai?: {
    baseUrl: string;
    apiKey: string;
    timeoutMs?: number;
    perMinute?: number;
    advertisedModel?: string;
    maxRequestBytes?: number;
  } | null;
}

export async function startService(options: StartServiceOptions): Promise<ServiceHarness> {
  let clock = Date.now();
  const secrets = deriveServerSecrets('integration-test-root-secret-long-enough');
  const mailer = createRecordingMailer();
  const inviteStore = createInviteStore(options.db);

  const authContext: AuthContext = {
    store: createDrizzleAccountStore(options.db),
    pepper: secrets.verifierPepper,
    enumerationSecret: secrets.enumerationSecret,
    escrowKey: secrets.escrowKey,
    mailer,
    now: () => new Date(clock),
    mintToken: generateToken,
    mintResetToken: generatePasswordResetToken,
    mintFamilyId: generateFamilyId,
    logger: createSilentLogger(),
  };

  const aiSurface =
    options.ai == null
      ? null
      : {
          upstream: {
            baseUrl: options.ai.baseUrl,
            apiKey: options.ai.apiKey,
            timeoutMs: options.ai.timeoutMs ?? 5_000,
          },
          quota: createDrizzleAiQuotaStore(options.db),
          // High by default: a suite that is not ABOUT the minute limiter must
          // not trip it, exactly as `PERMISSIVE_THROTTLE` does for the signup
          // lockout.
          perMinute: options.ai.perMinute ?? 10_000,
          maxRequestBytes: options.ai.maxRequestBytes ?? DEFAULT_AI_MAX_REQUEST_BYTES,
        };

  const app = createApp({
    authContext,
    storage: createDrizzleStorageAdapter(options.db),
    rotation: createDrizzleRotationStore(options.db),
    throttle: createThrottleStore(options.throttleConfig ?? PERMISSIVE_THROTTLE),
    logger: createSilentLogger(),
    trustProxy: false,
    mailer,
    now: () => new Date(clock),
    admin: {
      token: options.adminToken ?? null,
      metadata: createDrizzleAdminStore(options.db),
      invites: inviteStore,
      links: options.links ?? null,
    },
    shares: options.sharing === true ? createDrizzleShareStore(options.db) : null,
    research: options.research === true ? createDrizzleResearchStore(options.db) : null,
    ai: aiSurface,
    // `main.ts` builds this the same way, and the harness mirrors it rather
    // than omitting it: `/health` is the ONLY way a client learns whether this
    // instance can scan a plate at all, so a fixture that left it off would
    // let a `create-app` that forgot to report `ai` pass every suite.
    instance: {
      name: 'integration',
      language: 'en',
      mail: false,
      ai: aiSurface === null ? null : { model: options.ai?.advertisedModel ?? null },
    },
  });

  const server: Server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (address === null) throw new Error('expected a listening server');
  // SAFETY: `listen(0)` binds a TCP port, and Node only returns the string
  // form of an address for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  const harness: ServiceHarness = {
    baseUrl,
    authContext,
    mailer,
    advance(ms: number) {
      clock += ms;
    },
    async signupThroughInvite(input: SignupThroughInviteInput): Promise<SessionResponse> {
      const now = new Date(clock);
      const minted = await inviteStore.mint({
        email: input.email,
        displayName: input.displayName ?? null,
        role: input.role ?? 'member',
        dailyAiLimit: input.dailyAiLimit ?? 0,
        expiresAt: new Date(clock + 7 * 24 * 60 * 60 * 1000),
        now,
      });
      if (!minted.ok) throw new Error(`could not mint an invite for ${input.email}: ${minted.reason}`);

      const response = await harness.request<SessionResponse>({
        method: 'POST',
        path: '/v1/auth/signup',
        body: {
          inviteToken: minted.minted.token,
          authHash: input.authHash ?? sampleAuthHash(),
          kdfDescriptor: sampleKdfDescriptor(),
          displayName: input.displayName ?? null,
          recoveryAuthHash: input.recoveryAuthHash ?? sampleAuthHash(31),
          recoveryCode: input.recoveryCode ?? sampleRecoveryCode(),
          keyRecords: [
            { kind: 'passphrase', kdfDescriptor: sampleKdfDescriptor(), wrappedDek: sampleWrappedDek() },
            { kind: 'recovery', kdfDescriptor: null, wrappedDek: sampleWrappedDek(41) },
          ],
        },
      });
      if (response.status !== 201) {
        throw new Error(`signup for ${input.email} answered ${response.status}: ${JSON.stringify(response.body)}`);
      }
      return response.body;
    },
    async currentKeyRecordToken(input: { accessToken: string; kind: SyncKeyRecordKind }): Promise<string | null> {
      const listed = await harness.request<{ records: { kind: string; updatedAt: string }[] }>({
        method: 'GET',
        path: '/v1/sync/key-records',
        accessToken: input.accessToken,
      });
      if (listed.status !== 200) throw new Error(`could not list key records: ${listed.status}`);
      // `null` is the honest answer for a kind that does not exist, and it is
      // also the correct `expectedUpdatedAt` for creating one.
      return listed.body.records.find((record) => record.kind === input.kind)?.updatedAt ?? null;
    },

    async request<T>(input: HttpRequestInput): Promise<HttpResponse<T>> {
      const headers: Record<string, string> = {};
      if (input.body !== undefined) headers['content-type'] = 'application/json';
      if (input.accessToken) headers.authorization = `Bearer ${input.accessToken}`;
      if (input.adminToken) headers.authorization = `Bearer ${input.adminToken}`;

      const response = await fetch(`${baseUrl}${input.path}`, {
        method: input.method,
        headers,
        body: input.body === undefined ? undefined : JSON.stringify(input.body),
      });

      // 204 has no body; everything else in this service is JSON by contract.
      // SAFETY: the caller names the response type it is asserting against —
      // this harness cannot know it, and a wrong `T` fails the assertion that
      // follows, which is the point of the test.
      const body = (response.status === 204 ? undefined : await response.json()) as T;
      return { status: response.status, body, headers: response.headers };
    },
    async close() {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
  return harness;
}

/** A structurally valid Argon2id descriptor for request bodies. */
export function sampleKdfDescriptor(saltByte = 1) {
  return {
    salt: Buffer.alloc(16, saltByte).toString('base64'),
    params: { memorySizeKib: 65536, iterations: 3, parallelism: 1 },
  };
}

export function sampleAuthHash(seed = 7): string {
  return Buffer.alloc(32, seed).toString('base64');
}

export function sampleWrappedDek(seed = 9): string {
  return Buffer.alloc(60, seed).toString('base64');
}

/**
 * A structurally valid recovery code: 32 Crockford base32 characters, which is
 * the 160 bits PROTOCOL.md §3.1 specifies. Rendered in the grouped form a
 * person reads, so the canonicaliser is exercised by every signup here.
 */
export function sampleRecoveryCode(seed = 0): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const characters = Array.from({ length: 32 }, (_unused, index) => alphabet[(index * 7 + seed) % alphabet.length]);
  return (characters.join('').match(/.{1,5}/g) ?? []).join('-');
}

export function sampleCiphertext(seed = 3, bytes = 256): string {
  return Buffer.alloc(bytes, seed).toString('base64');
}

/**
 * A structurally valid share wrap: ADR-0002's frozen 125 bytes
 * (`ephPub(65) ‖ iv(12) ‖ AES-256-GCM(...)`). The service never looks inside
 * it, but it does check the length, so a test wrap has to be the right size.
 */
export function sampleShareWrap(seed = 5): string {
  return Buffer.alloc(SHARE_WRAPPED_DEK_BYTES, seed).toString('base64');
}

/**
 * A structurally plausible research envelope: ADR-0003's
 * `ephPub(65) ‖ iv(12) ‖ AES-256-GCM(payload)`, which has no fixed size —
 * unlike the share wrap — because the payload is a window of days. The
 * service checks only the floor.
 */
export function sampleContributionBody(seed = 11, bytes = RESEARCH_BODY_MIN_BYTES + 64): string {
  return Buffer.alloc(bytes, seed).toString('base64');
}
