/**
 * Boots the REAL Express app (`createApp`) against a real Postgres on an
 * ephemeral loopback port, and hands back a small typed HTTP client.
 *
 * Exactly ONE dependency is substituted, for a reason that is about
 * determinism rather than avoidance: the clock, so token expiry is assertable
 * without sleeping. The store, the storage adapter, the router, the bearer
 * middleware, the CORS layer and the error handler are all production code,
 * and the schema is the committed migrations.
 *
 * The mailer used to be the second substitution. M181 deleted it.
 */
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/server/create-app.js';
import { createDrizzleAccountStore } from '../../src/db/account-store.js';
import { createDrizzleStorageAdapter } from '../../src/db/storage-adapter.js';
import { createDrizzleAdminStore } from '../../src/db/admin-store.js';
import { createDrizzleInviteStore } from '../../src/db/invite-store.js';
import { createDrizzleShareStore } from '../../src/db/share-store.js';
import { createDrizzleRotationStore } from '../../src/db/rotation-store.js';
import { createDrizzleResearchStore } from '../../src/db/research-store.js';
import { createSilentLogger } from '../../src/logger.js';
import { createThrottleStore, type ThrottleConfig } from '../../src/lib/throttle.js';
import { generateFamilyId, generateToken } from '../../src/lib/tokens.js';
import { deriveServerSecrets } from '../../src/lib/server-secrets.js';
import type { AuthContext } from '../../src/accounts/auth-handlers.js';
import type { SignupMode } from '../../src/protocol.js';
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

export interface ServiceHarness {
  baseUrl: string;
  authContext: AuthContext;
  advance(ms: number): void;
  request<T>(input: HttpRequestInput): Promise<HttpResponse<T>>;
  close(): Promise<void>;
}

/**
 * Every request in a test file arrives from 127.0.0.1, so the production
 * throttle would lock the suite out of `/v1/auth/signup` after five accounts.
 * Suites that are not ABOUT abuse control therefore run with a permissive
 * config; `abuse-controls.test.ts` opts back in to the real defaults and
 * asserts the lockout deliberately.
 */
export const PERMISSIVE_THROTTLE: ThrottleConfig = {
  freeAttempts: 10_000,
  baseLockoutMs: 1,
  maxLockoutMs: 1,
  attemptResetMs: 1,
};

export interface StartServiceOptions {
  db: Database;
  signupMode?: SignupMode;
  throttleConfig?: ThrottleConfig;
  /**
   * Absent (the default) boots the service the way every deployment boots
   * today: no admin API at all, and `/v1/admin/*` answering the ordinary
   * unknown-path 404. `admin-api.test.ts` opts in.
   */
  adminToken?: string | null;
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
}

export async function startService(options: StartServiceOptions): Promise<ServiceHarness> {
  let clock = Date.now();
  const secrets = deriveServerSecrets('integration-test-root-secret-long-enough');

  const authContext: AuthContext = {
    store: createDrizzleAccountStore(options.db),
    pepper: secrets.verifierPepper,
    enumerationSecret: secrets.enumerationSecret,
    signupMode: options.signupMode ?? 'open',
    now: () => new Date(clock),
    mintToken: generateToken,
    mintFamilyId: generateFamilyId,
    logger: createSilentLogger(),
  };

  const app = createApp({
    authContext,
    storage: createDrizzleStorageAdapter(options.db),
    rotation: createDrizzleRotationStore(options.db),
    throttle: createThrottleStore(options.throttleConfig ?? PERMISSIVE_THROTTLE),
    logger: createSilentLogger(),
    trustProxy: false,
    admin:
      options.adminToken === undefined || options.adminToken === null
        ? null
        : {
            token: options.adminToken,
            metadata: createDrizzleAdminStore(options.db),
            invites: createDrizzleInviteStore(options.db),
          },
    shares: options.sharing === true ? createDrizzleShareStore(options.db) : null,
    research: options.research === true ? createDrizzleResearchStore(options.db) : null,
  });

  const server: Server = app.listen(0);
  await new Promise<void>((resolve) => server.once('listening', resolve));
  const address = server.address();
  if (address === null) throw new Error('expected a listening server');
  // SAFETY: `listen(0)` binds a TCP port, and Node only returns the string
  // form of an address for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    baseUrl,
    authContext,
    advance(ms: number) {
      clock += ms;
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
