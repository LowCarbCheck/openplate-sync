/**
 * Boots the REAL app (`createApp`) with fake stores, on an ephemeral loopback
 * port, so the admin-API tests exercise the actual mount decision rather than
 * a router assembled by the test.
 *
 * That matters more here than usual. The property under test in
 * `admin-404-when-unset.test.ts` is a MOUNTING property — "with no token
 * configured, nothing that answers 401 exists on this path" — and a test that
 * built the admin router itself and called it directly could not observe it.
 * So the harness takes an admin token or `null` and hands the whole thing to
 * `createApp` exactly as `main.ts` does.
 *
 * The logger is captured rather than silenced, because "the log line carries
 * the account id and not the address" is itself a tested property
 * (`admin-log-leak.test.ts`).
 */
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createApp } from '../../src/server/create-app.js';
import { createThrottleStore } from '../../src/lib/throttle.js';
import type { LogFields, Logger } from '../../src/logger.js';
import type { AccountStore } from '../../src/accounts/account-store.js';
import { createAuthFixture } from './auth-context-fixture.js';
import { createFakeStorageAdapter } from './fake-storage-adapter.js';
import { createFakeRotationStore } from './fake-rotation-store.js';
import { createFakeAdminStore, type FakeAdminStore } from './fake-admin-store.js';
import type { FakeAccountStore } from './fake-account-store.js';

/** One emitted log line, kept whole so a test can assert on the message AND the fields. */
export interface CapturedLogLine {
  level: string;
  message: string;
  fields: LogFields | undefined;
}

export interface CapturingLogger {
  logger: Logger;
  lines: CapturedLogLine[];
}

export function createCapturingLogger(): CapturingLogger {
  const lines: CapturedLogLine[] = [];
  const record =
    (level: string) =>
    (message: string, fields?: LogFields): void => {
      lines.push({ level, message, fields });
    };
  return {
    lines,
    logger: { debug: record('debug'), info: record('info'), warn: record('warn'), error: record('error') },
  };
}

export interface AdminHarness {
  baseUrl: string;
  admin: FakeAdminStore;
  /** The store the app holds — the spying wrapper below. */
  accounts: AccountStore;
  /** The store underneath it, with the test-only inspectors (`hasAccount`, `allTokens`). */
  fakeAccounts: FakeAccountStore;
  logLines: CapturedLogLine[];
  /** Every account id passed to the shared `AccountStore.deleteAccount`, in order. */
  deletedAccountIds: number[];
  request(input: { method: string; path: string; token?: string | null }): Promise<Response>;
  close(): Promise<void>;
}

export interface StartAdminHarnessOptions {
  /** `null` means "this instance never configured an admin API" — the default state of every deployment. */
  adminToken: string | null;
}

export async function startAdminHarness(options: StartAdminHarnessOptions): Promise<AdminHarness> {
  const fixture = createAuthFixture();
  const adminStore = createFakeAdminStore();
  const capturing = createCapturingLogger();
  const deletedAccountIds: number[] = [];

  /**
   * The account store the app is given, wrapped so a test can prove the admin
   * route goes through `AccountStore.deleteAccount` — the same method the
   * self-service path calls — rather than reaching past it into SQL.
   */
  const accounts: AccountStore = {
    ...fixture.store,
    async deleteAccount(accountId: number): Promise<void> {
      deletedAccountIds.push(accountId);
      await fixture.store.deleteAccount(accountId);
    },
  };

  const app = createApp({
    authContext: { ...fixture.ctx, store: accounts },
    storage: createFakeStorageAdapter(),
    rotation: createFakeRotationStore(),
    throttle: createThrottleStore({ freeAttempts: 10_000, baseLockoutMs: 1, maxLockoutMs: 1, attemptResetMs: 1 }),
    logger: capturing.logger,
    trustProxy: false,
    admin: options.adminToken === null ? null : { token: options.adminToken, metadata: adminStore },
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
    admin: adminStore,
    accounts,
    fakeAccounts: fixture.store,
    logLines: capturing.lines,
    deletedAccountIds,
    async request(input: { method: string; path: string; token?: string | null }): Promise<Response> {
      const headers: Record<string, string> = {};
      const token = input.token ?? null;
      if (token !== null) headers.authorization = `Bearer ${token}`;
      return fetch(`${baseUrl}${input.path}`, { method: input.method, headers });
    },
    async close(): Promise<void> {
      await new Promise<void>((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
    },
  };
}
