/**
 * Database connection — a FACTORY, deliberately not a module-level singleton.
 *
 * The openplate app learned this the hard way: its `drizzle/db.ts` opens a
 * pool and starts a retrying connect as a module-load side effect, so any
 * unit test that transitively imports it hangs or rejects with no database
 * around. Here the pool is created only when someone calls
 * `createDatabase()`, which means every module in `src/` is safe to import
 * from a plain `node --test` run, and the integration suite can stand up and
 * tear down its own pool per file.
 *
 * The connect retry loop exists for one specific, routine situation: a
 * `docker compose up` starts this service and Postgres at the same instant,
 * and Postgres is not accepting connections for the first second or two.
 * Crashing there would make a correct compose file look broken.
 */
import pg from 'pg';
import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import * as schema from './schema.js';
import type { Logger } from '../logger.js';
import { sqlstate } from '../lib/storage-conflict.js';

export type Database = NodePgDatabase<typeof schema>;

export interface DatabaseHandle {
  db: Database;
  pool: pg.Pool;
  close(): Promise<void>;
}

export interface CreateDatabaseOptions {
  connectionString: string;
  ssl: boolean;
}

export function createDatabase(options: CreateDatabaseOptions): DatabaseHandle {
  const pool = new pg.Pool({
    connectionString: options.connectionString,
    ssl: options.ssl ? { rejectUnauthorized: false } : undefined,
  });

  // Without this, an idle client dropped by the database (or by a NAT
  // timeout) surfaces as an *uncaught* exception and takes the process down.
  pool.on('error', () => undefined);

  return {
    db: drizzle(pool, { schema }),
    pool,
    async close() {
      await pool.end();
    },
  };
}

export interface WaitForDatabaseOptions {
  pool: pg.Pool;
  logger: Logger;
  /** Explicit bound — never an unbounded retry loop; a genuinely wrong `DATABASE_URL` must eventually fail the boot. */
  maxAttempts?: number;
  delayMs?: number;
}

/**
 * Postgres SQLSTATEs that a retry can never fix. Waiting on these turns a
 * clear misconfiguration into ten seconds of "not reachable yet" followed by a
 * message about connectivity — which sends the operator to look at their
 * network instead of at their typo.
 */
const UNRECOVERABLE_CONNECT_CODES = new Set([
  '3D000', // invalid_catalog_name — the database does not exist
  '28P01', // invalid_password
  '28000', // invalid_authorization_specification
]);

/** Whether an error is a Postgres rejection that no amount of waiting will change. */
export function isUnrecoverableConnectError(cause: unknown): boolean {
  const code = sqlstate(cause);
  return code !== null && UNRECOVERABLE_CONNECT_CODES.has(code);
}

/**
 * Blocks until a connection succeeds, or throws.
 *
 * The retry exists for ONE routine situation: `docker compose up` starts this
 * service and Postgres at the same instant and Postgres is not accepting
 * connections for a second or two. Anything Postgres actively rejects — wrong
 * database name, wrong password — fails immediately instead, because it is a
 * configuration error and reporting it as a connectivity problem wastes the
 * operator's time.
 */
export async function waitForDatabase(options: WaitForDatabaseOptions): Promise<void> {
  const maxAttempts = options.maxAttempts ?? 10;
  const delayMs = options.delayMs ?? 1000;

  let attempt = 1;
  let lastError: unknown;
  while (attempt <= maxAttempts) {
    try {
      const client = await options.pool.connect();
      client.release();
      return;
    } catch (error) {
      lastError = error;
      if (isUnrecoverableConnectError(error)) break;
      options.logger.warn('Database not reachable yet', { attempt, maxAttempts });
      if (attempt === maxAttempts) break;
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
    attempt += 1;
  }

  const reason = lastError instanceof Error ? lastError.message : 'unknown error';
  if (isUnrecoverableConnectError(lastError)) {
    throw new Error(`Postgres rejected the connection — check DATABASE_URL: ${reason}`);
  }
  throw new Error(`Could not connect to the database after ${maxAttempts} attempts: ${reason}`);
}

/**
 * Applies pending migrations. Run on EVERY boot, before the HTTP listener
 * opens — a self-hoster upgrading their image must never have to run a
 * separate command, and a half-migrated schema must never serve a request.
 */
export async function runMigrations(input: { db: Database; migrationsFolder: string }): Promise<void> {
  await migrate(input.db, { migrationsFolder: input.migrationsFolder });
}
