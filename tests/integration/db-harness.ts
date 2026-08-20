/**
 * Integration-test database harness.
 *
 * Points at the SHARED local Postgres (`localhost:5433` by default — the
 * workspace's `projects-postgres-1`), never at a per-repo compose database.
 * `docker/compose.yml` exists for self-hosters; using it for tests would mean
 * every developer running a second Postgres for no reason. A contributor with
 * no shared Postgres can start `docker/compose.dev.yml`, which serves exactly
 * the default URL below.
 *
 * The test database is created idempotently (a `42P04` "already exists" is
 * the expected outcome on every run after the first) and migrated with the
 * SAME committed migrations production uses — which is the point. A harness
 * that built its schema by any other route would let a broken migration pass
 * a green suite.
 *
 * Override with `TEST_DATABASE_URL` to run against something else.
 */
import pg from 'pg';
import { createDatabase, runMigrations, type DatabaseHandle } from '../../src/db/client.js';
import { sqlstate } from '../../src/lib/storage-conflict.js';

const DEFAULT_TEST_DATABASE_URL = 'postgres://postgres:postgres@localhost:5433/openplate_sync_test';

/** Postgres SQLSTATE for "database already exists" — the normal case, not an error. */
const DUPLICATE_DATABASE = '42P04';

export function testDatabaseUrl(): string {
  return process.env.TEST_DATABASE_URL ?? DEFAULT_TEST_DATABASE_URL;
}

/**
 * Creates the test database if it is missing, by connecting to the server's
 * default `postgres` database first (you cannot `CREATE DATABASE` from inside
 * the database you are creating).
 */
async function ensureTestDatabaseExists(url: string): Promise<void> {
  const target = new URL(url);
  const databaseName = target.pathname.replace(/^\//, '');

  const adminUrl = new URL(url);
  adminUrl.pathname = '/postgres';

  const admin = new pg.Client({ connectionString: adminUrl.toString() });
  await admin.connect();
  try {
    // Identifier interpolation is unavoidable here (Postgres does not accept a
    // parameter for a database name); the value comes from our own test URL,
    // and the quoting below is the standard escape.
    await admin.query(`CREATE DATABASE "${databaseName.replace(/"/g, '""')}"`);
  } catch (error) {
    if (sqlstate(error) !== DUPLICATE_DATABASE) throw error;
  } finally {
    await admin.end();
  }
}

export interface TestDatabase extends DatabaseHandle {
  /** Empties every table, resetting identity sequences so ids are predictable per test. */
  reset(): Promise<void>;
}

export async function setupTestDatabase(): Promise<TestDatabase> {
  const url = testDatabaseUrl();
  await ensureTestDatabaseExists(url);

  const handle = createDatabase({ connectionString: url, ssl: false });
  await runMigrations({ db: handle.db, migrationsFolder: 'drizzle/migrations' });

  return {
    ...handle,
    async reset() {
      // One statement, CASCADE, identity restart: fast, and it exercises the
      // real foreign keys rather than deleting in a hand-maintained order.
      await handle.pool.query(
        'TRUNCATE TABLE account_tokens, sync_blobs, sync_key_records, accounts RESTART IDENTITY CASCADE',
      );
    },
  };
}
