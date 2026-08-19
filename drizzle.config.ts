/**
 * drizzle-kit configuration.
 *
 * The schema lives under `src/` (with the rest of the code it belongs to);
 * only the GENERATED migrations live in `drizzle/`. Nothing in that directory
 * is ever hand-written — see `src/db/schema.ts`'s header for why, and for the
 * journal-timestamp rule that silently skips migrations when broken.
 *
 * `drizzle-kit generate` never opens a connection, so the dummy fallback
 * below lets migrations be generated offline (in a sandbox, or on a laptop
 * with no database running). `migrate`, `push` and `studio` DO connect, and
 * against the fallback they will fail loudly — which is correct: they had no
 * business running without a real `DATABASE_URL`.
 */
import type { Config } from 'drizzle-kit';

const OFFLINE_GENERATE_PLACEHOLDER = 'postgres://drizzle:drizzle@127.0.0.1:5432/drizzle';

export default {
  dialect: 'postgresql',
  schema: './src/db/schema.ts',
  out: './drizzle/migrations',
  dbCredentials: {
    url: process.env.DATABASE_URL ?? OFFLINE_GENERATE_PLACEHOLDER,
  },
} satisfies Config;
