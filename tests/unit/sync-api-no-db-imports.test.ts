/**
 * `sync-api` must be runnable with nothing but a URL and a token.
 *
 * That is the property `shw-api`, `np-api` and `lcc-api` have, and the reason
 * an operator (or an agent) can act on a running instance from a laptop with
 * no Postgres, no `DATABASE_URL` and no `SERVER_SECRET`. It is also easy to
 * lose by accident: one convenient `import type { AccountRecord } from
 * '../../src/db/account-store.js'` drags `drizzle-orm` — and, through
 * `db/client.js`, `pg` and a live connection pool — into the CLI's graph. A
 * type-only import looks free and is not: the module still has to load.
 *
 * A grep over `scripts/` cannot express this, because `scripts/build.ts` is
 * another entrypoint entirely. So this test walks the static import graph
 * reachable from `scripts/sync-api/main.ts` specifically and asserts that no
 * module in it names a database package or reaches into `src/db`, `src/config`
 * (which would pull in a whole environment contract the CLI has no business
 * knowing) or the account store.
 *
 * The idiom is `nicotinepouch-org/tests/unit/np-api-no-db-imports.test.ts`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const entrypoint = resolve(repoRoot, 'scripts/sync-api/main.ts');

/** Package specifiers that mean "this module reached the database layer". */
const FORBIDDEN_PACKAGES = ['pg', 'drizzle-orm', 'drizzle-kit', 'dotenv', 'express', 'nodemailer'] as const;

/** Repo files the CLI must not reach, by the path they resolve to. */
const FORBIDDEN_FILES = ['src/db/', 'src/config.ts', 'src/accounts/', 'src/main.ts'] as const;

/** Every `from '…'` specifier in a source file, imports and re-exports alike. */
function readSpecifiers(file: string): string[] {
  const source = readFileSync(file, 'utf8');
  const found: string[] = [];
  for (const match of source.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
    const specifier = match[1];
    if (specifier !== undefined) found.push(specifier);
  }
  return found;
}

/**
 * Resolve a relative specifier to a file inside the repo, or `null` for a bare
 * package name. The `.js` → `.ts` rewrite is NodeNext's rule: the source says
 * `./client.js` and the file on disk is `client.ts`.
 */
function resolveLocal(specifier: string, fromFile: string): string | null {
  if (!specifier.startsWith('.')) return null;
  const base = resolve(dirname(fromFile), specifier);

  for (const candidate of [base.replace(/\.js$/, '.ts'), base, `${base}.ts`, `${base}/index.ts`]) {
    if (existsSync(candidate) && !candidate.endsWith('/')) return candidate;
  }
  return null;
}

interface GraphEdge {
  file: string;
  specifier: string;
}

interface ImportGraph {
  files: string[];
  specifiers: GraphEdge[];
}

function collectGraph(): ImportGraph {
  const seen = new Set<string>();
  const queue = [entrypoint];
  const specifiers: GraphEdge[] = [];

  while (queue.length > 0) {
    const file = queue.pop();
    if (file === undefined || seen.has(file)) continue;
    seen.add(file);

    for (const specifier of readSpecifiers(file)) {
      specifiers.push({ file, specifier });
      const local = resolveLocal(specifier, file);
      if (local !== null && !seen.has(local)) queue.push(local);
    }
  }

  return { files: [...seen], specifiers };
}

function relative(file: string): string {
  return file.slice(repoRoot.length + 1);
}

test('the walker actually follows imports', () => {
  const { files } = collectGraph();
  // The entrypoint, the client, the views module and `src/lib/json.ts` at
  // minimum — a walker that resolved nothing would make every assertion below
  // pass on an empty graph.
  assert.ok(files.length >= 4, `expected the walker to follow imports, saw ${files.length} files`);
  assert.ok(
    files.some((file) => relative(file) === 'src/lib/json.ts'),
    'the walker must reach src/lib/json.ts through scripts/sync-api/views.ts',
  );
});

test('no database or server package appears anywhere in the CLI graph', () => {
  const { specifiers } = collectGraph();

  const offenders = specifiers.filter(({ specifier }) =>
    FORBIDDEN_PACKAGES.some((banned) => specifier === banned || specifier.startsWith(`${banned}/`)),
  );

  assert.deepEqual(
    offenders.map(({ file, specifier }) => `${relative(file)} → ${specifier}`),
    [],
    'sync-api must not import the database or the HTTP server layer',
  );
});

test('the CLI graph reaches no store, config or service-entry module', () => {
  const { files } = collectGraph();

  const offenders = files
    .map(relative)
    .filter((file) => FORBIDDEN_FILES.some((banned) => file === banned || file.startsWith(banned)));

  assert.deepEqual(offenders, [], 'sync-api must reach only pure modules — src/lib/json.ts is the one it needs');
});
