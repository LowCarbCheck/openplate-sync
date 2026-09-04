/**
 * Build script — bundles the SERVICE entry point (`src/main.ts`) into a
 * single ESM `dist/server.js` via esbuild. That file is what the Docker image
 * runs and what `pnpm start` executes.
 *
 * WHY BUNDLE AT ALL: the runtime image then carries one file plus a handful of
 * externals, rather than a `node_modules` tree a self-hoster has to trust and
 * scan, and the artifact is reproducible from one command.
 *
 * WHY THESE FOUR ARE EXTERNAL:
 *  - `pg` resolves optional native/dialect helpers at runtime; bundling it is a
 *    well-known source of "cannot find module" failures that only appear in
 *    production.
 *  - `express` relies on `instanceof` in a few internals, so a second bundled
 *    copy can misbehave in ways that are extremely unfun to debug.
 *  - `dotenv` is CommonJS and calls `require('fs')` at load time. Inlined into
 *    an ESM bundle that becomes esbuild's `Dynamic require of "fs" is not
 *    supported` shim, and the process dies on its FIRST line — a failure no
 *    unit or integration test can see, because neither runs `dist/`. Found by
 *    actually starting the built image; the lesson is that "the bundle builds"
 *    and "the bundle runs" are different claims.
 *  - `undici` is the AI proxy's HTTP client (`src/ai/proxy.ts`), and it is
 *    there because Node's global `fetch` caps `headersTimeout` at 300 s in a
 *    way an `AbortSignal` cannot raise. It ships native-ish internals and its
 *    own dispatcher registry, so a bundled second copy would be a second
 *    connection pool with the operator's provider key in it.
 *
 * All four are ordinary production dependencies installed into the image
 * (`pnpm install --prod`), so the bundle resolves them at runtime.
 *
 * Migrations are NOT bundled: `drizzle/migrations/` is copied into the image as
 * data and read by the migrator at boot (`src/main.ts`).
 */
import { build } from 'esbuild';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

/**
 * esbuild's shim for a CommonJS `require()` it could not resolve at build time.
 * Its presence means some inlined dependency will throw on its first line at
 * runtime — a build that succeeds and an artifact that cannot start.
 */
const DYNAMIC_REQUIRE_SHIM = 'Dynamic require of';

/**
 * Fails the build if the bundle contains the shim above.
 *
 * This exists because that failure is invisible to every other check: typecheck
 * passes, the unit and integration suites pass (they run TypeScript sources,
 * never `dist/`), and esbuild reports success. The only thing that catches it
 * is starting the artifact — or this grep, which costs a millisecond and does
 * not need a database.
 *
 * If it fires, add the offending package to `external` above.
 */
async function assertBundleHasNoDynamicRequire(outfile: string): Promise<void> {
  const bundle = await readFile(outfile, 'utf8');
  if (!bundle.includes(DYNAMIC_REQUIRE_SHIM)) return;
  throw new Error(
    `dist/server.js contains esbuild's dynamic-require shim, so it will throw on startup. ` +
      `A CommonJS dependency was inlined into the ESM bundle — add it to \`external\` in scripts/build.ts.`,
  );
}

/**
 * The version the built server reports on `/health`.
 *
 * Read from `package.json` HERE, at build time, and inlined — because the
 * bundle runs as `dist/server.js` where `package.json` sits at no guaranteed
 * relative path, and because the alternative is a hand-maintained constant
 * that goes stale. It did: 0.3.0 deployed reporting `0.2.0`, which is exactly
 * the value an operator reads to decide whether their deploy landed.
 */
async function packageVersion(): Promise<string> {
  const raw = await readFile(resolve(repoRoot, 'package.json'), 'utf8');
  // SAFETY: this file is our own `package.json`, read from the repo root two
  // lines above. A malformed one fails the guard below rather than shipping a
  // wrong version, and it is not external input.
  const { version } = JSON.parse(raw) as { version?: string };
  if (!version) throw new Error('package.json has no usable version field');
  return version;
}

/**
 * Fails the build if the emitted bundle does not carry the package version.
 *
 * The `define` above is easy to delete in a refactor, and nothing else would
 * notice: typecheck passes, tests pass (they run the TS sources, where the
 * fallback applies), and the image starts fine — reporting the wrong version
 * to the only person who is checking whether their deploy landed. That is not
 * hypothetical; it is what happened to the constant this replaced.
 */
async function assertBundleReportsVersion(outfile: string, version: string): Promise<void> {
  const bundle = await readFile(outfile, 'utf8');
  if (bundle.includes(JSON.stringify(version))) return;
  throw new Error(
    `dist/server.js does not contain the package version ${version}, so the built server would ` +
      'report a stale one. The `define` for `__SERVICE_VERSION__` is missing or has stopped working.',
  );
}

async function main(): Promise<void> {
  const outfile = resolve(repoRoot, 'dist/server.js');
  await build({
    entryPoints: [resolve(repoRoot, 'src/main.ts')],
    outfile,
    bundle: true,
    platform: 'node',
    format: 'esm',
    target: 'node20',
    external: ['express', 'pg', 'dotenv', 'undici'],
    sourcemap: true,
    logLevel: 'info',
    define: { 'globalThis.__SERVICE_VERSION__': JSON.stringify(await packageVersion()) },
  });
  await assertBundleHasNoDynamicRequire(outfile);
  await assertBundleReportsVersion(outfile, await packageVersion());
}

main().catch((cause: unknown) => {
  console.error(cause);
  process.exitCode = 1;
});
