/**
 * Runs the `sync-api` entrypoint as a REAL child process, against a local
 * server that counts every request it receives.
 *
 * WHY A CHILD PROCESS AND NOT AN IMPORTED FUNCTION. Two of the properties
 * under test are about the process — a non-zero exit status, and a message on
 * stderr — and neither is observable from inside the module. The third, "no
 * network call was made", is only credible if the CLI could have made one: the
 * `--url` handed in below points at a listener that would happily answer, so a
 * request that is not counted is a request that was never sent.
 */
import { spawn } from 'node:child_process';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const entrypoint = resolve(repoRoot, 'scripts/sync-api/main.ts');

export interface CountingServer {
  baseUrl: string;
  /** `METHOD /path` for every request that arrived. Empty means the CLI sent nothing. */
  requests: string[];
  close(): Promise<void>;
}

/** A server that answers everything with an empty JSON object and remembers being asked. */
export async function startCountingServer(): Promise<CountingServer> {
  const requests: string[] = [];
  const server: Server = createServer((req, res) => {
    requests.push(`${req.method ?? 'UNKNOWN'} ${req.url ?? ''}`);
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });

  server.listen(0);
  await new Promise<void>((ready) => server.once('listening', ready));
  const address = server.address();
  if (address === null) throw new Error('expected a listening server');
  // SAFETY: `listen(0)` binds a TCP port, and Node only returns the string
  // form of an address for a Unix domain socket, which this never opens.
  const { port } = address as AddressInfo;

  return {
    baseUrl: `http://127.0.0.1:${port}`,
    requests,
    async close(): Promise<void> {
      await new Promise<void>((closed, failed) => server.close((error) => (error ? failed(error) : closed())));
    },
  };
}

export interface CliRun {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface RunCliInput {
  args: string[];
  /** The admin token to export, or `null` for "the operator has not set it". */
  adminToken: string | null;
}

/**
 * Runs the CLI with a DELIBERATELY MINIMAL environment. Inheriting the test
 * runner's env would let a developer's own exported `ADMIN_TOKEN` make the
 * missing-token test pass for the wrong reason.
 */
export async function runCli(input: RunCliInput): Promise<CliRun> {
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '' };
  if (input.adminToken !== null) env.ADMIN_TOKEN = input.adminToken;

  const child = spawn(process.execPath, ['--import', 'tsx', entrypoint, ...input.args], {
    cwd: repoRoot,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => {
    stdout += chunk.toString('utf8');
  });
  child.stderr.on('data', (chunk: Buffer) => {
    stderr += chunk.toString('utf8');
  });

  const exitCode = await new Promise<number>((done, failed) => {
    child.on('error', failed);
    child.on('close', (code) => done(code ?? 0));
  });

  return { exitCode, stdout, stderr };
}
