/**
 * `pnpm sync-api` — the operator's command line over `/v1/admin`.
 *
 * A THIN HTTP CLIENT AND NOTHING ELSE. It imports no store, no config module
 * and no database driver, so it runs from a laptop that has never seen
 * Postgres — the same shape `shw-api`, `np-api` and `lcc-api` have in this
 * workspace. `tests/unit/sync-api-no-db-imports.test.ts` walks the static
 * import graph from this file and fails if that stops being true.
 *
 * ── THE TOKEN COMES FROM THE ENVIRONMENT, AND ONLY FROM THERE ───────────────
 * `ADMIN_TOKEN`. There is deliberately no `--token` flag: a credential on a
 * command line lands in shell history and is visible in `ps` to every other
 * user on the box for as long as the command runs. There is no dotenv loading
 * and no `~/.config` file either — this is a credential that lists and erases
 * accounts, and the fewer places it can come to rest, the better. Missing it
 * is an error that names the variable, raised BEFORE any request is built.
 *
 * ── NO `--production` FLAG ──────────────────────────────────────────────────
 * `--url`, then `SYNC_SERVER_URL`, then `http://localhost:3000`. A named
 * shortcut for "the real one with the real accounts on it" is a shortcut for
 * typing it by accident; on a self-hostable service there is no single
 * production instance for such a flag to mean, either.
 *
 * ── DELETION ASKS ───────────────────────────────────────────────────────────
 * `accounts delete` requires `--yes`. Without it the command exits non-zero
 * having sent nothing. The erasure is immediate, total and irreversible: no
 * soft delete, no grace period, and the ciphertext is gone by cascade in the
 * same statement. A confirmation flag is a very small price for the one
 * command in this tool that cannot be undone.
 */
import { parseArgs } from 'node:util';
import { AdminClient, CliError, type MintInviteRequestBody } from './client.js';
import {
  decodeAccountPage,
  decodeHandshake,
  decodeSingleAccount,
  decodeStats,
  formatAccountDetail,
  formatAccountTable,
  formatStats,
  decodeInvitePage,
  decodeMintedInvite,
  formatInviteTable,
  formatMintedInvite,
} from './views.js';

const DEFAULT_BASE_URL = 'http://localhost:3000';

const USAGE = `sync-api — the openplate-sync admin CLI

  Usage: pnpm sync-api <command> [options]

  Commands:
    status                     Version handshake and admin-API reachability
    stats                      Aggregate account and storage counts
    accounts list              List accounts (metadata only)
    accounts get <id>          One account's metadata
    accounts delete <id> --yes Erase an account and everything attached to it
    invites list               Outstanding and spent signup invites
    invites create             Mint one invite; prints the token ONCE
    invites revoke <id> --yes  Withdraw an unredeemed invite

  Options:
    --url <base>   Service base URL (default: SYNC_SERVER_URL, else ${DEFAULT_BASE_URL})
    --limit <n>    Page size for "accounts list" (default 50, max 200)
    --offset <n>   Page offset for "accounts list" (default 0)
    --json         Print the decoded response as JSON (read commands only)
    --yes          Required by "accounts delete" and "invites revoke"
    --note <text>  Who an invite is for. Stored as an operator label only
    --expires-in-days <n>  Invite lifetime, 1–365 (default 14)
    --client-url <base>    Render the invite as a sign-up link on this origin

  Authentication:
    ADMIN_TOKEN must be set in the environment. There is no --token flag, on
    purpose: a credential in argv is a credential in your shell history.
`;

interface Invocation {
  command: string[];
  baseUrl: string;
  limit: string | null;
  offset: string | null;
  note: string | null;
  expiresInDays: string | null;
  clientUrl: string | null;
  json: boolean;
  yes: boolean;
  help: boolean;
}

function parseInvocation(argv: string[]): Invocation {
  const parsed = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      url: { type: 'string' },
      limit: { type: 'string' },
      offset: { type: 'string' },
      note: { type: 'string' },
      'expires-in-days': { type: 'string' },
      'client-url': { type: 'string' },
      json: { type: 'boolean', default: false },
      yes: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
  });

  return {
    command: parsed.positionals,
    // Flag beats environment beats default.
    baseUrl: parsed.values.url ?? process.env.SYNC_SERVER_URL ?? DEFAULT_BASE_URL,
    limit: parsed.values.limit ?? null,
    offset: parsed.values.offset ?? null,
    note: parsed.values.note ?? null,
    expiresInDays: parsed.values['expires-in-days'] ?? null,
    clientUrl: parsed.values['client-url'] ?? process.env.CLIENT_BASE_URL ?? null,
    json: parsed.values.json === true,
    yes: parsed.values.yes === true,
    help: parsed.values.help === true,
  };
}

/** The credential, or a refusal. Called before any request is built — see the module header. */
function requireAdminToken(): string {
  const token = process.env.ADMIN_TOKEN?.trim();
  if (token === undefined || token === '') {
    throw new CliError(
      'ADMIN_TOKEN is not set. Export it in your shell (the same value the service was started with); there is no --token flag.',
    );
  }
  return token;
}

function inviteIdArgument(invocation: Invocation): string {
  const raw = invocation.command[2];
  if (raw === undefined || raw === '') {
    throw new CliError('That command needs an invite id, e.g. `pnpm sync-api invites revoke 3 --yes`.');
  }
  return encodeURIComponent(raw);
}

function accountIdArgument(invocation: Invocation): string {
  const raw = invocation.command[2];
  if (raw === undefined || raw === '') {
    throw new CliError('That command needs an account id, e.g. `pnpm sync-api accounts get 42`.');
  }
  return encodeURIComponent(raw);
}

function listQuery(invocation: Invocation): string {
  const query = new URLSearchParams();
  if (invocation.limit !== null) query.set('limit', invocation.limit);
  if (invocation.offset !== null) query.set('offset', invocation.offset);
  const rendered = query.toString();
  return rendered === '' ? '' : `?${rendered}`;
}

function print(line: string): void {
  process.stdout.write(`${line}\n`);
}

async function runAccounts(client: AdminClient, invocation: Invocation): Promise<void> {
  const subcommand = invocation.command[1] ?? '';

  if (subcommand === 'list') {
    const page = decodeAccountPage(
      await client.request({ method: 'GET', path: `/v1/admin/accounts${listQuery(invocation)}` }),
    );
    print(invocation.json ? JSON.stringify(page, null, 2) : formatAccountTable(page));
    return;
  }

  if (subcommand === 'get') {
    const id = accountIdArgument(invocation);
    const account = decodeSingleAccount(await client.request({ method: 'GET', path: `/v1/admin/accounts/${id}` }));
    print(invocation.json ? JSON.stringify(account, null, 2) : formatAccountDetail(account));
    return;
  }

  if (subcommand === 'delete') {
    const id = accountIdArgument(invocation);
    // Checked BEFORE the request is built, so an unconfirmed delete sends nothing.
    if (!invocation.yes) {
      throw new CliError(
        `Refusing to delete account ${decodeURIComponent(id)} without --yes. This erases the account, its blob and its key records immediately and irreversibly.`,
      );
    }
    await client.request({ method: 'DELETE', path: `/v1/admin/accounts/${id}` });
    print(`Deleted account ${decodeURIComponent(id)} and everything attached to it.`);
    return;
  }

  throw new CliError(`Unknown accounts subcommand "${subcommand}". Try: list, get, delete.`);
}

async function runInvites(client: AdminClient, invocation: Invocation): Promise<void> {
  const subcommand = invocation.command[1] ?? '';

  if (subcommand === 'list') {
    const page = decodeInvitePage(
      await client.request({ method: 'GET', path: `/v1/admin/invites${listQuery(invocation)}` }),
    );
    print(invocation.json ? JSON.stringify(page, null, 2) : formatInviteTable(page));
    return;
  }

  if (subcommand === 'create') {
    const body: MintInviteRequestBody = { note: invocation.note };
    if (invocation.expiresInDays !== null) {
      const days = Number(invocation.expiresInDays);
      // Rejected here as well as by the service, so an obvious typo costs no
      // round trip and cannot mint an invite with a lifetime nobody meant.
      if (!Number.isInteger(days) || days <= 0) {
        throw new CliError('--expires-in-days must be a whole number of days, 1–365.');
      }
      body.expiresInDays = days;
    }

    const minted = decodeMintedInvite(await client.request({ method: 'POST', path: '/v1/admin/invites', body }));
    // The token IS printed — this is the one command whose whole purpose is to
    // hand the operator a secret. It is not logged by the service and cannot
    // be fetched again.
    print(invocation.json ? JSON.stringify(minted, null, 2) : formatMintedInvite(minted, invocation.clientUrl));
    return;
  }

  if (subcommand === 'revoke') {
    const id = inviteIdArgument(invocation);
    // Checked BEFORE the request is built, as with `accounts delete`.
    if (!invocation.yes) {
      throw new CliError(
        `Refusing to revoke invite ${decodeURIComponent(id)} without --yes. Anyone already holding that token loses it.`,
      );
    }
    await client.request({ method: 'DELETE', path: `/v1/admin/invites/${id}` });
    print(`Revoked invite ${decodeURIComponent(id)}.`);
    return;
  }

  throw new CliError(`Unknown invites subcommand "${subcommand}". Try: list, create, revoke.`);
}

async function runStatus(client: AdminClient, invocation: Invocation): Promise<void> {
  const handshake = decodeHandshake(await client.request({ method: 'GET', path: '/health' }));
  // The second call is the one that proves the ADMIN surface is reachable and
  // the token is accepted: `/health` answers to anybody.
  const stats = decodeStats(await client.request({ method: 'GET', path: '/v1/admin/stats' }));

  if (invocation.json) {
    print(JSON.stringify({ handshake, stats }, null, 2));
    return;
  }
  print(
    [
      `service         ${handshake.serviceVersion}`,
      `protocol        v${handshake.protocolVersion} (envelope v${handshake.envelopeVersion})`,
      `admin API       reachable, token accepted`,
      `accounts        ${stats.accounts}`,
    ].join('\n'),
  );
}

async function run(argv: string[]): Promise<void> {
  const invocation = parseInvocation(argv);
  if (invocation.help || invocation.command.length === 0) {
    print(USAGE);
    return;
  }

  // Before the client exists, so a missing credential can never become a request.
  const client = new AdminClient({ baseUrl: invocation.baseUrl, adminToken: requireAdminToken() });
  const command = invocation.command[0] ?? '';

  if (command === 'invites') {
    await runInvites(client, invocation);
    return;
  }

  if (command === 'accounts') {
    await runAccounts(client, invocation);
    return;
  }
  if (command === 'stats') {
    const stats = decodeStats(await client.request({ method: 'GET', path: '/v1/admin/stats' }));
    print(invocation.json ? JSON.stringify(stats, null, 2) : formatStats(stats));
    return;
  }
  if (command === 'status') {
    await runStatus(client, invocation);
    return;
  }

  throw new CliError(`Unknown command "${command}". Run \`pnpm sync-api --help\`.`);
}

run(process.argv.slice(2)).catch((cause: unknown) => {
  // A `CliError` is already a sentence written for an operator. Anything else
  // is a bug in this tool, and its message is scrubbed for the same reason the
  // service scrubs a startup failure: it can carry a URL, and a URL can carry
  // a query string somebody put a credential in.
  const message = cause instanceof CliError ? cause.message : 'sync-api failed with an unexpected error';
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
