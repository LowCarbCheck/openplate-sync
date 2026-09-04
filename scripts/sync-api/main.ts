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
import { AdminClient, CliError, type AccountPatchBody, type MintInviteRequestBody } from './client.js';
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
  decodeResetMail,
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
    accounts set-role <id> admin|member   Change what an account may do
    accounts set-limit <id> <n>           Change its AI requests per UTC day
    accounts suspend <id>      Lock it out and revoke every session, reversibly
    accounts reactivate <id>   Let it back in
    invites list               Outstanding and spent signup invites
    invites create --email <address>   Mint one addressed invite; prints the link ONCE
    invites resend <id>        Mint a NEW token for the same invite and send it
    invites revoke <id> --yes  Withdraw an unredeemed invite
    accounts reset-mail <id>   Send this account a password-reset letter

  Options:
    --url <base>   Service base URL (default: SYNC_SERVER_URL, else ${DEFAULT_BASE_URL})
    --limit <n>    Page size for "accounts list" (default 50, max 200)
    --offset <n>   Page offset for "accounts list" (default 0)
    --json         Print the decoded response as JSON (read commands only)
    --yes          Required by "accounts delete" and "invites revoke"
    --email <address>      Who the invite is for. Becomes the account's identity
    --display-name <text>  The person's name, carried onto the account
    --role <admin|member>  What the redeemed account may do (default member)
    --daily-ai-limit <n>   AI requests a day for the redeemed account (default 0)
    --expires-in-days <n>  Invite lifetime, 1–30 (default 7)

  Authentication:
    ADMIN_TOKEN must be set in the environment. There is no --token flag, on
    purpose: a credential in argv is a credential in your shell history.
`;

interface Invocation {
  command: string[];
  baseUrl: string;
  limit: string | null;
  offset: string | null;
  email: string | null;
  displayName: string | null;
  role: string | null;
  dailyAiLimit: string | null;
  expiresInDays: string | null;
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
      email: { type: 'string' },
      'display-name': { type: 'string' },
      role: { type: 'string' },
      'daily-ai-limit': { type: 'string' },
      'expires-in-days': { type: 'string' },
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
    email: parsed.values.email ?? null,
    displayName: parsed.values['display-name'] ?? null,
    role: parsed.values.role ?? null,
    dailyAiLimit: parsed.values['daily-ai-limit'] ?? null,
    expiresInDays: parsed.values['expires-in-days'] ?? null,
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

/** The role argument of `accounts set-role`, or a refusal. Checked here so an obvious typo costs no round trip. */
function roleFrom(value: string): AccountPatchBody {
  if (value !== 'admin' && value !== 'member') {
    throw new CliError('accounts set-role needs a role: `accounts set-role <id> admin` or `... member`.');
  }
  return { role: value };
}

/** The allowance argument of `accounts set-limit`, or a refusal. `0` is meaningful: it turns AI off for the account. */
function limitFrom(value: string): AccountPatchBody {
  const limit = Number(value);
  if (!Number.isInteger(limit) || limit < 0) {
    throw new CliError('accounts set-limit needs a whole number of requests a day, 0 or more.');
  }
  return { dailyAiLimit: limit };
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

  if (subcommand === 'reset-mail') {
    const id = accountIdArgument(invocation);
    const sent = decodeResetMail(await client.request({ method: 'POST', path: `/v1/admin/accounts/${id}/reset-mail` }));
    if (sent.emailed) {
      print(`A password-reset letter was sent to account ${decodeURIComponent(id)}.`);
      return;
    }
    // No mail on this instance, so the operator carries the link. It opens the
    // account's recovery code ONCE, so it goes to the account holder and to
    // nobody else.
    print(
      [
        `This instance sends no mail, so nothing was sent to account ${decodeURIComponent(id)}.`,
        '',
        'Give this link to the account holder and to nobody else. It works once.',
        '',
        sent.link ?? '(no link: set CLIENT_BASE_URL and SERVER_PUBLIC_URL on the service)',
      ].join('\n'),
    );
    return;
  }

  if (subcommand === 'set-role' || subcommand === 'set-limit') {
    const id = accountIdArgument(invocation);
    // The third positional, because a value this short is clearer beside the id
    // than behind a flag: `accounts set-role 7 admin` reads as the sentence it is.
    const value = invocation.command[3] ?? '';
    const patch = subcommand === 'set-role' ? roleFrom(value) : limitFrom(value);
    const account = decodeSingleAccount(
      await client.request({ method: 'PATCH', path: `/v1/admin/accounts/${id}`, body: patch }),
    );
    print(invocation.json ? JSON.stringify(account, null, 2) : formatAccountDetail(account));
    return;
  }

  if (subcommand === 'suspend' || subcommand === 'reactivate') {
    const id = accountIdArgument(invocation);
    const account = decodeSingleAccount(
      await client.request({
        method: 'PATCH',
        path: `/v1/admin/accounts/${id}`,
        body: { suspended: subcommand === 'suspend' },
      }),
    );
    if (subcommand === 'suspend') {
      // Say what it did rather than only that it worked: revoking the sessions
      // is the half an operator does not see in the row.
      print(`Suspended account ${decodeURIComponent(id)}. Every session is revoked and its next request is refused.`);
    } else {
      print(`Reactivated account ${decodeURIComponent(id)}. It signs in again with its own password.`);
    }
    if (invocation.json) print(JSON.stringify(account, null, 2));
    return;
  }

  throw new CliError(
    `Unknown accounts subcommand "${subcommand}". Try: list, get, delete, set-role, set-limit, suspend, reactivate, reset-mail.`,
  );
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
    // Checked BEFORE the request is built. An invite with no address is not an
    // invite: the address is what the letter goes to and what the account is
    // identified by, and there is nothing sensible to default it to.
    if (invocation.email === null || invocation.email.trim() === '') {
      throw new CliError('invites create needs --email <address>: an invite is addressed to one person.');
    }

    const body: MintInviteRequestBody = { email: invocation.email.trim(), displayName: invocation.displayName };
    if (invocation.role !== null) {
      // Rejected here as well as by the service, so an obvious typo costs no
      // round trip and cannot mint an invite nobody meant.
      if (invocation.role !== 'admin' && invocation.role !== 'member') {
        throw new CliError('--role must be "admin" or "member".');
      }
      body.role = invocation.role;
    }
    if (invocation.dailyAiLimit !== null) {
      const limit = Number(invocation.dailyAiLimit);
      if (!Number.isInteger(limit) || limit < 0) {
        throw new CliError('--daily-ai-limit must be a whole number of requests, 0 or more.');
      }
      body.dailyAiLimit = limit;
    }
    if (invocation.expiresInDays !== null) {
      const days = Number(invocation.expiresInDays);
      if (!Number.isInteger(days) || days <= 0) {
        throw new CliError('--expires-in-days must be a whole number of days, 1–30.');
      }
      body.expiresInDays = days;
    }

    const minted = decodeMintedInvite(await client.request({ method: 'POST', path: '/v1/admin/invites', body }));
    // The capability IS printed — this is the one command whose whole purpose
    // is to hand the operator a secret. It is not logged by the service and
    // cannot be fetched again.
    print(invocation.json ? JSON.stringify(minted, null, 2) : formatMintedInvite(minted));
    return;
  }

  if (subcommand === 'resend') {
    const id = inviteIdArgument(invocation);
    const resent = decodeMintedInvite(await client.request({ method: 'POST', path: `/v1/admin/invites/${id}/resend` }));
    // A NEW token on the same invite, so the previous link is dead. Printed
    // under the same rule `create` uses: the capability is shown once.
    print(invocation.json ? JSON.stringify(resent, null, 2) : formatMintedInvite(resent));
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

  throw new CliError(`Unknown invites subcommand "${subcommand}". Try: list, create, resend, revoke.`);
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
      `instance        ${handshake.instanceName ?? 'unnamed'}`,
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
