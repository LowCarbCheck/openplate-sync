/**
 * Decoding and rendering for `sync-api` — the boundary between "JSON that
 * arrived from somewhere" and the lines an operator reads.
 *
 * The decoders below use `src/lib/json.ts`, the same pure module the service
 * parses request bodies with. A CLI that trusted a response shape would crash
 * with a stack trace the first time `--url` pointed at a reverse proxy, an
 * older instance, or something that is not this service at all; here a
 * response that does not have the documented shape is a sentence.
 *
 * NOTHING HERE RENDERS A SECRET, because the API never sends one — there is no
 * ciphertext, verifier, KDF descriptor or token in any admin response (see
 * `src/server/admin-routes.ts` and the ADR). This module therefore has no
 * redaction logic and must never need any: if a future field arrives that
 * would have to be redacted here, the mistake is on the server.
 */
import { asArray, asBoolean, asNumber, asObject, asString, type JsonValue } from '../../src/lib/json.js';
import { CliError } from './client.js';

export interface AccountView {
  id: number;
  email: string;
  displayName: string | null;
  role: string;
  dailyAiLimit: number;
  aiUsedToday: number;
  suspendedAt: string | null;
  createdAt: string;
  blobBytes: number | null;
  blobUpdatedAt: string | null;
  keyRecordKinds: string[];
}

export interface AccountPageView {
  accounts: AccountView[];
  total: number;
  limit: number;
  offset: number;
}

export interface StatsView {
  accounts: number;
  accountsWithBlob: number;
  blobVersions: number;
  keyRecords: number;
  blobBytes: number;
}

export interface HandshakeView {
  protocolVersion: number;
  envelopeVersion: number;
  serviceVersion: string;
  /** What the instance calls itself, or `null` on a service older than protocol 2. */
  instanceName: string | null;
}

/** The one sentence every decode failure gets: the far end is not what we expected, and we do not quote it. */
function undocumentedResponse(what: string): CliError {
  return new CliError(
    `The service's ${what} response did not have the documented shape. Check that --url points at an openplate-sync instance and that its version matches this CLI.`,
  );
}

function decodeAccount(value: JsonValue | undefined): AccountView {
  const account = asObject(value);
  const id = asNumber(account?.id);
  const email = asString(account?.email);
  const createdAt = asString(account?.createdAt);
  if (id === null || email === null || createdAt === null) throw undocumentedResponse('account');

  const blob = asObject(account?.blob);
  const kinds = asArray(account?.keyRecordKinds) ?? [];

  return {
    id,
    email,
    displayName: asString(account?.displayName),
    // Defaulted rather than demanded: an older instance omits them, and a CLI
    // that refused to print an account over a missing allowance would be less
    // useful than one that says `member` and `0`.
    role: asString(account?.role) ?? 'member',
    dailyAiLimit: asNumber(account?.dailyAiLimit) ?? 0,
    aiUsedToday: asNumber(account?.aiUsedToday) ?? 0,
    suspendedAt: asString(account?.suspendedAt),
    createdAt,
    blobBytes: asNumber(blob?.sizeBytes),
    blobUpdatedAt: asString(blob?.updatedAt),
    keyRecordKinds: kinds.map((kind) => asString(kind)).filter((kind): kind is string => kind !== null),
  };
}

export function decodeAccountPage(value: JsonValue): AccountPageView {
  const body = asObject(value);
  const accounts = asArray(body?.accounts);
  const total = asNumber(body?.total);
  if (accounts === null || total === null) throw undocumentedResponse('account list');

  return {
    accounts: accounts.map(decodeAccount),
    total,
    limit: asNumber(body?.limit) ?? accounts.length,
    offset: asNumber(body?.offset) ?? 0,
  };
}

export function decodeSingleAccount(value: JsonValue): AccountView {
  const body = asObject(value);
  if (body?.account === undefined) throw undocumentedResponse('account');
  return decodeAccount(body.account);
}

export interface InviteView {
  id: number;
  email: string;
  displayName: string | null;
  role: string;
  dailyAiLimit: number;
  createdAt: string;
  expiresAt: string;
  status: string;
  redeemedAccountId: number | null;
}

export interface InvitePageView {
  invites: InviteView[];
  total: number;
  limit: number;
  offset: number;
}

/**
 * A freshly minted invite. The only decoded shape in this CLI that carries a
 * secret — and since M192 the secret arrives in one of two forms: a `link`,
 * when the instance knows where its client lives, or a raw `token` when it
 * does not. Exactly one of the two is present.
 */
export interface MintedInviteView {
  invite: InviteView;
  /** Whether the service mailed the invitation itself. Spec 02 makes this true. */
  emailed: boolean;
  link: string | null;
  token: string | null;
}

function decodeInvite(value: JsonValue): InviteView {
  const invite = asObject(value);
  const id = asNumber(invite?.id);
  const email = asString(invite?.email);
  const createdAt = asString(invite?.createdAt);
  const expiresAt = asString(invite?.expiresAt);
  if (id === null || email === null || createdAt === null || expiresAt === null) {
    throw undocumentedResponse('invite');
  }

  return {
    id,
    email,
    displayName: asString(invite?.displayName),
    role: asString(invite?.role) ?? 'member',
    dailyAiLimit: asNumber(invite?.dailyAiLimit) ?? 0,
    createdAt,
    expiresAt,
    status: asString(invite?.status) ?? 'pending',
    redeemedAccountId: asNumber(invite?.redeemedAccountId),
  };
}

export function decodeInvitePage(value: JsonValue): InvitePageView {
  const body = asObject(value);
  const invites = asArray(body?.invites);
  const total = asNumber(body?.total);
  if (invites === null || total === null) throw undocumentedResponse('invite list');

  return {
    invites: invites.map(decodeInvite),
    total,
    limit: asNumber(body?.limit) ?? invites.length,
    offset: asNumber(body?.offset) ?? 0,
  };
}

export function decodeMintedInvite(value: JsonValue): MintedInviteView {
  const body = asObject(value);
  const link = asString(body?.link);
  const token = asString(body?.token);
  // ONE of the two must be there. A response with neither has minted a
  // capability nobody can use, which is worse than either and must not print
  // as a success.
  if (body?.invite === undefined || (link === null && token === null)) throw undocumentedResponse('minted invite');
  return { invite: decodeInvite(body.invite), emailed: asBoolean(body?.emailed) ?? false, link, token };
}

/**
 * Renders the one-time capability, loudly.
 *
 * It is printed on its own line with nothing after it, so a copy-paste picks
 * up the link and not a trailing word. The warning is above rather than below
 * it: an operator who scrolls stops reading once they have the value.
 *
 * THE SERVICE DECIDES THE FORM, not this CLI. It returns a `link` when it knows
 * where its client lives and a raw `token` when it does not, and building a
 * link here from a guessed base URL is exactly how an operator ends up pasting
 * one that goes nowhere.
 */
export function formatMintedInvite(minted: MintedInviteView): string {
  const capability = minted.link ?? minted.token ?? '';
  const header = [
    `Invite ${minted.invite.id} for ${minted.invite.email}.`,
    `Expires ${minted.invite.expiresAt}. It creates ONE account, as ${minted.invite.role}, with ${minted.invite.dailyAiLimit} AI requests a day.`,
  ];

  // MAILED MEANS THE OPERATOR NEEDS NOTHING ELSE, so the capability is not
  // printed: a link in a terminal is a link in a scrollback buffer, and the
  // person it is for already has it.
  if (minted.emailed) return [...header, '', `An invitation was mailed to ${minted.invite.email}.`].join('\n');

  return [
    ...header,
    '',
    'This instance sends no mail, so give the link below to the person yourself.',
    'It is shown once and is not stored. If you lose it, resend the invite.',
    '',
    capability,
  ].join('\n');
}

export function formatInviteTable(page: InvitePageView): string {
  if (page.invites.length === 0) return 'No invites.';

  const header = `${pad('ID', 6)}${pad('EMAIL', 36)}${pad('EXPIRES', 26)}${pad('STATUS', 12)}ACCOUNT`;
  const rows = page.invites.map((invite) => {
    const account = invite.redeemedAccountId === null ? '—' : String(invite.redeemedAccountId);
    return `${pad(String(invite.id), 6)}${pad(invite.email, 36)}${pad(invite.expiresAt, 26)}${pad(invite.status, 12)}${account}`;
  });
  const shown = page.offset + page.invites.length;
  return [header, ...rows, '', `${page.invites.length} of ${page.total} invites (through ${shown}).`].join('\n');
}

/** `POST /v1/admin/accounts/:id/reset-mail` — whether a letter went, and the link when none did. */
export interface ResetMailView {
  emailed: boolean;
  link: string | null;
}

export function decodeResetMail(value: JsonValue): ResetMailView {
  const body = asObject(value);
  const emailed = asBoolean(body?.emailed);
  if (emailed === null) throw undocumentedResponse('reset mail');
  return { emailed, link: asString(body?.link) };
}

export function decodeStats(value: JsonValue): StatsView {
  const stats = asObject(asObject(value)?.stats);
  const accounts = asNumber(stats?.accounts);
  if (stats === null || accounts === null) throw undocumentedResponse('stats');

  return {
    accounts,
    accountsWithBlob: asNumber(stats.accountsWithBlob) ?? 0,
    blobVersions: asNumber(stats.blobVersions) ?? 0,
    keyRecords: asNumber(stats.keyRecords) ?? 0,
    blobBytes: asNumber(stats.blobBytes) ?? 0,
  };
}

export function decodeHandshake(value: JsonValue): HandshakeView {
  const body = asObject(value);
  const protocolVersion = asNumber(body?.protocolVersion);
  const envelopeVersion = asNumber(body?.envelopeVersion);
  const serviceVersion = asString(body?.serviceVersion);
  if (protocolVersion === null || envelopeVersion === null || serviceVersion === null) {
    throw undocumentedResponse('health');
  }
  // Optional on the wire, so absent is a `null` here rather than a refusal:
  // demanding it would make this CLI unable to talk to a service older than
  // protocol 2, which is the opposite of what a diagnostic tool is for.
  return { protocolVersion, envelopeVersion, serviceVersion, instanceName: asString(asObject(body?.instance)?.name) };
}

/** Bytes as something an operator can read at a glance. Binary units, because that is what a disk quota is in. */
export function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB'];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${units[unit]}`;
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : value.padEnd(width, ' ');
}

export function formatAccountTable(page: AccountPageView): string {
  if (page.accounts.length === 0) return 'No accounts.';

  const header = `${pad('ID', 6)}${pad('EMAIL', 32)}${pad('NAME', 20)}${pad('ROLE', 8)}${pad('AI', 12)}${pad('BLOB', 10)}STANDING`;
  const rows = page.accounts.map((account) => {
    const blob = account.blobBytes === null ? '—' : formatBytes(account.blobBytes);
    // An allowance of 0 is a dash rather than `0/0`: the account cannot use the
    // proxy at all, which reads differently from one that has spent its day.
    const ai = account.dailyAiLimit === 0 ? '—' : `${account.aiUsedToday}/${account.dailyAiLimit}`;
    const standing = account.suspendedAt === null ? 'active' : 'suspended';
    return [
      pad(String(account.id), 6),
      pad(account.email, 32),
      pad(account.displayName ?? '—', 20),
      pad(account.role, 8),
      pad(ai, 12),
      pad(blob, 10),
      standing,
    ].join('');
  });
  const shown = page.offset + page.accounts.length;
  return [header, ...rows, '', `${page.accounts.length} of ${page.total} accounts (through ${shown}).`].join('\n');
}

export function formatAccountDetail(account: AccountView): string {
  return [
    `id              ${account.id}`,
    `email           ${account.email}`,
    `name            ${account.displayName ?? '—'}`,
    `role            ${account.role}`,
    `ai today        ${account.aiUsedToday} of ${account.dailyAiLimit}`,
    `standing        ${account.suspendedAt === null ? 'active' : `suspended ${account.suspendedAt}`}`,
    `created         ${account.createdAt}`,
    `blob            ${account.blobBytes === null ? 'none' : `${formatBytes(account.blobBytes)}, updated ${account.blobUpdatedAt ?? 'unknown'}`}`,
    `key records     ${account.keyRecordKinds.length === 0 ? 'none' : account.keyRecordKinds.join(', ')}`,
  ].join('\n');
}

export function formatStats(stats: StatsView): string {
  return [
    `accounts            ${stats.accounts}`,
    `  with a blob       ${stats.accountsWithBlob}`,
    `blob versions       ${stats.blobVersions}`,
    `key records         ${stats.keyRecords}`,
    `stored ciphertext   ${formatBytes(stats.blobBytes)}`,
  ].join('\n');
}
