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
import { asArray, asNumber, asObject, asString, type JsonValue } from '../../src/lib/json.js';
import { CliError } from './client.js';

export interface AccountView {
  id: number;
  handle: string;
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
  const handle = asString(account?.handle);
  const createdAt = asString(account?.createdAt);
  if (id === null || handle === null || createdAt === null) throw undocumentedResponse('account');

  const blob = asObject(account?.blob);
  const kinds = asArray(account?.keyRecordKinds) ?? [];

  return {
    id,
    handle,
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
  note: string | null;
  createdAt: string;
  expiresAt: string;
  redeemedAt: string | null;
  redeemedAccountId: number | null;
}

export interface InvitePageView {
  invites: InviteView[];
  total: number;
  limit: number;
  offset: number;
}

/** A freshly minted invite. The only decoded shape in this CLI that carries a secret. */
export interface MintedInviteView {
  invite: InviteView;
  token: string;
}

function decodeInvite(value: JsonValue): InviteView {
  const invite = asObject(value);
  const id = asNumber(invite?.id);
  const createdAt = asString(invite?.createdAt);
  const expiresAt = asString(invite?.expiresAt);
  if (id === null || createdAt === null || expiresAt === null) throw undocumentedResponse('invite');

  return {
    id,
    note: asString(invite?.note),
    createdAt,
    expiresAt,
    redeemedAt: asString(invite?.redeemedAt),
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
  const token = asString(body?.token);
  if (body?.invite === undefined || token === null) throw undocumentedResponse('minted invite');
  return { invite: decodeInvite(body.invite), token };
}

/**
 * Renders the one-time token, loudly.
 *
 * It is printed on its own line with nothing after it, so a copy-paste picks
 * up the token and not a trailing word. The warning is above rather than below
 * it: an operator who scrolls stops reading once they have the value.
 */
export function formatMintedInvite(minted: MintedInviteView, clientBaseUrl: string | null): string {
  const link = clientBaseUrl === null ? null : `${clientBaseUrl.replace(/\/+$/, '')}/settings/sync#invite=${minted.token}`;
  return [
    `Invite ${minted.invite.id} minted${minted.invite.note === null ? '' : ` for "${minted.invite.note}"`}.`,
    `Expires ${minted.invite.expiresAt}. It can create ONE account.`,
    '',
    'This token is shown once and is not stored. If you lose it, revoke the invite and mint another.',
    '',
    link === null ? minted.token : link,
  ].join('\n');
}

export function formatInviteTable(page: InvitePageView): string {
  if (page.invites.length === 0) return 'No invites.';

  const header = `${pad('ID', 6)}${pad('NOTE', 28)}${pad('EXPIRES', 26)}${pad('STATE', 12)}ACCOUNT`;
  const rows = page.invites.map((invite) => {
    const state = invite.redeemedAt === null ? 'open' : 'redeemed';
    const account = invite.redeemedAccountId === null ? '—' : String(invite.redeemedAccountId);
    return `${pad(String(invite.id), 6)}${pad(invite.note ?? '—', 28)}${pad(invite.expiresAt, 26)}${pad(state, 12)}${account}`;
  });
  const shown = page.offset + page.invites.length;
  return [header, ...rows, '', `${page.invites.length} of ${page.total} invites (through ${shown}).`].join('\n');
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
  return { protocolVersion, envelopeVersion, serviceVersion };
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

  const header = `${pad('ID', 6)}${pad('HANDLE', 36)}${pad('CREATED', 26)}${pad('BLOB', 12)}KEY RECORDS`;
  const rows = page.accounts.map((account) => {
    const blob = account.blobBytes === null ? '—' : formatBytes(account.blobBytes);
    const kinds = account.keyRecordKinds.length === 0 ? '—' : account.keyRecordKinds.join(',');
    return `${pad(String(account.id), 6)}${pad(account.handle, 36)}${pad(account.createdAt, 26)}${pad(blob, 12)}${kinds}`;
  });
  const shown = page.offset + page.accounts.length;
  return [header, ...rows, '', `${page.accounts.length} of ${page.total} accounts (through ${shown}).`].join('\n');
}

export function formatAccountDetail(account: AccountView): string {
  return [
    `id              ${account.id}`,
    `handle          ${account.handle}`,
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
