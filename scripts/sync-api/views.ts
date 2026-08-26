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
  email: string;
  createdAt: string;
  emailVerifiedAt: string | null;
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
  verifiedAccounts: number;
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
  const email = asString(account?.email);
  const createdAt = asString(account?.createdAt);
  if (id === null || email === null || createdAt === null) throw undocumentedResponse('account');

  const blob = asObject(account?.blob);
  const kinds = asArray(account?.keyRecordKinds) ?? [];

  return {
    id,
    email,
    createdAt,
    emailVerifiedAt: asString(account?.emailVerifiedAt),
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

export function decodeStats(value: JsonValue): StatsView {
  const stats = asObject(asObject(value)?.stats);
  const accounts = asNumber(stats?.accounts);
  if (stats === null || accounts === null) throw undocumentedResponse('stats');

  return {
    accounts,
    verifiedAccounts: asNumber(stats.verifiedAccounts) ?? 0,
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

  const header = `${pad('ID', 6)}${pad('EMAIL', 36)}${pad('CREATED', 26)}${pad('BLOB', 12)}KEY RECORDS`;
  const rows = page.accounts.map((account) => {
    const blob = account.blobBytes === null ? '—' : formatBytes(account.blobBytes);
    const kinds = account.keyRecordKinds.length === 0 ? '—' : account.keyRecordKinds.join(',');
    return `${pad(String(account.id), 6)}${pad(account.email, 36)}${pad(account.createdAt, 26)}${pad(blob, 12)}${kinds}`;
  });
  const shown = page.offset + page.accounts.length;
  return [header, ...rows, '', `${page.accounts.length} of ${page.total} accounts (through ${shown}).`].join('\n');
}

export function formatAccountDetail(account: AccountView): string {
  return [
    `id              ${account.id}`,
    `email           ${account.email}`,
    `created         ${account.createdAt}`,
    `email verified  ${account.emailVerifiedAt ?? 'never'}`,
    `blob            ${account.blobBytes === null ? 'none' : `${formatBytes(account.blobBytes)}, updated ${account.blobUpdatedAt ?? 'unknown'}`}`,
    `key records     ${account.keyRecordKinds.length === 0 ? 'none' : account.keyRecordKinds.join(', ')}`,
  ].join('\n');
}

export function formatStats(stats: StatsView): string {
  return [
    `accounts            ${stats.accounts}`,
    `  email verified    ${stats.verifiedAccounts}`,
    `  with a blob       ${stats.accountsWithBlob}`,
    `blob versions       ${stats.blobVersions}`,
    `key records         ${stats.keyRecords}`,
    `stored ciphertext   ${formatBytes(stats.blobBytes)}`,
  ].join('\n');
}
