/**
 * The password-reset letter, as a PURE FUNCTION of its inputs.
 *
 * Same shape and the same reasoning as `invite-message.ts`: the link is the
 * only thing that can be silently wrong, so it is built here and asserted by
 * string comparison, with no HTTP anywhere near the test. The escaping, the
 * HTML shell and the trailing-slash handling are shared with that module
 * rather than copied, so the two letters cannot drift apart in their framing.
 *
 * WHAT THIS LETTER IS NOT. It does not carry a credential that changes
 * anything by itself. `POST /v1/auth/reset/open` writes nothing to the
 * account: it hands back the recovery code the server already holds in escrow,
 * and the client then runs the ordinary rotation ceremony with it
 * (PROTOCOL.md §5.12). The token is still a capability worth protecting, which
 * is why it travels in the fragment and is never logged, but redeeming it is
 * not a password change.
 */
import type { InstanceLanguage } from '../protocol.js';
import { renderHtml, type BuiltMessage } from './invite-message.js';
import { MAIL_STRINGS } from './strings.js';

export interface ResetMessageInput {
  /** Where the openplate client lives, from `CLIENT_BASE_URL`. */
  clientBaseUrl: string;
  /** This service's externally reachable base URL, from `SERVER_PUBLIC_URL`. */
  serverPublicUrl: string;
  /** The plaintext `sr_` reset token. A credential, see the module header. */
  resetToken: string;
  language: InstanceLanguage;
}

/**
 * The link the person opens, in the fragment for exactly the reason
 * `buildInviteLink` gives: a fragment is never sent to any server, so the
 * token stays out of history, `Referer` headers and access logs.
 *
 * The path is `/reset` rather than `/join`, and both values are encoded.
 */
export function buildResetLink(parts: { clientBaseUrl: string; serverPublicUrl: string; resetToken: string }): string {
  const client = parts.clientBaseUrl.replace(/\/+$/, '');
  const server = encodeURIComponent(parts.serverPublicUrl.replace(/\/+$/, ''));
  const token = encodeURIComponent(parts.resetToken);
  return `${client}/reset#server=${server}&token=${token}`;
}

/**
 * PARAGRAPH ORDER IS FIXED BY THE SPEC: greeting, intro, open, link, expiry,
 * ignore, help. `ignore` sits after the facts about the link and before the
 * help, because a person who did not ask for this reads down to the first
 * sentence that tells them to stop.
 */
export function buildResetMessage(input: ResetMessageInput): BuiltMessage {
  const strings = MAIL_STRINGS[input.language].reset;
  const link = buildResetLink({
    clientBaseUrl: input.clientBaseUrl,
    serverPublicUrl: input.serverPublicUrl,
    resetToken: input.resetToken,
  });

  // Built once and used by both parts, so the two can never disagree about
  // what the reader was told.
  const before = [strings.greeting, strings.intro, strings.open];
  const after = [strings.expiry, strings.ignore, strings.help];

  return {
    subject: strings.subject,
    text: [...before, link, ...after].join('\n\n'),
    html: renderHtml({ language: input.language, before, after, link }),
    link,
  };
}
