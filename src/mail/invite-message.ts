/**
 * The invitation, as a PURE FUNCTION of its inputs.
 *
 * WHY THE MESSAGE IS BUILT NOWHERE NEAR THE TRANSPORT. The one thing that can
 * actually be wrong here is the link: a mistyped separator, a missing
 * `encodeURIComponent`, a base URL with a trailing slash doubling into `//`.
 * Every one of those produces a message that sends perfectly and does not
 * work, and none is observable from a test that mocks a mail client and
 * asserts it was called. Separating the builder means the link is checked by
 * string comparison, with no HTTP anywhere near the test.
 *
 * THE TOKEN IS IN THE LINK, SO THE LINK IS A CREDENTIAL. It must never be
 * logged. `mailer.ts` logs an invite id and nothing else, and this module
 * returns a value rather than performing an effect precisely so there is no
 * temptation to log what it built.
 *
 * PLAIN TEXT FIRST, MINIMAL HTML SECOND. The plain part is not a fallback, it
 * is what a lot of people actually see, and a mail with a bare "click here"
 * whose href is invisible is indistinguishable from phishing. Both parts carry
 * the full URL as readable text.
 *
 * Ported in substance from `openplate-gateway/src/mail/invite-message.ts`,
 * whose reasoning holds unchanged; the copy is the M192 letter and the link
 * grammar is this service's own.
 */
import type { InstanceLanguage } from '../protocol.js';
import { MAIL_STRINGS, fill, formatExpiryDate } from './strings.js';

export interface InviteMessageInput {
  /** Where the openplate client lives, from `CLIENT_BASE_URL`. */
  clientBaseUrl: string;
  /** This service's externally reachable base URL, from `SERVER_PUBLIC_URL`. */
  serverPublicUrl: string;
  /** The plaintext `si_` invite token. A credential, see the module header. */
  inviteToken: string;
  expiresAt: string;
  /**
   * The instance's configured language (`INSTANCE_LANGUAGE`).
   *
   * An INPUT, not a module-scope read, for the same reason everything else
   * here is: this builder stays a pure function of its arguments, so both
   * languages are asserted by string comparison with no environment and no
   * mail API anywhere near the test.
   */
  language: InstanceLanguage;
}

export interface BuiltMessage {
  subject: string;
  text: string;
  html: string;
  /** Returned separately so a caller can show the same link in an admin response. */
  link: string;
}

/** Drops trailing slashes so the join below never produces `//`. */
function stripTrailingSlashes(value: string): string {
  return value.replace(/\/+$/, '');
}

/**
 * The link the invited person opens.
 *
 * THE FRAGMENT, NEVER THE QUERY STRING. The token is a live capability that
 * creates an account. A query string carries it into the browser's history,
 * into the `Referer` of the next request the page makes, and into the access
 * log of every server the link passes on its way. A fragment is never sent to
 * any server at all, which is the whole reason the grammar is
 * `/join#server=...&invite=si_...`.
 *
 * BOTH VALUES ARE ENCODED. The server URL obviously: it is a URL inside
 * another URL's fragment, and an unencoded `&` in it would silently truncate
 * everything after. The token less obviously: it is base64url, whose alphabet
 * happens to be safe today, and relying on that means the day the token format
 * changes the link breaks for everybody at once.
 */
export function buildInviteLink(parts: {
  clientBaseUrl: string;
  serverPublicUrl: string;
  inviteToken: string;
}): string {
  const client = stripTrailingSlashes(parts.clientBaseUrl);
  const server = encodeURIComponent(stripTrailingSlashes(parts.serverPublicUrl));
  const invite = encodeURIComponent(parts.inviteToken);
  return `${client}/join#server=${server}&invite=${invite}`;
}

/**
 * Minimal escaping for the values interpolated into the HTML part.
 *
 * Not a general-purpose sanitiser and it does not need to be: the only sinks
 * are element text and an `href` this module built itself.
 */
export function escapeHtml(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/**
 * Wraps the paragraphs in the one HTML shell both letters share, with the link
 * in the SAME position it occupies in the text part.
 *
 * Two parts that ordered their paragraphs differently would be two letters,
 * and the one a given reader sees depends on their mail client. `before` and
 * `after` are named rather than a single list with a marker in it so the
 * position cannot drift.
 *
 * The link is rendered as its own URL rather than as "click here": a bare
 * anchor whose target is invisible is exactly what a phishing mail looks like,
 * and the plain part shows the same string.
 */
export function renderHtml(input: {
  language: InstanceLanguage;
  before: string[];
  after: string[];
  link: string;
}): string {
  const paragraph = (value: string): string => `<p>${escapeHtml(value)}</p>`;
  return [
    '<!doctype html>',
    `<html lang="${input.language}"><body style="font-family:system-ui,sans-serif;line-height:1.5;color:#111">`,
    ...input.before.map(paragraph),
    `<p style="word-break:break-all"><a href="${escapeHtml(input.link)}">${escapeHtml(input.link)}</a></p>`,
    ...input.after.map(paragraph),
    '</body></html>',
  ].join('\n');
}

/**
 * PARAGRAPH ORDER IS FIXED BY THE SPEC: greeting, invited, open, link, expiry,
 * password, help. The link sits between the instruction to open it and the
 * facts about it, which is where a reader looks for it.
 */
export function buildInviteMessage(input: InviteMessageInput): BuiltMessage {
  const strings = MAIL_STRINGS[input.language].invite;
  const link = buildInviteLink({
    clientBaseUrl: input.clientBaseUrl,
    serverPublicUrl: input.serverPublicUrl,
    inviteToken: input.inviteToken,
  });
  const expiry = fill(strings.expiry, {
    date: formatExpiryDate({ expiresAt: input.expiresAt, language: input.language }),
  });

  // Built once and used by both parts, so the two can never disagree about
  // what the reader was told.
  const before = [strings.greeting, strings.invited, strings.open];
  const after = [expiry, strings.password, strings.help];

  return {
    subject: strings.subject,
    text: [...before, link, ...after].join('\n\n'),
    html: renderHtml({ language: input.language, before, after, link }),
    link,
  };
}
