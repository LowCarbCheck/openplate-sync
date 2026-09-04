/**
 * The mail PORT — what this service needs from a mailer, and nothing about how
 * one is built.
 *
 * TWO LETTERS, EVER. An invitation, and a password reset. That bound is the
 * design: a service that can send arbitrary mail grows a notification system,
 * and a notification system needs an address for people who did not ask for
 * one. These two go to an address an operator typed (the invite) or to an
 * address that is already the account's own identity (the reset).
 *
 * WHY AN INTERFACE AND NOT AN HTTP CLIENT. Everything upstream of the
 * transport has to be testable without one: the admin invite route has real
 * branching (mail configured or not, send succeeded or not, and what the
 * response says in each case), and none of it should require a mail server to
 * exercise. This is the seam; the messages themselves are built by
 * `invite-message.ts` and `reset-message.ts`, which are pure. An instance with
 * no mail configured gets {@link createNoopMailer}.
 *
 * NOTHING HERE THROWS ON A FAILED SEND, and that is a contract rather than an
 * omission. `POST /v1/auth/reset/request` answers `202` whether or not the
 * account exists; if a send failure could turn that into a `500`, the status
 * code would become the enumeration oracle the endpoint exists to avoid. An
 * implementation logs its own failures and resolves.
 */
import type { InstanceLanguage, IsoTimestamp } from '../protocol.js';
import type { Logger } from '../logger.js';
import { buildInviteMessage } from './invite-message.js';
import { buildResetMessage } from './reset-message.js';

export interface SendInviteInput {
  /** The address the invitation goes to — the invite's own `email`, never one from a request body. */
  email: string;
  /** What the operator typed as the person's name, or `null`. */
  displayName: string | null;
  /** The raw `si_` token. Held for as long as one letter takes to build, and never logged. */
  inviteToken: string;
  expiresAt: IsoTimestamp;
}

export interface SendResetInput {
  /** The account's own address. */
  email: string;
  /** The raw `sr_` token. Held for as long as one letter takes to build, and never logged. */
  resetToken: string;
  expiresAt: IsoTimestamp;
}

export interface Mailer {
  sendInvite(input: SendInviteInput): Promise<void>;
  sendReset(input: SendResetInput): Promise<void>;
}

/**
 * The mailer an instance with no mail configuration gets: it accepts both
 * letters and sends neither.
 *
 * SILENCE HERE IS NOT A DROPPED MESSAGE. An instance without mail hands the
 * operator the link instead — `POST /v1/admin/invites` returns it, and the
 * `sync-api` CLI prints it — so the capability always reaches somebody. What
 * this implementation removes is the alternative: a hard failure that would
 * make a self-hosted instance unusable until its owner stood up a relay, which
 * is the instruction ADR-0004 refused to give and ADR-0005 still refuses.
 */
export function createNoopMailer(): Mailer {
  return {
    async sendInvite(): Promise<void> {
      // Deliberately nothing. See the doc above.
    },
    async sendReset(): Promise<void> {
      // Deliberately nothing. See the doc above.
    },
  };
}

/**
 * 15 s, and NO RETRIES. Every call site already treats a failed send as
 * survivable: the row is written before the send, and the response says
 * `emailed: false` with a link that still works. A retry loop here would be
 * duplicate-email machinery bolted onto a path that is allowed to fail. It is
 * an option rather than a constant because the only caller that needs a
 * different value is a test proving the bound exists; an operator has nothing
 * to tune here.
 */
export const DEFAULT_MAIL_API_TIMEOUT_MS = 15_000;

/** What an operator configured, already validated all-or-nothing by `config.ts`. */
export interface HttpMailConfig {
  url: string;
  apiKey: string;
  from: string;
}

export interface CreateHttpMailerOptions {
  mail: HttpMailConfig;
  /** The two base URLs a link is built from. Required whenever mail is configured (`config.ts`). */
  links: { clientBaseUrl: string; serverPublicUrl: string };
  /** Which language both letters are written in (`INSTANCE_LANGUAGE`). */
  language: InstanceLanguage;
  logger: Logger;
  timeoutMs?: number;
}

/** One message, ready to post. Internal: nothing outside this module builds one. */
interface OutgoingMail {
  to: string;
  subject: string;
  text: string;
  html: string;
}

/**
 * Posts a Resend-compatible payload to the configured mail API.
 *
 * ONE ADAPTER, NOT ONE PER PROVIDER. Resend and our own pigeon service differ
 * in exactly two ways: the path (`/emails` against `/v1/emails`) and whether
 * `to` may be a bare string. The path is the operator's whole URL, so it never
 * reaches this code; `to` is ALWAYS sent as a one-element array, which Resend
 * accepts and pigeon requires. That is the entire compatibility story, and it
 * is why there is no provider enum and no branch below.
 *
 * GLOBAL `fetch`, NOT UNDICI. Node's `fetch` IS undici, so importing the
 * package would buy nothing and cost an entry on `scripts/build.ts`'s
 * `external` list. This adapter adds no dependency at all, which for a public
 * repo whose every dependency is a supply-chain surface a self-hoster inherits
 * is the point.
 */
async function postMail(input: { mail: HttpMailConfig; timeoutMs: number; outgoing: OutgoingMail }): Promise<void> {
  const response = await fetch(input.mail.url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${input.mail.apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: input.mail.from,
      // An array even for one recipient: see the header.
      to: [input.outgoing.to],
      subject: input.outgoing.subject,
      text: input.outgoing.text,
      html: input.outgoing.html,
    }),
    // No retry, and no idempotency key: with nothing retrying, there is no
    // duplicate for a key to suppress. See `DEFAULT_MAIL_API_TIMEOUT_MS`.
    signal: AbortSignal.timeout(input.timeoutMs),
  });

  // THE BODY IS DISCARDED WITHOUT BEING READ, and that is a privacy decision
  // rather than a tidiness one. Both Resend and pigeon echo the request back
  // inside an error body — the recipient address and the subject, and any
  // provider might one day echo the html, which carries the token. Cancelling
  // rather than reading means there is no string in scope for a later
  // `${...}` to put into a message or a log.
  await response.body?.cancel();

  if (!response.ok) {
    // THE STATUS CODE, AND NOTHING ELSE. Not `statusText`, which some
    // providers set from their own error text; not the body; not the URL,
    // which is where a hosted API's credential sometimes ends up as a query
    // parameter.
    throw new Error(`mail API responded ${response.status}`);
  }
}

/**
 * The real mailer: builds each letter with the pure builders and posts it.
 *
 * A FAILED SEND THROWS OUT OF HERE, deliberately, and the CALL SITE decides
 * what that means. The admin invite route answers `201 emailed: false` with a
 * link that still works; `POST /v1/auth/reset/request` answers `202` either
 * way, because letting a send failure change its status code would make that
 * status the enumeration oracle the endpoint exists to avoid. Both log the
 * failure against a row id.
 *
 * NOTHING HERE LOGS A RECIPIENT, A SUBJECT, A BODY OR A LINK. The link carries
 * a token, so it is a credential; the recipient address is personal data held
 * for one send. This module logs that a send was attempted and its outcome,
 * with no argument that could carry either.
 */
export function createHttpMailer(options: CreateHttpMailerOptions): Mailer {
  const timeoutMs = options.timeoutMs ?? DEFAULT_MAIL_API_TIMEOUT_MS;
  const { language, links, logger, mail } = options;

  return {
    async sendInvite(input: SendInviteInput): Promise<void> {
      const message = buildInviteMessage({
        clientBaseUrl: links.clientBaseUrl,
        serverPublicUrl: links.serverPublicUrl,
        inviteToken: input.inviteToken,
        expiresAt: input.expiresAt,
        language,
      });
      await postMail({
        mail,
        timeoutMs,
        outgoing: { to: input.email, subject: message.subject, text: message.text, html: message.html },
      });
      logger.info('Invitation mailed');
    },

    async sendReset(input: SendResetInput): Promise<void> {
      const message = buildResetMessage({
        clientBaseUrl: links.clientBaseUrl,
        serverPublicUrl: links.serverPublicUrl,
        resetToken: input.resetToken,
        language,
      });
      await postMail({
        mail,
        timeoutMs,
        outgoing: { to: input.email, subject: message.subject, text: message.text, html: message.html },
      });
      logger.info('Password reset mailed');
    },
  };
}

/**
 * Picks the adapter from config. `null` is the copy-link-only deployment,
 * which is what most self-hosters run.
 */
export function createMailer(options: {
  mail: HttpMailConfig | null;
  links: { clientBaseUrl: string; serverPublicUrl: string } | null;
  language: InstanceLanguage;
  logger: Logger;
}): Mailer {
  // Both or neither: `config.ts` refuses to boot with mail configured and no
  // link bases, so this branch is a type narrowing rather than a policy.
  if (options.mail === null || options.links === null) return createNoopMailer();
  return createHttpMailer({
    mail: options.mail,
    links: options.links,
    language: options.language,
    logger: options.logger,
  });
}
