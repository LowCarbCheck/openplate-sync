/**
 * Mail transport abstraction — relocated from the openplate app in M128 spec
 * 02, because this service is now the only thing that sends mail (signup
 * verification and auth reset).
 *
 * Three implementations, selected at boot by `selectTransport`, highest
 * precedence first:
 *
 * - **PigeonTransport** — a thin `fetch`-based HTTP adapter that POSTs to a
 *   pigeon email service (`POST {baseUrl}/v1/emails`, bearer-auth). Selected
 *   when both `PIGEON_API_KEY` and `PIGEON_BASE_URL` are set: the hosted-
 *   instance path. It replicates pigeon's HTTP contract BY HAND with the
 *   built-in global `fetch`. The `@sprqvntrs/pigeon` SDK is deliberately not
 *   a dependency and never will be: this repo ships publicly, and a
 *   private-registry dependency would make it un-buildable by anyone outside
 *   our org. That invariant is enforced by a verification grep.
 * - **SmtpTransport** — sends over SMTP via `nodemailer` (public registry,
 *   likewise no `@sprqvntrs/*`). Selected when `SMTP_HOST` is set and pigeon
 *   is not. This is the transport most self-hosters will use.
 * - **ConsoleTransport** (default) — logs a clearly delimited block including
 *   the action URL. This is the no-SMTP self-host path: an admin reads the
 *   verification/reset link straight out of `docker logs`. It means a fresh
 *   instance works with zero mail configuration.
 *
 * FAIL-SOFT, ALWAYS: `send` returns a `MailResult` and never throws. A dead
 * SMTP relay must not turn a successful signup into a 500 after the account
 * row is already committed. Callers surface "check your email" either way and
 * the server logs the failure.
 *
 * SCRUBBING: no path here logs the API key, the Authorization header, an SMTP
 * password, or a response body that could echo any of them — only a status
 * code or an error message string.
 */
import nodemailer from 'nodemailer';
import type { EmailSettings } from '../config.js';
import type { Logger } from '../logger.js';
import { asObject, asString, type JsonValue } from '../lib/json.js';

export interface MailMessage {
  to: string;
  subject: string;
  /** Plain-text body — always provided; the console transport prints exactly this. */
  text: string;
  /** Optional HTML alternative. */
  html?: string;
}

export interface MailResult {
  success: boolean;
  messageId?: string;
  error?: string;
}

export interface MailTransport {
  /** Short label for logs and tests, e.g. `console` or `smtp`. */
  readonly name: string;
  send(message: MailMessage): Promise<MailResult>;
}

// ── Console transport (default, no-SMTP self-host path) ──────────────────────

export function createConsoleTransport(logger: Logger): MailTransport {
  return {
    name: 'console',
    async send(message) {
      // Deliberately loud and copy-pasteable: a self-hoster running without
      // SMTP grabs the verification/reset URL from stdout.
      logger.info(
        [
          '',
          '──────────────────────────────────────────────────────────────',
          ' openplate-sync email (console transport — no SMTP configured)',
          `   To:      ${message.to}`,
          `   Subject: ${message.subject}`,
          '   Body:',
          message.text
            .split('\n')
            .map((line) => `     ${line}`)
            .join('\n'),
          '──────────────────────────────────────────────────────────────',
          '',
        ].join('\n'),
      );
      return { success: true, messageId: `console-${Date.now()}` };
    },
  };
}

// ── SMTP transport (nodemailer) ──────────────────────────────────────────────

export interface SmtpTransportConfig {
  host: string;
  port: number;
  user: string;
  password: string;
  secure: boolean;
  from: string;
}

export function createSmtpTransport(config: SmtpTransportConfig, logger: Logger): MailTransport {
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    // Only attach auth when credentials are supplied — some relays (a local
    // Postfix, say) accept unauthenticated submission from trusted hosts.
    auth: config.user ? { user: config.user, pass: config.password } : undefined,
  });

  return {
    name: 'smtp',
    async send(message) {
      try {
        const info = await transporter.sendMail({
          from: config.from,
          to: message.to,
          subject: message.subject,
          text: message.text,
          html: message.html,
        });
        return { success: true, messageId: info.messageId };
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown SMTP error';
        // Never let the underlying error object (which may echo credentials)
        // escape beyond a scrubbed message string.
        logger.error('SMTP send failed', { error: errorMessage });
        return { success: false, error: errorMessage };
      }
    },
  };
}

// ── Pigeon HTTP transport (hosted-instance configuration) ────────────────────

/** Guards against a hung pigeon wedging a request: an unresolved send is aborted and treated as a fail-soft timeout. */
const PIGEON_REQUEST_TIMEOUT_MS = 10_000;

export interface PigeonTransportConfig {
  apiKey: string;
  baseUrl: string;
  from: string;
}

/** JSON body of `POST {baseUrl}/v1/emails` — pigeon's contract, hand-transcribed. */
interface PigeonSendBody {
  from: string;
  /** Pigeon expects an array of recipients even for a single address. */
  to: string[];
  subject: string;
  text: string;
  html?: string;
}

/**
 * Maps a thrown/rejected fetch to a scrubbed, log-safe message. An abort is
 * always the timeout above; every other error is reduced to its `message`
 * (undici's is `fetch failed` — no key, header, or recipient).
 */
function describePigeonError(cause: unknown): string {
  if (cause instanceof Error && cause.name === 'AbortError') {
    return 'pigeon request timed out';
  }
  if (cause instanceof Error) {
    return cause.message;
  }
  return 'unknown pigeon error';
}

export function createPigeonTransport(config: PigeonTransportConfig, logger: Logger): MailTransport {
  // Strip trailing slashes once so the join below never doubles the separator.
  const endpoint = `${config.baseUrl.replace(/\/+$/, '')}/v1/emails`;

  return {
    name: 'pigeon',
    async send(message) {
      const controller = new AbortController();
      const timeout: ReturnType<typeof setTimeout> = setTimeout(() => controller.abort(), PIGEON_REQUEST_TIMEOUT_MS);

      const body: PigeonSendBody = {
        from: config.from,
        to: [message.to],
        subject: message.subject,
        text: message.text,
      };
      if (message.html) body.html = message.html;

      try {
        const response = await fetch(endpoint, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${config.apiKey}`,
            'Content-Type': 'application/json',
            Accept: 'application/json',
          },
          body: JSON.stringify(body),
          signal: controller.signal,
        });

        if (!response.ok) {
          // Status only — never the response body, which could echo the key.
          const errorMessage = `pigeon send failed: HTTP ${response.status}`;
          logger.error('pigeon send failed', { status: response.status });
          return { success: false, error: errorMessage };
        }

        const payload: JsonValue = await response.json();
        const messageId = asString(asObject(payload)?.id) ?? undefined;
        return { success: true, messageId };
      } catch (error) {
        const errorMessage = describePigeonError(error);
        logger.error('pigeon send failed', { error: errorMessage });
        return { success: false, error: errorMessage };
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}

// ── Transport selection ──────────────────────────────────────────────────────

/**
 * Picks the transport from config: pigeon (both key + base URL set) → SMTP
 * (`SMTP_HOST` set) → console. Exported so tests can assert selection without
 * booting anything.
 */
export function selectTransport(settings: EmailSettings, logger: Logger): MailTransport {
  if (settings.pigeon.apiKey && settings.pigeon.baseUrl) {
    return createPigeonTransport(
      { apiKey: settings.pigeon.apiKey, baseUrl: settings.pigeon.baseUrl, from: settings.from },
      logger,
    );
  }
  if (settings.smtp.host) {
    return createSmtpTransport(
      {
        host: settings.smtp.host,
        port: settings.smtp.port,
        user: settings.smtp.user,
        password: settings.smtp.password,
        secure: settings.smtp.secure,
        from: settings.from,
      },
      logger,
    );
  }
  return createConsoleTransport(logger);
}
