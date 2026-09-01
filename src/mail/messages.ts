/**
 * The two emails this service sends, as PURE builders over
 * `(clientBaseUrl, rawToken)`. No transport, no config object, no clock —
 * so the copy and the link shape are unit-testable directly.
 *
 * THE RESET COPY IS A SAFETY FEATURE, NOT MARKETING. In a zero-knowledge
 * design an email reset can restore LOGIN and nothing else: the server never
 * held a key, so it cannot re-wrap the data-encryption key for a new
 * passphrase. Only the recovery code can do that, on the client. A user who
 * resets without it keeps their account and loses access to everything in it,
 * permanently. The message below says so before they click, in those words —
 * a user who discovers this afterwards has already lost the data.
 *
 * Links point at the CLIENT app (`CLIENT_BASE_URL`), not at this service.
 * A sync service has no UI; the client redeems the token by calling back into
 * `/v1/auth/*`.
 */
import type { MailMessage } from './transport.js';

/** Client routes the emailed links land on. The client owns these paths; changing one is a coordinated change. */
export const VERIFY_EMAIL_PATH = '/verify-email';
export const RESET_PATH = '/reset-passphrase';

function buildActionUrl(input: { clientBaseUrl: string; path: string; token: string }): string {
  const base = input.clientBaseUrl.replace(/\/+$/, '');
  return `${base}${input.path}?token=${encodeURIComponent(input.token)}`;
}

export function buildVerificationEmail(input: { to: string; clientBaseUrl: string; token: string }): MailMessage {
  const url = buildActionUrl({ clientBaseUrl: input.clientBaseUrl, path: VERIFY_EMAIL_PATH, token: input.token });
  return {
    to: input.to,
    subject: 'Confirm your openplate sync account',
    text: [
      'Confirm your email address to finish setting up sync.',
      '',
      url,
      '',
      'This link is valid for 24 hours.',
      '',
      "If you didn't create an account, you can ignore this message. Nothing was set up.",
    ].join('\n'),
  };
}

export function buildResetEmail(input: { to: string; clientBaseUrl: string; token: string }): MailMessage {
  const url = buildActionUrl({ clientBaseUrl: input.clientBaseUrl, path: RESET_PATH, token: input.token });
  return {
    to: input.to,
    subject: 'Reset your openplate sync passphrase',
    text: [
      'You asked to reset the passphrase for your openplate sync account.',
      '',
      url,
      '',
      'This link is valid for 1 hour.',
      '',
      'READ THIS BEFORE YOU CONTINUE.',
      '',
      'Your data is encrypted with a key only your passphrase and your recovery',
      'code can unlock. We do not have that key and cannot recover it for you.',
      '',
      'If you have your recovery code, this link restores your login and your app',
      'will use the code to keep your data.',
      '',
      'If you do NOT have your recovery code, this link restores your login only.',
      'Everything already synced becomes permanently unreadable, by you and by us.',
      '',
      "If you didn't request this, ignore this message. Nothing has changed yet.",
    ].join('\n'),
  };
}
