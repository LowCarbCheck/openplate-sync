/**
 * Mail transport selection and message content.
 *
 * Selection is asserted by NAME only — instantiating the pigeon and SMTP
 * transports is cheap and side-effect-free (no connection is opened until a
 * send), so the precedence rule can be checked without a network.
 *
 * The reset copy is asserted because it is a safety control, not marketing:
 * in a zero-knowledge design an email reset restores login and cannot restore
 * data, and a user who learns that afterwards has already lost it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { EmailSettings } from '../../src/config.js';
import { createSilentLogger } from '../../src/logger.js';
import { selectTransport } from '../../src/mail/transport.js';
import { buildResetEmail, buildVerificationEmail } from '../../src/mail/messages.js';

const logger = createSilentLogger();

function settings(overrides: Partial<EmailSettings> = {}): EmailSettings {
  return {
    from: 'openplate <noreply@example.test>',
    smtp: { host: '', port: 587, user: '', password: '', secure: false },
    pigeon: { apiKey: '', baseUrl: '' },
    ...overrides,
  };
}

test('with nothing configured, the console transport is selected', () => {
  // The zero-config self-host path: an admin reads the link out of the logs.
  assert.equal(selectTransport(settings(), logger).name, 'console');
});

test('SMTP is selected when a host is set', () => {
  assert.equal(
    selectTransport(
      settings({ smtp: { host: 'mail.example.test', port: 587, user: '', password: '', secure: false } }),
      logger,
    ).name,
    'smtp',
  );
});

test('pigeon outranks SMTP when both are configured', () => {
  const transport = selectTransport(
    settings({
      smtp: { host: 'mail.example.test', port: 587, user: '', password: '', secure: false },
      pigeon: { apiKey: 'ske_test', baseUrl: 'https://pigeon.example.test' },
    }),
    logger,
  );
  assert.equal(transport.name, 'pigeon');
});

test('pigeon needs BOTH the key and the base URL', () => {
  assert.equal(selectTransport(settings({ pigeon: { apiKey: 'ske_test', baseUrl: '' } }), logger).name, 'console');
  assert.equal(
    selectTransport(settings({ pigeon: { apiKey: '', baseUrl: 'https://pigeon.example.test' } }), logger).name,
    'console',
  );
});

test('the verification email links to the client app with an escaped token', () => {
  const message = buildVerificationEmail({
    to: 'person@example.test',
    clientBaseUrl: 'https://app.example.test/',
    token: 'a b+c',
  });
  assert.equal(message.to, 'person@example.test');
  assert.match(message.text, /https:\/\/app\.example\.test\/verify-email\?token=a%20b%2Bc/);
});

test('the reset email names the recovery code and the permanent consequence', () => {
  const message = buildResetEmail({
    to: 'person@example.test',
    clientBaseUrl: 'https://app.example.test',
    token: 'tok',
  });
  assert.match(message.text, /recovery code/i);
  assert.match(message.text, /permanently unreadable/i);
  assert.match(message.text, /https:\/\/app\.example\.test\/reset-passphrase\?token=tok/);
});
