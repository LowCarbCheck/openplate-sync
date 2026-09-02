/**
 * Config parsing — every assertion here is a boot that MUST fail rather than
 * a service that starts half-configured and takes real accounts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_SYNC_NOTICE_LENGTH, MIN_SERVER_SECRET_LENGTH, parseConfig } from '../../src/config.js';

const SECRET = 'x'.repeat(MIN_SERVER_SECRET_LENGTH);

function baseEnv(overrides: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  return {
    DATABASE_URL: 'postgres://user:pass@localhost:5432/db',
    SERVER_SECRET: SECRET,
    ...overrides,
  };
}

test('a minimal valid environment parses with sane defaults', () => {
  const config = parseConfig(baseEnv());
  assert.equal(config.port, 3000);
  assert.equal(config.signupMode, 'open');
  assert.equal(config.trustProxy, false);
  assert.equal(config.logLevel, 'info');
  // Both dark features are OFF unless an operator opts in. This is the
  // default every deployment runs on, and it is what makes shipping the
  // routes before anyone opts in safe (ADR-0002 / ADR-0003).
  assert.equal(config.sharingEnabled, false);
  assert.equal(config.researchEnabled, false);
});

test('a missing DATABASE_URL or SERVER_SECRET is fatal', () => {
  for (const key of ['DATABASE_URL', 'SERVER_SECRET']) {
    const env = baseEnv();
    delete env[key];
    assert.throws(() => parseConfig(env), new RegExp(key));
  }
});

test('a short SERVER_SECRET is fatal', () => {
  // The pepper derived from this is the only thing standing between a stolen
  // table and offline verification of guessed auth-hashes.
  assert.throws(() => parseConfig(baseEnv({ SERVER_SECRET: 'too-short' })), /SERVER_SECRET/);
});

test('SIGNUP_MODE accepts its three values and rejects anything else', () => {
  assert.equal(parseConfig(baseEnv({ SIGNUP_MODE: 'open' })).signupMode, 'open');
  assert.equal(parseConfig(baseEnv({ SIGNUP_MODE: 'invite' })).signupMode, 'invite');
  assert.equal(parseConfig(baseEnv({ SIGNUP_MODE: 'closed' })).signupMode, 'closed');
  // A typo must not silently mean "open".
  assert.throws(() => parseConfig(baseEnv({ SIGNUP_MODE: 'inviteonly' })), /SIGNUP_MODE/);
});

test('the removed SIGNUPS_OPEN is fatal rather than ignored', () => {
  // The direction matters more than the rejection. SIGNUPS_OPEN defaulted to
  // OPEN and is what has been holding the hosted instance shut; ignoring it
  // would let a deploy that lands before the env change silently reopen public
  // registration. Both spellings must throw, including the one an operator
  // used to mean "closed".
  assert.throws(() => parseConfig(baseEnv({ SIGNUPS_OPEN: 'false' })), /SIGNUP_MODE/);
  assert.throws(() => parseConfig(baseEnv({ SIGNUPS_OPEN: 'true' })), /SIGNUP_MODE/);
});

test('TRUST_PROXY accepts a hop count as well as a boolean', () => {
  assert.equal(parseConfig(baseEnv({ TRUST_PROXY: '1' })).trustProxy, 1);
  assert.equal(parseConfig(baseEnv({ TRUST_PROXY: 'true' })).trustProxy, true);
  assert.throws(() => parseConfig(baseEnv({ TRUST_PROXY: 'maybe' })), /TRUST_PROXY/);
});

test('an invalid PORT or LOG_LEVEL is fatal', () => {
  assert.throws(() => parseConfig(baseEnv({ PORT: '0' })), /PORT/);
  assert.throws(() => parseConfig(baseEnv({ PORT: 'http' })), /PORT/);
  assert.throws(() => parseConfig(baseEnv({ LOG_LEVEL: 'chatty' })), /LOG_LEVEL/);
});

test('every variable M181 removed is fatal rather than ignored', () => {
  // The same asymmetry SIGNUPS_OPEN is rejected under, applied to the mailer.
  // A variable that is quietly ignored lets an operator believe mail is
  // configured on a service that has no mailer, and believe their users can
  // reset a passphrase they cannot — a false belief discovered by whoever
  // needs it most, on the day they need it. Refusing to boot costs one deploy.
  const removed = [
    'REQUIRE_EMAIL_VERIFICATION',
    'CLIENT_BASE_URL',
    'EMAIL_FROM',
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_USER',
    'SMTP_PASSWORD',
    'SMTP_SECURE',
    'PIGEON_API_KEY',
    'PIGEON_BASE_URL',
  ];
  for (const key of removed) {
    // The message must NAME the variable, or an operator reading one line of
    // container output cannot tell which of ten it was.
    assert.throws(() => parseConfig(baseEnv({ [key]: 'anything' })), new RegExp(key), `${key} must be fatal`);
  }
});

test('a removed variable is fatal even when set to its old default', () => {
  // The trap this closes: an operator who left REQUIRE_EMAIL_VERIFICATION at
  // `false` reads it as "off, therefore harmless". It is not harmless, it is
  // stale, and an empty-looking value must not slip past the guard.
  assert.throws(() => parseConfig(baseEnv({ REQUIRE_EMAIL_VERIFICATION: 'false' })), /REQUIRE_EMAIL_VERIFICATION/);
  assert.throws(() => parseConfig(baseEnv({ SMTP_HOST: '' })), /SMTP_HOST/);
});

test('SYNC_RESEARCH and SYNC_SHARING are independent flags', () => {
  // PROTOCOL.md §5.18: neither implies the other. A clinic instance may want
  // sharing and no cohort graph; a study host may want the reverse. Folding
  // them into one variable would silently widen every sharing deployment into
  // a research deployment, and vice versa.
  const researchOnly = parseConfig(baseEnv({ SYNC_RESEARCH: 'true' }));
  assert.equal(researchOnly.researchEnabled, true);
  assert.equal(researchOnly.sharingEnabled, false);

  const sharingOnly = parseConfig(baseEnv({ SYNC_SHARING: '1' }));
  assert.equal(sharingOnly.sharingEnabled, true);
  assert.equal(sharingOnly.researchEnabled, false);

  // A typo must not silently mean "off" on a flag whose absence is a 404.
  assert.throws(() => parseConfig(baseEnv({ SYNC_RESEARCH: 'yes' })), /SYNC_RESEARCH/);
});

test('an instance with nothing to say publishes no notice at all', () => {
  // ABSENCE IS THE DEFAULT AND IT IS A SHAPE, not just a value: `null` here is
  // what keeps the field off the /health body entirely, so a client older than
  // M181 parses the response exactly as it always did.
  assert.equal(parseConfig(baseEnv()).notice, null);
  assert.equal(parseConfig(baseEnv({ SYNC_NOTICE: '   ' })).notice, null);
});

test('SYNC_NOTICE is carried whole, with its optional link', () => {
  assert.deepEqual(parseConfig(baseEnv({ SYNC_NOTICE: '  We move on 1 March.  ' })).notice, {
    text: 'We move on 1 March.',
  });
  assert.deepEqual(
    parseConfig(baseEnv({ SYNC_NOTICE: 'We move on 1 March.', SYNC_NOTICE_URL: 'https://example.org/moving' })).notice,
    { text: 'We move on 1 March.', url: 'https://example.org/moving' },
  );
});

test('an over-long SYNC_NOTICE is a boot failure, never a truncation', () => {
  // /health is this container's own HEALTHCHECK path and is polled forever, so
  // the cap is real. Failing to boot is the only honest answer: quietly cutting
  // a shutdown notice in half ships a sentence the operator never wrote.
  const tooLong = 'n'.repeat(MAX_SYNC_NOTICE_LENGTH + 1);
  assert.throws(() => parseConfig(baseEnv({ SYNC_NOTICE: tooLong })), /SYNC_NOTICE/);
  // The boundary itself is accepted, so the cap is a limit and not an off-by-one.
  const atCap = 'n'.repeat(MAX_SYNC_NOTICE_LENGTH);
  assert.deepEqual(parseConfig(baseEnv({ SYNC_NOTICE: atCap })).notice, { text: atCap });
});

test('SYNC_NOTICE_URL must be an absolute http(s) URL, and must have something to link from', () => {
  const withNotice = (url: string): NodeJS.ProcessEnv => baseEnv({ SYNC_NOTICE: 'Read this.', SYNC_NOTICE_URL: url });
  // The client refuses these schemes too; refusing them at boot means the
  // operator hears about it instead of wondering why no link appears.
  assert.throws(() => parseConfig(withNotice('javascript:alert(1)')), /SYNC_NOTICE_URL/);
  assert.throws(() => parseConfig(withNotice('data:text/html,hi')), /SYNC_NOTICE_URL/);
  assert.throws(() => parseConfig(withNotice('/moving')), /SYNC_NOTICE_URL/);
  // A link with no message is far more likely a typo in the variable name than
  // an intention, and it would publish nothing either way.
  assert.throws(() => parseConfig(baseEnv({ SYNC_NOTICE_URL: 'https://example.org/moving' })), /SYNC_NOTICE_URL/);
});
