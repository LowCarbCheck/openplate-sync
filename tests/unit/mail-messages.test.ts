/**
 * The two letters this service sends, in both languages, asserted as strings.
 *
 * THE BUILDERS ARE PURE, WHICH IS THE WHOLE REASON THIS FILE CAN EXIST. The
 * one thing that can actually be wrong in a mail is the LINK: a mistyped
 * separator, a missing `encodeURIComponent`, a base URL whose trailing slash
 * doubles into `//`. Every one of those sends perfectly and does not work, and
 * none is observable from a test that mocks a transport and asserts it was
 * called. Here the link is compared character by character with no HTTP
 * anywhere near it.
 *
 * THE WORDING BANS ARE THE OTHER HALF. The reader is a person who was invited
 * to a food diary; the architecture behind it is not their business, and the
 * 2026-09-04 walk-through found a letter that named two services. A test is
 * what keeps that from coming back, because prose has no type system.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildInviteMessage, buildInviteLink, escapeHtml } from '../../src/mail/invite-message.js';
import { buildResetMessage, buildResetLink } from '../../src/mail/reset-message.js';
import { MAIL_STRINGS, formatExpiryDate } from '../../src/mail/strings.js';
import { INSTANCE_LANGUAGES, type InstanceLanguage } from '../../src/protocol.js';

const CLIENT_BASE_URL = 'https://openplate.de';
const SERVER_PUBLIC_URL = 'https://sync.openplate.de';
const INVITE_TOKEN = 'si_an-invite-token-for-this-suite';
const RESET_TOKEN = 'sr_a-reset-token-for-this-suite';
const EXPIRES_AT = '2026-09-11T10:00:00.000Z';

/**
 * Words no letter may contain, in either language.
 *
 * EVERY ONE OF THESE NAMES A PIECE OF ARCHITECTURE. The 2026-09-04 invite
 * mail talked about a sync service and a gateway, and the person reading it
 * had to work out which of the two they were being invited to. There is one
 * service now, and the letters do not mention it either.
 */
const BANNED_WORDS = [
  'Sync',
  'sync',
  'Gateway',
  'gateway',
  'KI-Verbindung',
  'AI connection',
  'account link',
  'Konto-Link',
];

/** Both dashes, banned workspace-wide in prose and unpredictable across mail clients. */
const BANNED_DASHES = ['—', '–'];

function inviteFor(language: InstanceLanguage) {
  return buildInviteMessage({
    clientBaseUrl: CLIENT_BASE_URL,
    serverPublicUrl: SERVER_PUBLIC_URL,
    inviteToken: INVITE_TOKEN,
    expiresAt: EXPIRES_AT,
    language,
  });
}

function resetFor(language: InstanceLanguage) {
  return buildResetMessage({
    clientBaseUrl: CLIENT_BASE_URL,
    serverPublicUrl: SERVER_PUBLIC_URL,
    resetToken: RESET_TOKEN,
    language,
  });
}

/** How many times `needle` occurs in `haystack`. */
function countOccurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// ── The wording bans ───────────────────────────────────────────────────────

test('no letter, in any language, names a service or uses a dash', () => {
  for (const language of INSTANCE_LANGUAGES) {
    for (const [name, message] of [
      [`invite/${language}`, inviteFor(language)],
      [`reset/${language}`, resetFor(language)],
    ] as const) {
      // THE LINK IS EXCLUDED, and only the link. These bans are about what the
      // letter SAYS; the URL inside it is the operator's own hostname, and
      // `sync.openplate.de` is a name they chose and are entitled to. Banning a
      // substring of their domain would be this test dictating their DNS.
      // The SUBJECT counts: it is the part that shows in a notification.
      const whole = `${message.subject}\n${message.text}\n${message.html}`
        .split(message.link)
        .join('')
        .split(escapeHtml(message.link))
        .join('');
      for (const word of BANNED_WORDS) {
        assert.ok(!whole.includes(word), `${name} contains the banned word "${word}"`);
      }
      for (const dash of BANNED_DASHES) {
        assert.ok(!whole.includes(dash), `${name} contains a dash`);
      }
    }
  }
});

test('the shipped strings themselves carry no dash, so no builder can smuggle one in', () => {
  // The builders above only concatenate, so this is the same property one
  // level down: if the dictionary is clean, every letter is.
  const serialized = JSON.stringify(MAIL_STRINGS);
  for (const dash of BANNED_DASHES) {
    assert.ok(!serialized.includes(dash), 'a shipped mail string contains a dash');
  }
});

test('both languages carry the identical key set, which the type also enforces', () => {
  // The compiler already refuses a missing key. This asserts it at runtime too,
  // because the failure mode is a German letter with an English paragraph in
  // the middle and that is worth catching twice.
  assert.deepEqual(Object.keys(MAIL_STRINGS.en.invite).toSorted(), Object.keys(MAIL_STRINGS.de.invite).toSorted());
  assert.deepEqual(Object.keys(MAIL_STRINGS.en.reset).toSorted(), Object.keys(MAIL_STRINGS.de.reset).toSorted());
});

// ── The link, which is the thing that can silently be wrong ────────────────

test('the token appears exactly once in each letter, and only in the fragment', () => {
  for (const language of INSTANCE_LANGUAGES) {
    for (const [name, message, token] of [
      [`invite/${language}`, inviteFor(language), INVITE_TOKEN],
      [`reset/${language}`, resetFor(language), RESET_TOKEN],
    ] as const) {
      // ONCE in the text part. Twice would mean a builder repeated the link,
      // and a reader with two links does not know which one is live.
      assert.equal(countOccurrences(message.text, token), 1, `${name} text must carry the token exactly once`);

      // In the FRAGMENT, never the query string. A fragment is never sent to
      // any server, so the token stays out of history, `Referer` headers and
      // every access log the link passes on its way.
      const fragment = message.link.split('#')[1] ?? '';
      assert.ok(fragment.includes(token), `${name} must carry the token in the fragment`);
      assert.ok(
        !(message.link.split('#')[0] ?? '').includes(token),
        `${name} must not carry the token before the fragment`,
      );
      assert.ok(!message.link.includes('?'), `${name} must not use a query string at all`);
    }
  }
});

test('a trailing slash on either base URL never doubles into //', () => {
  const link = buildInviteLink({
    clientBaseUrl: 'https://openplate.de///',
    serverPublicUrl: 'https://sync.openplate.de//',
    inviteToken: INVITE_TOKEN,
  });
  assert.ok(link.startsWith('https://openplate.de/join#'), link);
  assert.ok(!link.includes('openplate.de//join'), link);
  // The server URL is encoded, so its own slashes survive as %2F rather than
  // truncating the fragment.
  assert.ok(link.includes(`server=${encodeURIComponent('https://sync.openplate.de')}`), link);
});

test('the two links differ only in their path and their parameter name', () => {
  assert.equal(
    buildInviteLink({ clientBaseUrl: CLIENT_BASE_URL, serverPublicUrl: SERVER_PUBLIC_URL, inviteToken: 'si_x' }),
    `https://openplate.de/join#server=${encodeURIComponent(SERVER_PUBLIC_URL)}&invite=si_x`,
  );
  assert.equal(
    buildResetLink({ clientBaseUrl: CLIENT_BASE_URL, serverPublicUrl: SERVER_PUBLIC_URL, resetToken: 'sr_x' }),
    `https://openplate.de/reset#server=${encodeURIComponent(SERVER_PUBLIC_URL)}&token=sr_x`,
  );
});

// ── Shape, so the absence assertions above are not about an empty string ───

test('each letter carries every paragraph its dictionary defines, in order', () => {
  for (const language of INSTANCE_LANGUAGES) {
    const invite = inviteFor(language);
    const strings = MAIL_STRINGS[language].invite;
    assert.equal(invite.subject, strings.subject);
    // Order, not merely presence: a letter whose paragraphs arrived shuffled
    // would pass an `includes` check for each one.
    const expectedOrder = [
      strings.greeting,
      strings.invited,
      strings.open,
      invite.link,
      formatExpiryDate({ expiresAt: EXPIRES_AT, language }),
      strings.password,
      strings.help,
    ];
    let cursor = -1;
    for (const piece of expectedOrder) {
      const found = invite.text.indexOf(piece);
      assert.ok(found > cursor, `invite/${language}: "${piece.slice(0, 24)}" is out of order`);
      cursor = found;
    }

    const reset = resetFor(language);
    const resetStrings = MAIL_STRINGS[language].reset;
    assert.equal(reset.subject, resetStrings.subject);
    let resetCursor = -1;
    for (const piece of [
      resetStrings.greeting,
      resetStrings.intro,
      resetStrings.open,
      reset.link,
      resetStrings.expiry,
      resetStrings.ignore,
      resetStrings.help,
    ]) {
      const found = reset.text.indexOf(piece);
      assert.ok(found > resetCursor, `reset/${language}: "${piece.slice(0, 24)}" is out of order`);
      resetCursor = found;
    }
  }
});

test('the HTML part carries the link in the same position the text does', () => {
  // Two parts ordering their paragraphs differently would be two letters, and
  // which one a reader sees would depend on their mail client.
  for (const language of INSTANCE_LANGUAGES) {
    const invite = inviteFor(language);
    const strings = MAIL_STRINGS[language].invite;
    const afterOpen = invite.html.indexOf(strings.open);
    // The href is HTML-escaped, so the `&` before `invite=` is `&amp;` there.
    const atLink = invite.html.indexOf(`href="${escapeHtml(invite.link)}"`);
    const beforeHelp = invite.html.indexOf(strings.help);
    assert.ok(afterOpen > 0 && atLink > afterOpen && beforeHelp > atLink, `invite/${language} html order`);
    assert.ok(invite.html.startsWith('<!doctype html>'));
    assert.ok(invite.html.includes(`<html lang="${language}"`));
  }
});

test('the expiry renders as a date in the reader language, in UTC', () => {
  assert.equal(formatExpiryDate({ expiresAt: EXPIRES_AT, language: 'en' }), '11 September 2026');
  assert.equal(formatExpiryDate({ expiresAt: EXPIRES_AT, language: 'de' }), '11. September 2026');
  // An unparseable value is passed through rather than rendered as "Invalid
  // Date": a caller's bug must not become a sentence in somebody's inbox.
  assert.equal(formatExpiryDate({ expiresAt: 'not a date', language: 'en' }), 'not a date');
});

test('the invite letter tells the reader what happens next, in both languages', () => {
  // A positive assertion, so the bans above cannot be satisfied by an empty
  // letter. The password sentence is the one that says what the link is for.
  for (const language of INSTANCE_LANGUAGES) {
    const invite = inviteFor(language);
    assert.ok(invite.text.includes(MAIL_STRINGS[language].invite.password));
    assert.ok(invite.text.length > 200, `invite/${language} is suspiciously short`);
  }
});
