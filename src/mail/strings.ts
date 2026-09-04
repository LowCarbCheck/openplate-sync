/**
 * Every word this service ever sends to a person, in the two languages it
 * sends them in.
 *
 * ONE DICTIONARY, TWO LANGUAGES, ONE KEY SET, ENFORCED BY THE TYPE.
 * `Record<InstanceLanguage, MailStrings>` means a key added to `en` and
 * forgotten in `de` is a compile error rather than a German letter with an
 * English paragraph in the middle of it. There is no fallback and no lookup
 * that can miss.
 *
 * THESE STRINGS ARE FINAL AND ARE NOT EDITED HERE. They came out of the
 * workspace wordsmith pass of 2026-09-04 (Gemini 3.8 Flash; the rule is in the
 * workspace `CLAUDE.md`), and the German is a native register rather than a
 * translation of the English. Changing a sentence means running that pass
 * again and pasting the result, not rewriting it in this file.
 *
 * THREE RULES THE TEXT OBEYS, AND `tests/unit/mail-messages.test.ts` HOLDS IT
 * TO THEM:
 *
 *  - **No service is ever named.** Not "the sync server", not "the gateway",
 *    not "an AI connection", not "your account link". The reader is a person
 *    who was invited to a food diary, and the architecture behind it is not
 *    their business. The banned-word list in that test is the enforcement.
 *  - **No em dashes and no en dashes.** A workspace-wide prose rule, and here
 *    it is also practical: they render unpredictably across mail clients.
 *  - **Say what the reader does next, and nothing else.** Every paragraph is
 *    an instruction or a fact about the link.
 */
import type { InstanceLanguage } from '../protocol.js';

/**
 * The invitation. One letter for every invite, with no variants: the M181-era
 * `both`/`sync`/`gateway` split is gone with the second service it described.
 */
export interface InviteStrings {
  subject: string;
  greeting: string;
  invited: string;
  open: string;
  /** Carries `{date}`, filled with the expiry rendered in the reader's language. */
  expiry: string;
  password: string;
  help: string;
}

/** The password reset. New in M192; there was no mailed reset to carry forward. */
export interface ResetStrings {
  subject: string;
  greeting: string;
  intro: string;
  open: string;
  expiry: string;
  ignore: string;
  help: string;
}

export interface MailStrings {
  invite: InviteStrings;
  reset: ResetStrings;
}

export const MAIL_STRINGS = {
  en: {
    invite: {
      subject: 'Your openplate invitation',
      greeting: 'Hello,',
      invited: 'You are invited to openplate, a food diary that keeps your data on your own device.',
      open: 'Open this link on the device you want to use openplate on:',
      expiry: 'The link works one time only, and it expires on {date}.',
      password:
        'On that page you choose a password. From then on you sign in with your email address and this password, on any device.',
      help: 'If the link no longer works, ask the person who sent it to you for a new one.',
    },
    reset: {
      subject: 'Set a new openplate password',
      greeting: 'Hello,',
      intro: 'Someone asked for a new password for the openplate account with this email address.',
      open: 'Open this link and choose a new password:',
      expiry: 'The link works one time only, and it expires in one hour.',
      ignore: 'If you did not ask for this, you can ignore this mail. Your password stays as it is.',
      help: 'If the link no longer works, ask for a new one on the sign-in page.',
    },
  },
  de: {
    invite: {
      subject: 'Deine Einladung zu openplate',
      greeting: 'Hallo,',
      invited:
        'Du bist zu openplate eingeladen, einem Ernährungstagebuch, das deine Daten auf deinem eigenen Gerät speichert.',
      open: 'Öffne diesen Link auf dem Gerät, auf dem du openplate nutzen möchtest:',
      expiry: 'Der Link funktioniert nur einmal und läuft am {date} ab.',
      password:
        'Auf dieser Seite wählst du ein Passwort. Danach meldest du dich mit deiner E-Mail-Adresse und diesem Passwort an, auf jedem Gerät.',
      help: 'Falls der Link nicht mehr funktioniert, bitte die Person, die ihn dir geschickt hat, um einen neuen.',
    },
    reset: {
      subject: 'Neues Passwort für openplate festlegen',
      greeting: 'Hallo,',
      intro: 'Jemand hat für das openplate-Konto mit dieser E-Mail-Adresse ein neues Passwort angefordert.',
      open: 'Öffne diesen Link und wähle ein neues Passwort:',
      expiry: 'Der Link funktioniert nur einmal und ist eine Stunde lang gültig.',
      ignore:
        'Wenn du das nicht angefordert hast, kannst du diese E-Mail ignorieren. Dein Passwort bleibt unverändert.',
      help: 'Wenn der Link nicht mehr funktioniert, fordere auf der Anmeldeseite einen neuen an.',
    },
  },
  // `satisfies` rather than an annotation: the check that both languages carry
  // the identical key set is what this line buys, and inference keeps each
  // string's literal type so a typo in a lookup is still a compile error.
} satisfies Record<InstanceLanguage, MailStrings>;

/** The one placeholder any shipped string carries. Named so `fill` has a concrete contract rather than an open dictionary. */
export interface FillValues {
  date?: string;
}

/**
 * Substitutes `{name}` placeholders. Deliberately tiny: the only value any
 * string interpolates is a formatted date, and a template engine here would be
 * a dependency bought for one substitution.
 */
export function fill(template: string, values: FillValues): string {
  // An unknown placeholder is left as written rather than blanked: a `{typo}`
  // visible in a letter is a bug somebody reports, and an empty gap is not.
  return template.replace(/\{(\w+)\}/g, (whole, key: string) => (key === 'date' ? (values.date ?? whole) : whole));
}

/**
 * The expiry as a person in that language reads it, in UTC.
 *
 * UTC AND NOT THE READER'S ZONE, because the server does not know theirs and
 * guessing would put a date on the letter that is wrong for somebody. A day is
 * a coarse enough unit that the zone rarely matters, and the link's real
 * lifetime is enforced by the server rather than by what this says.
 */
export function formatExpiryDate(input: { expiresAt: string; language: InstanceLanguage }): string {
  const parsed = Date.parse(input.expiresAt);
  // An unparseable value is passed through rather than rendered as "Invalid
  // Date": the caller's bug should not become a sentence in somebody's inbox.
  if (Number.isNaN(parsed)) return input.expiresAt;
  return new Intl.DateTimeFormat(input.language === 'de' ? 'de-DE' : 'en-GB', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  }).format(new Date(parsed));
}
