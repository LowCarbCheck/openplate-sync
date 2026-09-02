# ADR-0004 — Identity without email

- **Status:** accepted
- **Date:** 2026-09-02
- **Amends:** `PROTOCOL.md` §3.1 (a fourth frozen label), §4.2 (one revocation
  trigger renamed, the link tokens gone), §5.7 to §5.15 (the identifier, two
  removed endpoints, two new ones) and §9.2 (the service stores one less class
  of personal data than it did).
- **Extends:** ADR-0001's prohibition on an admin reset to the whole service.

## Context

An account on this service was an **email address** plus a passphrase, and the
address paid for two things: a channel to contact the account holder, and a
password reset. Both look obligatory. On a zero-knowledge service neither
survives contact with what the server actually holds.

The service stores a DEK wrapped twice, under a passphrase-KEK and under a
recovery-KEK, and it has never held either. Its entire claim is that the
operator cannot read a diary. Email contradicted that claim in three separate
ways, and it is worth separating them, because only the first is an argument
about security.

### The mailed reset was an account-takeover path that returned no recovery

`POST /v1/auth/request-reset` mailed a link. Whoever redeemed that link could
replace the account's verifier, its KDF descriptor and its key records.

On an ordinary web application that is the trade everybody makes: the mailbox
becomes the root credential, and in exchange a user who forgets a password
keeps their data. Here the second half of the trade does not happen. The link
holder gets a **login** to a blob that stays sealed, because nothing in the
reset submission can produce a DEK the server never saw. They cannot read one
byte of the diary, and on the way in they can overwrite the key records the
real owner still needed.

So the flow handed an attacker a takeover and handed the owner nothing. It was
not a weak recovery mechanism. It was a _negative_ one: strictly worse than
having no reset at all, on this service and only on this service.

Whoever controls a mailbox therefore controlled every account registered to it,
which quietly made the mailbox provider a party to a design whose whole point
is that no third party can be one.

### The address was the largest piece of personal data here

§9.2's account sentence used to open with "an email address". Everything else
in that list is opaque: a wrapped key, a byte count, a timestamp, a verifier.
The address was the single field that tied a row to a person in the world, on a
service holding health-adjacent data. Removing it removes a class of GDPR
surface rather than shrinking one.

### Mail is infrastructure the target personas do not have

`src/mail/` carried three transports (pigeon, SMTP, console) to send two
messages. The honest instruction to a solo self-hoster was "configure SMTP, or
your users cannot reset", which is a mail relay, a deliverability problem and a
bounce story, bought so that a stranger with a mailbox could take an account
over. A household sharing links in a chat has no relay. A clinic has one and
must never point it at diaries.

The window to act is now: pre-launch, private repos, one test account, which is
deleted rather than migrated.

## Decision

**An account is a handle plus a passphrase, and the recovery code is the second
authenticator.** Email is removed from this service entirely: no address
column, no mailer, no verification, no mailed link.

### The identifier is an opaque handle, and `@` is refused

The client mints a short Crockford-style handle at signup and the user may edit
it. The server canonicalises NFKC then trim then lowercase, bounds it at 64
characters, keeps it unique per server, and **rejects any handle containing
`@`**.

That rejection is the load-bearing rule, and it lives in exactly one function
(`parseHandle`). Without it the column drifts straight back into an address
register, one user at a time, because a user who is asked for an identifier
types their email. A column that holds addresses cannot be un-held later: the
rows are already there. A `400` naming the rule costs one confused signup and
buys the property permanently.

The handle is not a secret and not an identity. It is meaningful on one
instance, resolves to no person, and gives nobody a way to reach its holder.

### The recovery code both authenticates and unwraps, which the link never did

The client already derives `KEK_r` from the recovery code. It now derives a
second value from the same code under a **new frozen label**,
`openplate-sync:recovery-auth:v1`, and sends that as a proof. The server stores
it as `HMAC(pepper, hash)`, the same construction as the passphrase verifier,
in `accounts.recovery_verifier`.

**The label is never the recovery-KEK label, and that is the whole of the
argument.** The KEK branch derives the key that opens the diary. Were the same
output also sent here, the service would store an HMAC of the material that
unwraps a DEK, and "the operator cannot read your data" would rest on SHA-256
being one-way rather than on the operator never having held the value. Domain
separation is what keeps the second authenticator from being a copy of the
first key.

This is why the code is a better second authenticator than a mailbox, in one
sentence: **the user holds it and the server never does, so proving it also
unwraps the data**, where proving control of a mailbox unwrapped nothing.

Two endpoints, both throttled per IP and handle on one shared bucket, because
they authenticate the same secret and a separate allowance for each would halve
the cost of guessing it:

- `POST /v1/auth/recover` returns an ordinary session. Not a lesser one: the
  holder of the code is the owner by construction, and a restricted
  "recovery mode" token would add an authorization surface carrying no property
  the code does not already carry.
- `POST /v1/auth/recover-rotate` proves the code and sets a new passphrase in
  the same call. The proof travels in the request rather than in a session
  minted a minute earlier, so the value is checked in the call that writes.

An unknown handle, an account that never set a code, a wrong code and a lost
rotation race all answer with one identical `401`. Each costs the same work,
compared against a full-width stand-in, so the endpoint says nothing in its
timing either.

### The rotation is one transaction, and every half-state is a distinct disaster

`recoverAndRotatePassphrase` moves the passphrase verifier, the KDF descriptor,
an optionally new recovery verifier, both re-wrapped key records, the
revocation of every session and the caller's new session, in **one** Postgres
transaction, compare-and-swapped on the recovery verifier the proof matched.

None of the half-states is a retryable hiccup, and none is visible until the
user opens their diary:

| Half-state                                     | What the user gets                                                                |
| ---------------------------------------------- | --------------------------------------------------------------------------------- |
| Verifier moved, `passphrase` record not        | Logs in, decrypts nothing                                                         |
| Record moved, verifier not                     | Cannot log in, and the only key to the re-wrapped DEK is the passphrase they lost |
| Recovery verifier moved, `recovery` record not | A code that authenticates and then unwraps nothing                                |

So a `passphrase` key record is **required** here, unlike `change-passphrase`
where an empty array legitimately means "I am changing nothing", and rotating
the recovery code is all-or-nothing. The integration suite injects a real
failure part-way through the transaction and asserts that both verifiers and
both wraps are byte-for-byte unchanged. Removing the transaction turns that
test red.

### Anti-enumeration is unchanged, and the one oracle now leaks less

`deriveDummyKdfDescriptor` works over any string, and a handle is one, so `kdf`
and `login` stay indistinguishable for unknown accounts in shape and in work
done. Every enumeration test was ported rather than dropped.

The signup `409` remains the **one** accepted oracle. What it discloses changed
for the better: it confirms that an opaque per-server handle is taken, where it
used to confirm that a named person's address held an account. It also lost the
argument it used to rest on. The oracle-free variant ("always `202`, put the
truth in an email") is no longer merely unavailable in the default
configuration; with no mailer anywhere, there is no channel that could carry
the news, so a `202` would simply lie.

One weakness disappeared with the endpoint. `request-reset` was documented as
the one path where timing was _not_ equalised, because a known address cost a
token write and a mail send that an unknown address did not. There is no such
path now.

### Removed variables are a boot failure, not a no-op

`REQUIRE_EMAIL_VERIFICATION`, `CLIENT_BASE_URL`, `EMAIL_FROM`, `SMTP_*` and
`PIGEON_*` refuse to start the container, on the `SIGNUPS_OPEN` precedent from
M166. A container that will not boot costs one deploy. A variable that is
silently ignored lets an operator believe mail is configured on a service with
no mailer, and believe their users can reset a passphrase they cannot.

## What this costs, said plainly

**The service can no longer contact anybody.** No breach notice, no "this
instance is moving", no "your account will be deleted on Friday". That is
accepted, and it is mitigated twice, neither time by putting an address back in
the database: the operator keeps a contact list outside the service, and
`SYNC_NOTICE` publishes one short message on the `/health` handshake that
connecting clients render as a banner. The notice is **pull**, never push. It
reaches the people who open the app and nobody else, and the server cannot know
who read it.

**A handle is not memorable the way an address is.** The client must therefore
present the handle and the recovery code **together, once, as one saved account
card** at signup. A user who loses that card loses the account.

**If the passphrase and the recovery code are both lost, the account is
unrecoverable.** There is no third path. Any mechanism that let the server
restore access would mean the server could open the data, which is ADR-0001's
forbidden back door wearing a support-tool label. The only honest response is
to say so before the user commits, and to say it in the client, in `README.md`,
in `SECURITY.md` and in `PROTOCOL.md` §5.14.

## Prohibitions

1. **No email field, ever, not even optional.** Optional personal data is still
   personal data, and an optional contact channel grows a reset flow again
   within a release.
2. **No mailed, SMS'd or otherwise messaged reset.** A credential that arrives
   over a channel the server controls is a takeover path that returns no
   recovery on this service, whatever the channel is.
3. **The `@` rejection is never relaxed**, and never moved out of the single
   function that owns it.
4. **The recovery-auth label is never the recovery-KEK label**, and neither is
   ever re-derived from the other. A future change to either is a new `:v2`
   label, never a redefinition.
5. **No server-side escrow, no admin reset, no operator-assisted recovery.**
   ADR-0001 said this of the admin API; it holds for every surface.
6. **A rotation is atomic or it does not exist.** No sequence of individually
   committing endpoints may be documented or used as a recovery procedure.
7. **The recovery endpoints stay throttled on one shared bucket per (IP,
   handle), and neither clears on success.** A legitimate recovery happens
   once, so no honest client needs its allowance back.
8. **No document tells an operator to configure mail**, and no removed mail
   variable is ever restored to a no-op.

## Alternatives rejected

**Keep email as an optional field.** Rejected: see prohibition 1. It preserves
the largest personal-data field and the reset flow's whole gravity, in exchange
for a contact channel that only some accounts have, which is the worst of both.

**Keep the mailed reset and warn about it.** Rejected: the takeover is real and
the recovery is imaginary. A warning does not change either.

**Bind invites to an address.** Rejected in M166 and still rejected: it makes
the service store the address of somebody who has no account and never
consented.

**A recovery-code reset that reuses the recovery-KEK output as the proof.**
Rejected: it parks an HMAC of the diary-opening material in the database. This
is the one alternative that would have looked like a simplification.

**An operator-held escrow key "for support".** Rejected. It is a decryption
capability on the server, which is the property this whole service exists to
not have.
