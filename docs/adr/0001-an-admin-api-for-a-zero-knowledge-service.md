# ADR-0001 — An admin API for a zero-knowledge service

- **Status:** accepted
- **Date:** 2026-08-26

## Context

This service runs with real accounts on it and has **no operational tooling at
all**. There is no `bin`, no command script beyond build, test and drizzle, and
no way to answer "how many accounts are there", "does this address have an
account", or "please delete my account and everything attached to it" without
opening a SQL client against production.

The last of those is not a convenience. It is an obligation: a data subject may
demand erasure, and a service whose only erasure mechanism is a hand-written
`DELETE` executed by whoever is awake is a service that will eventually get it
wrong, or fail to do it at all, or do it and be unable to show that it did.

Meanwhile the sibling `openplate-gateway` grew an admin API and a CLI over it,
and the wider workspace already has the pattern three times over (`shw-api`,
`np-api`, `lcc-api`): a REST surface, and a thin HTTP client that wraps it and
imports no database code, so it runs from a laptop with no database.

The difficulty is that this service is **zero-knowledge**, and an admin API is
the single most natural place to destroy that property by accident. Everything
below exists to make the destruction impossible rather than merely discouraged.

## Decision

Add a small, opt-in admin API, and a `sync-api` CLI that wraps it.

### What it may expose

- **Count and list accounts** — metadata only: id, email, created-at,
  verified-at, blob size and its updated-at, and which key-record kinds exist.
- **Get one account's metadata** — the same fields, for one account.
- **Delete an account**, with everything attached to it.
- **Aggregate storage statistics.**

### What it may never expose — and why each one

These are prohibitions on the design, not defaults to be relaxed later.

**No blob ciphertext may be read or exported through the admin surface.**
Ciphertext is still personal data, and an admin endpoint that returns it is an
exfiltration route that exists whether or not anyone uses it. The server cannot
read a blob, but it can _hand one to someone who might_. A data subject gets
their data by logging in, which is the only path that involves their passphrase.
An admin export is metadata JSON and nothing else.

**No verifier, no KDF descriptor, no credential material in any response.** The
verifier is what a login is checked against; the KDF descriptor is what a client
needs to derive a key. Neither has an operational use that justifies putting it
where a screenshot, a log or a paste can carry it.

**No admin mutation of a user's authentication.** There is no admin password
reset, and there cannot be a meaningful one: the passphrase wraps the data key
on the client, so the server changing a credential would produce an account that
can log in and decrypt nothing. An endpoint that _pretends_ to do it is worse
than useless — it is an account-takeover primitive wearing a support-tool label.
The recovery code remains the only data-preserving reset, exactly as
`PROTOCOL.md` describes.

**No email may be sent from the admin surface.** Mail from an admin tool is how
an operator-triggered action becomes an unlogged message to a user.

### Amendment, 2026-08-31 (M166): the rule is about USER secrets

Signup invites (`POST /v1/admin/invites`) add the first endpoint on this
surface whose response body carries a secret, so the rule above is restated
rather than quietly excepted:

> No **user** secret ever appears in a response. An **operator-born
> capability** may appear exactly once, in the response that creates it, and
> only its digest is stored.

Every item on the prohibited list — ciphertext, verifier, KDF descriptor,
wrapped DEK, session and link tokens, and their digests — is a **user** secret.
Each one unlocks an existing account or the data inside it, and each belongs to
a data subject who did not ask for it to be readable by an operator. An invite
token is none of those things. It grants access to no account, decrypts
nothing, and did not exist until the operator asked for it. It is far closer to
`ADMIN_TOKEN` itself than to a session token, and like `ADMIN_TOKEN` it has to
be legible once to be usable at all.

The carve-out is bounded, and the boundary is tested rather than trusted.
`tests/unit/admin-no-forbidden-fields.test.ts` seeds a redeemed invite and adds
both its raw token and its digest to the forbidden-value walk, so either
appearing in any READ body fails the suite;
`tests/unit/admin-invites.test.ts` asserts the other half, that the mint
response really does carry the token. Together they say "here and nowhere
else", which neither says alone. `db/invite-store.ts` never SELECTs
`token_hash` in the first place, so the digest is not merely filtered out of
responses — it is never fetched.

**This does not cross the "no admin mutation of authentication" rule**, and the
reason is worth stating so the next reader does not have to re-derive it. That
rule exists because the passphrase wraps the data key on the client: a
server-side credential change would produce an account that logs in perfectly
and can never decrypt its own blob again. Minting an invite changes no account,
no verifier and no key record. There is no account yet for it to damage.

Two consequences of the same reasoning:

- Revocation deletes only **unredeemed** invites. A spent invite is the record
  of where an account came from; the capability in it is already gone, so
  there is nothing left to withdraw and something left to lose.
- `SIGNUP_MODE=invite` with no `ADMIN_TOKEN` is a deployment that can never
  mint an invite, and therefore one nobody can ever register on. It **warns at
  boot and starts anyway**: invites minted before the token was removed are
  still valid, and refusing to boot would lock out people already holding one.

### Deletion reuses the store, not the handler

One deletion semantics, or DSAR deletions and self-deletions drift apart and
the difference is discovered during an audit.

The self-service path is `handleDeleteAccount` in `src/accounts/auth-handlers.ts`.
It cannot be reused directly, and the reason is the interesting part: it requires
the caller's `authHash` and checks it with `verifierMatches` before proceeding.
**An admin cannot supply that** — not because of a missing permission, but
because the admin genuinely does not know the passphrase, which is the property
this whole service is built on.

So the shared unit is one level down: `AccountStore.deleteAccount(accountId)`,
which both paths call. That method is a single-row delete against `accounts`,
and every dependent table (`account_tokens`, `sync_blobs`, `sync_key_records`)
carries `onDelete: 'cascade'` — the schema comment already calls this "the
self-serve DSAR mechanism". Authorisation is what differs between the two paths;
the erasure itself is one line of code, called from both.

An admin deletion is logged with the account id and no address.

### Authentication: the gateway's pattern, unchanged

A single `ADMIN_TOKEN` bearer credential, minimum 24 characters, compared by
SHA-256 digest and `timingSafeEqual` so that neither a prefix nor a length is
observable.

**Unset ⇒ the entire admin tree answers 404, to everybody.** Not 401, not 403 —
404, the same answer any unknown path gets. This is the property that makes the
feature safe to ship at all: this service auto-deploys on push, so the commit
that introduces a route is the commit that puts it in production. An
unconfigured deployment must be indistinguishable from one where the feature was
never written, and that must be true in the first commit that adds a route
rather than retrofitted afterwards.

The failure mode being avoided is specific: an admin surface that announces
itself with a 401 tells an attacker there is a credential worth guessing, on a
service whose entire threat model assumes the attacker can reach it.

### Logging

Never an email address. Never a token, a verifier or a KDF descriptor. An
opaque account id is the correlation handle, matching the gateway's rule that
an invite id is the handle and the recipient is not.

## Consequences

- The DSAR obligation gets a mechanism, and one that can be demonstrated.
- The admin surface is strictly narrower than the user-facing one. It can see
  _less_ about a user's data than that user can, by construction.
- Enabling it on the hosted instance requires setting `ADMIN_TOKEN` in the Bay
  vault — a deliberate operational step, separate from shipping the code, and
  one that leaves the feature dark until somebody takes it.
- "Support cannot help you recover your data" remains true, and is now true by
  written decision rather than by absence of a feature.

## Alternatives rejected

**A read-only admin API with no deletion.** Rejected: deletion is the one
capability with a legal obligation behind it, and it is the reason to build this
now rather than later.

**Reusing `handleDeleteAccount` with an admin bypass flag.** Rejected: a flag
that skips a passphrase check is a flag that can be set by a caller who should
not have it, and it puts the bypass inside the function every self-service
deletion runs through. Sharing the store call instead means the privileged path
never touches the unprivileged one.

**Direct SQL, documented in a runbook.** The status quo. Rejected: it is
unauditable, it is unavailable to anyone without production database access, and
a runbook step that says "write a DELETE" is a runbook step that will one day
delete the wrong row.
