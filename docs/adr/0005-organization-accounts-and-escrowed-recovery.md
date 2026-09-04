# ADR-0005 — Organization accounts, and an escrowed recovery code

- **Status:** accepted
- **Date:** 2026-09-04
- **Supersedes:** ADR-0004's prohibitions 1, 2, 3, 5 and 8. Its prohibitions 4,
  6 and 7 remain binding and are restated below.
- **Amends:** `PROTOCOL.md` §2 (the identifier), §4.2 (a third token kind that
  is not a session), §5.6 to §5.15 (email, addressed invites, escrow, two reset
  endpoints, `AccountView`, suspension) and §9.2 (the service stores one more
  class of personal data than it did, and one more capability).
- **Protocol version:** 1 → 2.

## Context

ADR-0004 removed email from this service two days ago. It was right about
everything it argued and wrong about who the service was for.

On 2026-09-04 the owner walked the invite path as an end user, on a hosted
instance, as an organization would. What he found was a mail that named two
services, a sign-in screen where a registration was expected, a scan card
demanding an OpenRouter key on a managed instance, and a gateway invite burned
server-side with nothing saved on the device. Underneath all four sat one
shape: an identity split across two services, and a **handle plus a recovery
code** model that a beta of one person could carry and an organization cannot.

His words, and they are the whole of the context:

> "they will forget their usernames, they will forget their passwords, they
> know their email though"

and:

> "be bold in this refactoring, i want to nail this"

### What ADR-0004 got right, and why it does not settle this

ADR-0004's central argument is untouched by anything below. **A mailed link
that replaces an account's verifier is an account-takeover path that returns no
recovery**, because the DEK is wrapped under keys the server never held: the
link holder gets a login to a diary that stays sealed, and can destroy the real
owner's access on the way in. That flow is still deleted and is never coming
back. Nothing in this document restores it.

What it did not weigh is that the alternative it chose — an opaque handle plus a
160-bit code the user must never lose — puts the entire cost of recovery on a
person who did not choose to be here. An employee invited to their employer's
instance did not opt into custody of a code on a card. They will lose it. When
they do, ADR-0004's honest answer is "your diary is gone", and the operator's
honest answer is "I cannot help you". For a self-hoster that is a fair trade
they made knowingly. For a person handed an account at work it is a trap.

### The three costs, weighed again for an organization

**A handle is not memorable, and ADR-0004 said so.** Its mitigation was that the
client shows the handle and the code together as one saved account card. That
works for somebody who reads release notes. It does not survive a person signing
in on a second device six weeks later.

**There is no way to contact anybody.** ADR-0004 accepted this and mitigated it
with `SYNC_NOTICE`, a pull-only banner. An organization rolling software out to
employees needs to send one letter — the invitation — and it needs to be able to
send a second one when somebody is locked out. A notice on a handshake reaches
the people who are already in.

**The signup `409` was the one enumeration oracle.** It still is, and it is now
narrower rather than wider: see below.

## Decision

**An account is an email address plus a passphrase. Signup is invite-only,
always. The recovery code is held in escrow by the server.**

### The identifier is an email address, and the `@` rejection is inverted

`accounts.handle` becomes `accounts.email`, canonicalised NFKC then trimmed then
lowercased, at most 254 characters, exactly one `@`, a non-empty local part, and
a domain with a dot. `parseEmail` is the only email rule in the repo, in the same
single function `parseHandle` was.

Lowercasing the local part is a deliberate over-reach: RFC 5321 makes it
case-sensitive, and no mail provider a person is invited from treats it that
way. Folding is what a user expects; the standard's latitude here is one nobody
uses, and honouring it would let one employee hold two diaries.

### The invitation IS the address verification

`signup_invites` gains `email`, `display_name`, `role`, `daily_ai_limit` and
`revoked_at`, and loses `note`. `POST /v1/auth/signup` reads the address **from
the invite row, inside the transaction**, and never from the request body.

That single fact removes a whole flow. There is no confirmation link and no
`REQUIRE_EMAIL_VERIFICATION`, because the person who received the letter at that
mailbox is the person redeeming it. It also removes a class of mistake: an
invited person cannot mistype their own address into an account nobody can
reach.

M166 refused to bind an invite to an identifier, on the grounds that the service
would then store something about a person who has no account and gave no
consent. That is still true and is now accepted rather than avoided: between
minting and redemption this table holds an address, a name and an allowance for
somebody who has not signed up. An operator inviting their own colleagues is the
case this service is for, and `DELETE /v1/admin/invites/:id` withdraws the row.

### The recovery code is escrowed, and this is the honest privacy story

The client still generates the 160-bit recovery code at signup, still derives
`KEK_r` and `recoveryAuthHash` from it under the frozen labels of §3.1, and still
wraps the DEK under it. What changed is that it **no longer shows the code to
the person**. It sends the raw code to the server once, in the signup body, and
the server seals it into `accounts.recovery_code_escrow` with AES-256-GCM under
a new frozen subkey of `SERVER_SECRET`, `openplate-sync:escrow-key:v1`.

`POST /v1/auth/reset/request` mails a link. `POST /v1/auth/reset/open` spends
it once and returns the decrypted code. The client then runs the **existing**
`POST /v1/auth/recover-rotate` ceremony with it: prove the code, set a new
passphrase, re-wrap the DEK, mint a new code, re-escrow it — one transaction,
unchanged.

**The reset endpoint writes nothing to the account.** That is what makes it a
delivery mechanism for a credential the operator already holds, rather than the
takeover path ADR-0004 deleted. Without the key records, what it hands over is a
string.

**Said plainly, because it must be: the operator of a managed instance holds
what it takes to open a diary.** The key lives in the environment rather than in
the row, so a dumped database alone does not open one; the operator has both.
ADR-0004 prohibition 5 forbade exactly this and called an operator-held escrow
"a decryption capability on the server, which is the property this whole service
exists to not have". That sentence is still accurate. What has changed is the
honest accounting around it:

- A managed instance **already sees every plate photo** that passes through its
  AI proxy. The escrow does not create the operator's access to a person's
  intake; it makes explicit an access that the AI feature already granted.
- A **self-hosted** instance is its own operator, so the old promise is intact
  for the personal case ADR-0004 was written for.
- The alternative was not "no escrow and the same product". It was "an
  organization's employees lose their diaries", which is a worse privacy
  outcome for them than an operator who could read one and does not.

This is written into `README.md`, `.env.example`, the schema comment on
`accounts.recovery_code_escrow`, and the app's privacy copy. It is not buried.

### Roles, allowance and standing

`accounts.role` is `'admin' | 'member'`, `accounts.daily_ai_limit` is an integer
defaulting to `0`, `accounts.suspended_at` is nullable. A suspended account
cannot log in, refresh, sync or use AI: every such call is
`403 {"error":"account-suspended"}`, and suspending revokes every session in the
same transaction, so it means "now" rather than "within fifteen minutes".

The admin API accepts the static `ADMIN_TOKEN` (the operator's break-glass
credential, which works when every account is locked out) **or** an admin
account's own access token. The `/v1/admin` tree is therefore mounted always,
and `server/admin-auth.ts` — not the mount — answers the ordinary unknown-path
404 when no static token is configured and the caller is not an admin account.
ADR-0001's indistinguishability is preserved; only the place that enforces it
moved.

### The `409` oracle shrank

The signup `409` remains the one accepted enumeration oracle, and what it
discloses is now almost nothing. It is reachable only by somebody holding a live
invite that was **addressed to the very address it reports as taken** — so it
confirms only what the operator already wrote on the letter. Before M192 an
invite holder could probe arbitrary handles with one invite; they cannot now,
because the address is not theirs to choose.

## Prohibitions

Carried forward from ADR-0004, still binding:

4. **The recovery-auth label is never the recovery-KEK label**, and neither is
   ever re-derived from the other. A future change to either is a new `:v2`
   label, never a redefinition. The escrow key is a **third** frozen label and
   is derived from neither.
5. **A rotation is atomic or it does not exist.** No sequence of individually
   committing endpoints may be documented or used as a recovery procedure. The
   escrow now moves inside that same transaction: `newRecoveryAuthHash`, the
   `recovery` key record and `recoveryCode` arrive together or the rotation is a
   `400`.
6. **The recovery endpoints stay throttled on one shared bucket per (IP,
   email), and neither clears on success.** `POST /v1/auth/reset/request` joins
   them under the same rule.

New, and specific to what this ADR opened:

9. **The escrow is sealed under its own frozen label, and the key never leaves
   the environment.** It is not a column, not a config file, and not derivable
   from the verifier pepper.
10. **No endpoint ever returns a recovery code to anybody but the account
    holder, and only through a token mailed to the account's own address.**
    There is no admin endpoint that prints one, and `db/admin-store.ts` never
    names the column.
11. **The recovery code is never logged**, in any form, on any path. Not at
    signup, not at rotation, not at reset.
12. **`POST /v1/auth/reset/request` answers `202` to every caller, after the
    same work.** The token mint and its digest happen on both branches; only
    the store write and the send are skipped. ADR-0004 noted that the OLD
    `request-reset` was the one path where timing was not equalised. This one
    is, and a unit test counts the mints to prove it.
13. **A reset writes nothing to an account.** If a future change lets that
    endpoint touch a verifier or a key record, it has become the takeover path
    ADR-0004 deleted, whatever it is called.

## Alternatives rejected

**Keep handles and add an optional email for mail only.** Rejected. It is the
worst of both: the person still signs in with a handle they will forget, and the
service still stores the address. The address has to be the identity or it is
just a second thing to lose.

**Escrow the DEK instead of the recovery code.** Rejected, and the distinction
matters more than it looks. Escrowing the code means nothing on this server ever
derives `KEK_r`, unwraps a DEK, or holds one — the code becomes a key only after
the CLIENT runs HKDF over it. The operator can run HKDF too, so this buys no
security; it buys a code path with no decryption in it, which is what makes
"the server never held a key" a statement about the code rather than about
intentions.

**A mailed link that resets the passphrase directly.** Rejected, permanently,
and this is ADR-0004's argument unchanged. It restores a login to a sealed
diary and destroys the owner's access on the way. The reset here delivers the
code and writes nothing.

**Per-account escrow keys held by the client.** Rejected: a key the client holds
is a key a person can lose, which is the problem this ADR exists to solve.

**Keep ADR-0004 and tell organizations to use something else.** Rejected by the
owner's decision above. It was the honest option and it was on the table.

## What this costs, said plainly

**The operator can open any account on their instance.** Not through an
endpoint — there is none — but by reading `accounts.recovery_code_escrow` with
`SERVER_SECRET` in hand and running the client's own HKDF. Anybody deciding
whether to trust a hosted instance should read that sentence and decide about
the operator, not about the cryptography.

**`SERVER_SECRET` is now load-bearing twice over.** Rotating it already
invalidated every login; it now also makes every escrowed recovery code
permanently unreadable, so a mailed reset stops working for every account that
signed up before the change. Back it up with the database.

**The signup body carries the recovery code in the clear (under TLS).** For one
request, once, at account creation. It is never logged, and it is sealed before
it reaches a column.
