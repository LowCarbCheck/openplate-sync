# ADR 001 — Community features get a second auth lane, not an extended vault credential

- **Status:** Accepted
- **Date:** 2026-08-04
- **Context:** M128 spec 02 (standalone account + sync service)

## Context

This service is being introduced as "the LCC ecosystem account service, whose
first feature is sync". The phrasing is deliberate and it creates a design
pressure that will arrive later: once accounts exist here, the obvious place to
hang a future community feature — shared recipes, a public profile, following
someone — is on the same `accounts` row, authenticated by the same credential.

That obvious move would be wrong, and it would be very hard to undo once
accounts exist in the field.

The credential this service currently stores is not a password. It is a
verifier for the `auth` branch of the client's Argon2id → HKDF derivation
(PROTOCOL.md §3.1), whose _sibling_ branch produces the key that decrypts the
user's data. The two branches are cryptographically independent, but they share
one root: the user's passphrase, and its per-account KDF parameters. That
sharing is what forces the awkward parts of this design — the pre-login
`kdfDescriptor` endpoint, the deterministic dummy descriptors, the atomic
verifier-plus-re-wrapped-DEK rotation, and a reset flow that can restore login
but not data.

Every one of those constraints exists to protect the vault. None of them makes
sense for reading a public recipe.

## Decision

**Future community features authenticate through a SECOND auth lane, sharing
only the `accounts` id space with the vault lane.**

Concretely:

1. The vault lane is what exists today: `verifier` + `kdfDescriptor` on
   `accounts`, exercised by `/v1/auth/login`, `/v1/auth/change-passphrase` and
   `/v1/auth/reset`. Nothing outside sync ever consumes it.
2. A community lane, when it is built, is magic-link or OAuth shaped: a
   credential with no KDF parameters, no client-derived hash, and no
   relationship to any key. It hangs off its own table keyed by `accounts.id`.
3. The `accounts` table itself stays minimal — id, email, nullable
   `displayName`, the vault credential material, timestamps. A community
   profile is a separate table, and it is emphatically not this one.
4. A token issued in one lane is not valid in the other. `account_tokens.kind`
   already discriminates; a community lane adds its own kinds rather than
   reusing `access`/`refresh`.

## Consequences

**What this buys.**

- _The vault credential never leaves the vault._ A community feature cannot
  accidentally accept an auth-hash, log it, cache it, or hand it to a
  third-party OAuth provider — because nothing in that lane ever touches one.
- _Community features can have ordinary ergonomics._ Magic links, "sign in with
  GitHub", session lengths measured in months, password-less recovery. None of
  those are available to the vault lane, and forcing them to share would drag
  the vault's constraints across the whole product or, far worse, quietly relax
  them.
- _Losing access to one lane does not imply losing the other._ A user who
  cannot recover their vault (no recovery code) still has their community
  identity, and vice versa. Conflating the two would mean a forgotten
  passphrase destroys a social graph as well.
- _The blast radius of a community-feature bug stops at the community lane._
  Community surfaces are, by their nature, the ones that will accept
  user-generated content, render other people's data, and integrate third
  parties. That is exactly the code you do not want holding the key-derivation
  credential.

**What this costs.**

- Two auth code paths to maintain, with the ever-present temptation to "just
  reuse the login endpoint".
- A user with both will hold two credentials for one account id, which needs
  clear UI or it reads as a bug.
- Linking an existing community identity to a vault account (or the reverse) is
  a real flow that will have to be designed, not a free consequence of sharing
  a row.

**The rejected alternative** — one credential for everything — was rejected
because its failure mode is silent and permanent. It does not break; it
gradually spreads vault-derived material into surfaces that were never designed
to hold it, and by the time that is noticed there are accounts in the field and
no migration that can un-spread it. The cost of two lanes is paid in code. The
cost of one lane is paid in a security property that cannot be recovered.

## Notes

- The minimal `accounts` shape this ADR protects is enforced only by review.
  The next person to add a column to it should read this file first.
- PROTOCOL.md §9.2 is the honest statement of what this service knows. A
  community lane changes that list, and it should be updated in the same change
  that introduces one.
