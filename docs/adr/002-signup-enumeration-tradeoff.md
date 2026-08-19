# ADR 002 — Signup conflict discloses account existence, and that is accepted

- **Status:** Accepted
- **Date:** 2026-08-04
- **Context:** M128 spec 02 security review

## Context

This service works hard to be indistinguishable about which email addresses hold accounts:

- `POST /v1/auth/kdf` serves a deterministic, real-shaped dummy descriptor for unknown addresses, on the same code path, doing the same work (PROTOCOL.md §5.7).
- `POST /v1/auth/login` returns one `401` with identical body text for an unknown account and a wrong auth-hash, after computing the verifier either way.
- `POST /v1/auth/request-reset` returns `202` unconditionally; the only channel that reveals anything is the inbox itself.

`POST /v1/auth/signup` breaks that pattern. A duplicate signup returns `409 an account already exists for this email`, which tells the caller — anyone, unauthenticated — that the address is registered.

The security review flagged the inconsistency. It is real, and it is the one hole in an otherwise uniform discipline.

## Decision

**Accept it.** Signup keeps returning `409` on a duplicate address.

## Why it cannot simply be closed

The usual fix is to always return `202` and move the truth into an email: "you already have an account" to an existing address, "confirm your address" to a new one. That works only if mail is guaranteed to be delivered.

**This service's default configuration has no mail.** `REQUIRE_EMAIL_VERIFICATION` is off out of the box, and the console transport (link printed to `docker logs`) is a first-class supported deployment — a family instance is expected to run that way, and the README says so. In that configuration:

- If a duplicate signup returned `202`, the user would be told their account was created when it was not, with no email arriving to correct it. They would then fail to log in with the passphrase they just chose, and the service would have lied to them about the one thing they were trying to do.
- Silently signing them in instead would be far worse: it would mean accepting an unauthenticated request that guesses at a passphrase and treating a mismatch as a new account.

So the oracle-free variant is not merely inconvenient here — it is **unavailable** in the configuration most self-hosters will run. A "fix" that only works when SMTP is configured would leave the default deployment both dishonest and no more private.

Bitwarden, whose account model this one follows, behaves the same way for the same reason.

## Mitigation

- **Per-IP signup throttle** (`register-auth-routes.ts`, namespace `signup`): every attempt counts, successful or not, keyed by IP alone so rotating the submitted address does not buy a fresh allowance. Probing a list of addresses through this endpoint is bounded to a handful per window per source.
- **`SIGNUPS_OPEN=false`** closes the endpoint entirely on a personal or family instance, removing the oracle outright for the deployments least able to absorb it.
- **Every other path stays indistinguishable.** This is the containment that matters: an attacker gets one bounded oracle, not a consistent posture of leaking, and the paths that are cheap to probe at volume (`kdf`) or that would reveal something about an inbox (`request-reset`) give nothing.

## Consequences

- A determined attacker with many source IPs can, slowly, confirm whether specific addresses have accounts on a public instance with signups open. The information gained is "this person uses this service" — not their data, which remains undecryptable to us as well.
- The inconsistency must not be used as precedent. A future endpoint that leaks existence needs its own justification of this shape; "signup already does it" is not one.
- If `REQUIRE_EMAIL_VERIFICATION` ever becomes the enforced default _and_ mail becomes mandatory, this decision should be revisited — at that point the `202`-plus-email variant becomes honest, and the reason for accepting the oracle disappears.

## Notes

- The `409` site in `auth-handlers.ts` carries a comment pointing here. Keep them together.
- PROTOCOL.md §5.8 states the tradeoff on the wire-contract side, so a third-party implementer knows it is deliberate rather than copying a bug.
- Related: [ADR 001](./001-community-auth-lane.md), which keeps vault credentials isolated from any future community surface — a surface that would otherwise be a much larger enumeration oracle than this one.
