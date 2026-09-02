# Changelog

All notable changes to `openplate-sync` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/spec/v2.0.0.html). Pre-1.0, a breaking
change moves the minor.

## [0.5.0] - 2026-09-02

Identity without email. An account is a **handle** plus a passphrase, and a lost
passphrase is recovered with the recovery code the client showed the user at
signup. The service sends no mail and stores no email address.

### BREAKING

- **`accounts.email` is now `accounts.handle`** (migration `0007`), and
  `email_verified_at` is dropped. The server rejects any handle containing `@`,
  canonicalises with NFKC then trim then lowercase, and keeps it unique per
  server.
- **Removed endpoints**: `POST /v1/auth/verify-email`,
  `POST /v1/auth/request-reset`, `POST /v1/auth/reset`. They answer `404`.
  `PROTOCOL.md` §5.12 and §5.13 are marked REMOVED rather than renumbered, so
  section references in both repos still resolve.
- **Removed env vars, and each is a boot failure rather than a no-op**:
  `REQUIRE_EMAIL_VERIFICATION`, `CLIENT_BASE_URL`, `EMAIL_FROM`, `SMTP_HOST`,
  `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_SECURE`, `PIGEON_API_KEY`,
  `PIGEON_BASE_URL`. A container that refuses to start costs one deploy; a
  variable that is quietly ignored lets an operator believe mail is configured
  on a service that has no mailer.
- **A pre-0.5.0 client cannot talk to a 0.5.0 server.** It sends an `email`
  field that no longer exists and calls endpoints that are gone. The `/health`
  handshake (`PROTOCOL.md` §6) is what turns that into a clear refusal instead
  of a partial failure.
- **Signup invites now carry an `si_` prefix.** A token of the wrong shape is
  refused by a shape gate before any lookup, with the same answer an unknown or
  spent invite gets. A gateway `gi_` token can no longer be posted here.

### Added

- **The recovery code is the second authenticator.** `POST /v1/auth/recover`
  and `POST /v1/auth/recover-rotate` let a user who holds their recovery code
  set a new passphrase. The client derives its proof under a new frozen HKDF
  label, `openplate-sync:recovery-auth:v1`, which is deliberately never the
  recovery-KEK label. Both endpoints are throttled per IP and handle, and both
  answer every failure identically.
- `accounts.recovery_verifier` (migration `0008`), stored with the same peppered
  `computeVerifier` the passphrase uses.
- **The operator notice.** `SYNC_NOTICE` and the optional `SYNC_NOTICE_URL` are
  published on the `/health` handshake and shown by the client. It is pull, not
  push: the service still has no way to contact anyone. A notice over 280
  characters, or a URL whose scheme is not http(s), or a URL without a notice,
  is a boot failure.

### Removed

- `src/mail/` and all three transports (pigeon, SMTP, console), the
  email-verification and auth-reset token kinds, and the reset-link plumbing.
  The mailed reset was an account-takeover path that returned no recovery: the
  DEK is wrapped under keys the server never sees, so whoever redeemed a link
  got a login to a diary they still could not read.

### Changed

- Anti-enumeration is unchanged. The signup `409` stays the one accepted oracle,
  and it now leaks an opaque per-server handle rather than a person's address,
  which is strictly less.
- `docker/compose.yml` forwards `SYNC_NOTICE` and `SYNC_NOTICE_URL`, which the
  README and `.env.example` already documented as operator settings.
- Docs: `PROTOCOL.md`, `SECURITY.md`, `README.md` and `.env.example` match the
  service. `docs/adr/0004-identity-without-email.md` records the decision.

### Upgrading

Losing both the passphrase and the recovery code ends an account. There is no
third path, because a reset the server could perform would mean a server that
can open your data. Say this to your users before you upgrade.

## [0.4.1] and earlier

Not recorded here. See the git history.
