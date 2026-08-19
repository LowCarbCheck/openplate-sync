# Security Policy

## Supported versions

Pre-1.0. The `0.1.x` line is the only one that receives fixes.

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/LowCarbCheck/openplate-sync/security/advisories/new). This opens a draft security advisory visible only to you and the maintainers, and is the only channel we triage for security reports.

This is a small open-source project maintained without a dedicated security team and with no bug bounty. There is no SLA, but reports are read and taken seriously — expect an initial response within a few days. If a report turns out to be valid, we will work with you on a fix and, if you want, credit you in the advisory when it is published.

## What "vulnerability" means for this service

openplate-sync is an account and end-to-end-encrypted sync service. The server stores an email address, opaque ciphertext blobs, and wrapped key records — it never receives a passphrase, a data-encryption key, or anything that decrypts a blob. See [`PROTOCOL.md`](./PROTOCOL.md) for the full design.

One enumeration tradeoff is accepted deliberately: `POST /v1/auth/signup` returns `409` on an existing account, which discloses that the address is registered. This is accepted because the service's default configuration has no email verification loop (mail is optional, and a family instance is expected to run without it) — closing the oracle would mean either lying to a user about whether their account was created, or silently signing in on an unverified passphrase guess, both worse than the disclosure. Every other auth path (`kdf`, `login`, `request-reset`) stays indistinguishable for known vs. unknown emails. Mitigations: a per-IP throttle on `signup`, and `SIGNUPS_OPEN=false` to close the endpoint entirely on private instances.

That threat model is exactly what makes some reports far more interesting than others. Please report:

- **Anything that lets the server (or an attacker with database access) decrypt or correlate a blob it should only ever see as opaque bytes.** The server is designed to never hold a key that unwraps a DEK — a bug that changes this is the most serious class of issue this project has.
- **Auth or token-handling flaws** — bypassing bearer-token checks, forging or replaying `access`/`refresh` tokens, breaking rotation/reuse detection, or any path that lets a session outlive a revocation trigger (`change-passphrase`, `reset`, account deletion).
- **KDF-descriptor downgrade tricks** — anything that lets a client or attacker force weaker Argon2id parameters than the account's recorded descriptor, or otherwise tamper with `kdfDescriptor` in a way the server should have rejected.
- **Account-enumeration beyond the documented tradeoff.** `POST /v1/auth/signup`'s `409` is the *only* accepted oracle in this protocol; `kdf`, `login`, and `request-reset` are all designed to stay indistinguishable for known vs. unknown emails, both in response shape and in timing. A way to distinguish them — or to bypass the per-IP throttle on `signup` or `kdf` — is a real report.
- Anything that breaks the compare-and-swap semantics on `/blob` or `/key-records/:kind` in a way that lets one device silently clobber another's data.

**Any report that even might fall into the "server can decrypt/correlate" or "breaks the enumeration protections" category should be reported privately, even if you are not sure it qualifies.** We would rather triage a false positive privately than have a real one discussed in a public issue.

Non-security bugs (crashes, incorrect sync behavior, docs errors, etc.) belong in regular [GitHub issues](https://github.com/LowCarbCheck/openplate-sync/issues), not here.
