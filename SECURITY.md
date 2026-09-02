# Security Policy

## Supported versions

Pre-1.0. Only the latest tagged release receives fixes — currently the `0.3.x` line.

## Reporting a vulnerability

**Please do not open a public issue for a suspected vulnerability.**

Report it privately via GitHub's [private vulnerability reporting](https://github.com/LowCarbCheck/openplate-sync/security/advisories/new). This opens a draft security advisory visible only to you and the maintainers, and is the only channel we triage for security reports.

This is a small open-source project maintained without a dedicated security team and with no bug bounty. There is no SLA, but reports are read and taken seriously — expect an initial response within a few days. If a report turns out to be valid, we will work with you on a fix and, if you want, credit you in the advisory when it is published.

## What "vulnerability" means for this service

openplate-sync is an account and end-to-end-encrypted sync service. The server stores a handle, opaque ciphertext blobs, and wrapped key records. It never receives a passphrase, a recovery code, a data-encryption key, or anything that decrypts a blob. See [`PROTOCOL.md`](./PROTOCOL.md) for the full design.

**Since 0.5.0 this service holds no email address and has no mailer.** An account is a handle plus a passphrase, where a handle is an opaque per-server string the client generated, the user may edit, and which may not contain an `@`. That removes an entire branch of this threat model: there is no mailbox whose compromise takes over an account, no mailed reset link, no verification token, and no address to phish, correlate or subpoena. The reasoning is in [`docs/adr/0004-identity-without-email.md`](./docs/adr/0004-identity-without-email.md); the short version is that a mailed reset on a zero-knowledge service was an account-takeover path that returned no recovery, because the link holder got a login to a diary that stayed sealed.

**The recovery code is the second authenticator.** `POST /v1/auth/recover` and `POST /v1/auth/recover-rotate` accept a proof derived from it under a frozen HKDF label that is deliberately not the recovery-KEK label, so the server never stores a keyed hash of the material that unwraps a DEK. Both endpoints share **one** throttle bucket per (IP, handle) and neither clears it on success: they authenticate the same secret, a separate allowance for each would halve the cost of guessing it, and a legitimate recovery happens once. An unknown handle, an account with no recovery code, a wrong code and a lost rotation race all answer with one identical `401`, after identical work. A way to tell those apart, or to get a fresh allowance on either endpoint, is a real report.

One enumeration tradeoff is accepted deliberately: `POST /v1/auth/signup` returns `409` on an existing account, which discloses that the handle is registered. It is accepted because there is no channel that could carry the news instead. The usual fix, always answering `202` and putting the truth in a message, needs a mailbox, and this service has none; a `202` here would simply tell the user their account was created when it was not, with nothing to correct it. The alternatives are worse than the disclosure: lie about the outcome, or sign in silently on an unverified passphrase guess.

**What that oracle leaks is now only an opaque handle, which is strictly less than it used to leak.** A confirmed hit says "this per-server string is taken". It used to say "this named person's email address holds an account here", which is a value an attacker can also phish, correlate across other services and sell. A handle is minted by the client, means nothing on any other instance, and gives nobody a way to reach or identify its holder.

Every other auth path (`kdf`, `login`, `recover`, `recover-rotate`) returns an indistinguishable RESPONSE for known vs. unknown handles, and does indistinguishable WORK: the dummy KDF descriptor is derived unconditionally over the canonical handle, and every verifier comparison runs against a full-width stand-in rather than being skipped. The one weakness this document used to record is gone with the endpoint that carried it: `request-reset` was **not** timing-equalised, because a known address cost a token write and a mail send that an unknown address did not. There is no such path now. Mitigations on the remaining oracle: a per-IP throttle on `signup`, and `SIGNUP_MODE=closed` to close the endpoint entirely on private instances.

`SIGNUP_MODE=invite` narrows the oracle rather than closing it, and the shape of that is worth stating plainly. An invite is **not** bound to a handle or to any identity, and it never was bound to an address: binding one would make this service store personal data about a person who has no account and never consented. The cost of leaving invites unbound is that a failed signup does not consume one (deliberately: a mistyped handle must not destroy somebody's invitation), so one invite holder can probe many handles through the `409`. It is bounded by the same per-IP throttle, and invite mode still exposes the oracle to strictly fewer people than `open` does — but it does not remove it. Only `closed` does that.

That threat model is exactly what makes some reports far more interesting than others. Please report:

- **Anything that lets the server (or an attacker with database access) decrypt or correlate a blob it should only ever see as opaque bytes.** The server is designed to never hold a key that unwraps a DEK — a bug that changes this is the most serious class of issue this project has.
- **Auth or token-handling flaws** — bypassing bearer-token checks, forging or replaying `access`/`refresh` tokens, breaking rotation/reuse detection, or any path that lets a session outlive a revocation trigger (`change-passphrase`, `recover-rotate`, account deletion).
- **Anything that breaks the atomicity of a credential rotation.** `recover-rotate` moves both verifiers and both key records in one transaction. A half-applied rotation is a silent data-loss bug, not a hiccup: the user logs in and decrypts nothing, or cannot log in at all, and finds out only when they open their diary.
- **KDF-descriptor downgrade tricks** — anything that lets a client or attacker force weaker Argon2id parameters than the account's recorded descriptor, or otherwise tamper with `kdfDescriptor` in a way the server should have rejected.
- **Account-enumeration beyond the documented tradeoff.** `POST /v1/auth/signup`'s `409` is the _only_ accepted oracle in this protocol. `kdf`, `login`, `recover` and `recover-rotate` are all designed to stay indistinguishable for known vs. unknown handles, in response shape and in work done. A way to distinguish them, or to bypass the throttle on `signup`, `kdf` or the shared recovery bucket, is a real report.
- Anything that breaks the compare-and-swap semantics on `/blob` or `/key-records/:kind` in a way that lets one device silently clobber another's data.

**Any report that even might fall into the "server can decrypt/correlate" or "breaks the enumeration protections" category should be reported privately, even if you are not sure it qualifies.** We would rather triage a false positive privately than have a real one discussed in a public issue.

## What is not a vulnerability: a lost passphrase and a lost recovery code

**If a user loses both their passphrase and their recovery code, the account cannot be recovered.** Not by an endpoint, not by the operator, not by us. This is by construction and is not a bug report.

The reason is the same fact the whole service rests on: the server holds no key material. The DEK is wrapped under a passphrase-KEK and a recovery-KEK it has never seen, and both verifiers are keyed hashes of values it cannot reverse. There is nothing on the server to restore access with, and any mechanism that could restore it would be a decryption capability sitting on the server, which would end the property this design exists to provide.

The consequence, stated plainly: the account still exists and still holds ciphertext, nobody can open it, and the only remaining useful operation is deletion, through the admin API of ADR-0001. Clients are required to say this before showing a recovery code, in those words (`PROTOCOL.md` §5.14 and §11).

A report that this is "a missing password reset" will be closed. A report that some other path _does_ restore access to such an account is the most serious class of issue this project has, and belongs in the private channel above.

Non-security bugs (crashes, incorrect sync behavior, docs errors, etc.) belong in regular [GitHub issues](https://github.com/LowCarbCheck/openplate-sync/issues), not here.
