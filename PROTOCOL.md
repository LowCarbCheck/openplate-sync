# openplate sync protocol

**Protocol version: 1** · **Envelope version: 1** · Status: pre-1.0, nothing shipped

This is the normative specification of the wire protocol between an openplate client and a sync service. It is written so a third party can implement **either side** without reading our code: an alternative client that syncs against our hosted service, or an alternative server that an openplate client can be pointed at with `SYNC_SERVER_URL`.

The machine-readable counterpart lives in two files that are hand-maintained duplicates of each other:

| Repo             | File                              |
| ---------------- | --------------------------------- |
| `openplate-sync` | `src/protocol.ts`                 |
| `openplate`      | `app/lib/sync/engine/protocol.ts` |

Each repo has a unit test asserting its constants against transcribed literals (`tests/unit/protocol.test.ts` and `tests/unit/sync-engine/protocol.test.ts`). There is no shared CI between the repos, so those tests are the only thing standing between us and a silent protocol split. **This document is normative; the TypeScript is its transcription.**

---

## 1. The one-paragraph summary

The client holds all the keys. It serializes its whole local store, gzips it, encrypts it with AES-256-GCM under a key the server has never seen, and pushes the result as one opaque blob. The server stores bytes, versions them, and refuses writes that would clobber another device's. It also stores two small **key records** — the same data-encryption key wrapped under two different key-encryption keys, one derived from the user's passphrase and one from a recovery code — so a second device can bootstrap. The server cannot decrypt any of it. That is not a policy; it is what the math permits.

## 2. Terminology

| Term              | Meaning                                                                                      |
| ----------------- | -------------------------------------------------------------------------------------------- |
| **DEK**           | Data-encryption key. Random 32 bytes. Encrypts the blob. Never leaves the client unwrapped.  |
| **KEK**           | Key-encryption key. Wraps the DEK. Two exist: passphrase-derived and recovery-code-derived.  |
| **Envelope**      | The encrypted blob's wire format: `iv ‖ AES-256-GCM(gzip(JSON(payload)))`.                   |
| **Key record**    | One wrapped DEK, plus (passphrase kind only) the KDF parameters needed to re-derive its KEK. |
| **`blobVersion`** | Monotonic per-account counter. The compare-and-swap token.                                   |
| **Account**       | The unit of isolation. One account has at most one current blob and at most two key records. |

## 3. Cryptography (client-side; the server implements none of it)

A conforming server needs none of this section — it is here so an alternative _client_ can interoperate, and so a reviewer can check the claims.

### 3.1 Key derivation

```
                          ┌─HKDF-SHA-256(salt, info=PASSPHRASE_KEK)──► KEK_p   (never sent)
passphrase ─Argon2id(salt, m, t, p)─► hash ─┤
                          └─HKDF-SHA-256(salt, info=AUTH)───────────► authHash (sent to the server)

recovery code ────────────────────────────────HKDF-SHA-256(salt="", info=RECOVERY_KEK)──► KEK_r
```

- **Argon2id** parameters (recorded per account in the passphrase key record's `kdfDescriptor` and in the account's own KDF descriptor, so they can be raised later without breaking existing accounts): `memorySizeKib: 65536` (64 MiB), `iterations: 3`, `parallelism: 1`, `hashLength: 32`. Salt: 16 random bytes.
- **HKDF `info` labels** are frozen byte strings, UTF-8 encoded. They provide domain separation so the derived values are cryptographically independent:
  - `openplate-sync:passphrase-kek:v1`
  - `openplate-sync:recovery-kek:v1`
  - `openplate-sync:auth:v1`
- **The `auth` branch is what the client sends as its password.** It is a sibling of `KEK_p`, not a parent and not a child: both are HKDF outputs over the same Argon2id hash under different `info` labels, so possession of one gives no information about the other. This is the whole reason the server can authenticate a user it cannot decrypt for. `authHash` is 32 bytes, base64 on the wire.
- The server never stores `authHash` either. It stores `HMAC-SHA-256(serverPepper, authHash)`, with the pepper held outside the database — see §5.8.
- The recovery path deliberately skips Argon2id and uses an **empty HKDF salt**. That is correct, not an oversight: RFC 5869 §3.1 permits it when the input key material is already high-entropy, which a 160-bit random code is by construction. Only low-entropy human passphrases need a memory-hard stretch and a real salt.
- **Recovery code**: 20 random bytes (160 bits), rendered in a Crockford-style base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ` — no `O`, `I`, `L` to survive transcription) in groups of 5.
- KEKs are 256-bit AES-GCM keys, imported non-extractable.

### 3.2 The envelope

```
build:  payload ─► JSON ─► UTF-8 ─► gzip ─► AES-256-GCM(key=DEK, iv=random 12B, aad=AAD) ─► iv ‖ ciphertext‖tag
parse:  split(iv, rest) ─► AES-256-GCM decrypt ─► gunzip ─► UTF-8 ─► JSON ─► payload
```

- **IV**: 12 random bytes, fresh per encryption, packed as the **leading bytes of `ciphertext`**. There is no separate IV field anywhere in this protocol.
- **Tag**: the 16-byte GCM authentication tag is appended to the ciphertext (WebCrypto's convention).
- **AAD** is the UTF-8 encoding of a canonical, fixed-key-order JSON object:

  ```json
  {"accountId":<int>,"blobVersion":<int>,"payloadSchemaVersion":<int>}
  ```

  Binding these defeats cut-and-paste (replaying a blob into a different account) and rollback (replaying an older version, or a payload from an incompatible local-store schema). A client must present the identical triple when decrypting or the tag check fails — which is the intended behaviour, not an error to work around.

- **Compression** (`gzip`, RFC 1952) is applied to the plaintext **before** encryption. Ciphertext is incompressible, so it is compress-first or not at all. See §8 for why this matters and §9.2 for the honest statement of what it leaks.

- **Payload** shape (everything inside `snapshot` is opaque to this protocol):

  ```json
  {
    "snapshot": { "...": "the client's local-store snapshot, protocol-opaque" },
    "syncMeta": {
      "perEntity": { "<entityId>": { "lamport": 3, "deviceId": "abc" } },
      "tombstones": [{ "entityId": "x", "entityType": "foodLog", "lamport": 4, "deviceId": "abc" }]
    }
  }
  ```

- **Wrapped DEK**: `iv ‖ AES-256-GCM(key=KEK, plaintext=DEK)`, **no AAD** — a wrapped DEK is not bound to any particular blob version. Length is always `12 + 32 + 16 = 60` bytes.

### 3.3 Merge semantics (client-side)

Conflicts are resolved per entity by `(lamport, deviceId)`: higher Lamport counter wins; ties break on lexicographic `deviceId`. Device wall-clock is explicitly **not** an ordering authority — it drifts and is trivially wrong across devices. A tombstone participates in the same comparison as a live value. Accepted v1 trade-off: whole-record last-writer-wins, so a concurrent offline edit to the _same_ entity on two devices loses the older write silently. No field-level merge, no conflict UI.

### 3.4 The share wrap (ADR-0002)

A **share** is a third wrapping of the same DEK, addressed to another account's
public key. The server stores it, serves it to the one account it is addressed
to, and holds no key for it — §9.1 is unchanged by this feature.

```
sender (grantor, holding recipientPub):
  (ephPriv, ephPub) ← ECDH P-256, fresh per wrap, discarded after
  Z         ← ECDH(ephPriv, recipientPub)
  KEK_share ← HKDF-SHA-256(salt = empty, IKM = Z,
                           info = "openplate-sync:share-kek:p256:v1")
  AAD       ← UTF-8 of canonical fixed-key-order JSON:
              {"grantorAccountId":<int>,"recipientKeyFingerprint":"<base64>"}
  wrap      ← ephPub(65, uncompressed SEC1) ‖ iv(12) ‖ AES-256-GCM(KEK_share, DEK, aad=AAD)
```

- **Length is 125 bytes**, always. Note this is a *different* invariant from
  §3.2's 60-byte wrapped DEK: 60 for a key record, 125 for a share. They live in
  different tables and no shared validation path branches on length.
- **P-256**, and the curve is named in the label rather than only the version, so
  a future construction is a new label instead of an ambiguity about `:v1`.
- **The empty HKDF salt is correct**, on the same RFC 5869 §3.1 grounds §3.1
  already records for the recovery code: the IKM is a fresh, high-entropy ECDH
  output, not a human secret needing a memory-hard stretch.
- **This wrap carries AAD; the §3.2 wrapped DEKs do not.** A key-record wrap is
  scoped by an owner-only row and cannot be confused with anyone else's. A share
  wrap sits in a server-controlled association table, where it could be: binding
  it means a spliced row fails its tag check rather than decrypting into the
  wrong diary.
- **The AAD binds the recipient's key fingerprint, not the grantee's account id.**
  Substitution attacks the key, so the key is what the binding names — and the
  grantee reconstructs the AAD from a fingerprint computed locally, so no
  server-supplied value enters the trust path.
- `recipientKeyFingerprint` is `SHA-256` of the raw uncompressed public key. The
  server stores it as pinning metadata and **never** endorses, serves or
  generates a public key; the authoritative pinned key lives inside the
  grantor's own encrypted snapshot.

**A grantee must trial-decrypt.** §3.2's blob AAD binds `payloadSchemaVersion`,
which §7 defines as an opaque integer that never appears on the wire. An owner
knows its own; a grantee does not know the grantor's. So a grantee attempts
decryption across the schema versions its build supports and takes the one whose
GCM tag verifies. This is cheap, and it is the intended behaviour — do not add a
plaintext schema-version field to solve it.

### 3.5 The research contribution envelope (ADR-0003)

A **contribution** is a reduced, date-bounded slice of the diary, encrypted to a
study's public key. It is a different artifact from a share, not a narrower one:
different payload, different key, different lifecycle, and **no DEK is involved**
— the wrap is over the payload directly.

**The pseudonym.** A per-account random 256-bit root lives in the owner-private
compartment, so it survives a recovery restore and reaches a second device.

```
pid = HMAC-SHA-256(root, "openplate-sync:study-pseudonym:v1" ‖ uint64be(studyAccountId))
      truncated to the leading 128 bits, Crockford base32, 26 characters
```

**The bytes are fixed, because an underspecified concatenation is two
implementations that disagree in one deployment.** The label is its UTF-8
bytes with no terminator; `studyAccountId` is **8 bytes, unsigned,
big-endian, always eight** — never its decimal text and never a
minimal-length encoding. The output is the MAC's leading 16 bytes in the
Crockford base32 alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no check
symbol, no hyphens), which is exactly 26 upper-case characters. A client
deriving over the id's ASCII digits produces a well-formed pseudonym that
joins up with nothing.

Stable across a contributor's submissions, unlinkable across studies (HMAC
outputs under different messages are independent), and underivable by anyone
holding both the account table and a cohort. `H(accountId ‖ studyId)` would
*not* have that last property: with public inputs it reverses by enumeration.

The pseudonym defends against the **researcher**, not the server. The server
authenticates the push by bearer token and therefore knows the account behind
every row regardless — see §9.2.

**The envelope.**

```
  (ephPriv, ephPub) ← ECDH P-256, fresh per contribution
  Z         ← ECDH(ephPriv, studyPub)
  KEK       ← HKDF-SHA-256(salt = empty, IKM = Z,
                           info = "openplate-sync:research-kek:p256:v1")
  AAD       ← UTF-8 of canonical fixed-key-order JSON:
              {"studyAccountId":<int>,"pseudonym":"<string>",
               "contributionVersion":<int>,"schemaTier":"<string>",
               "studyKeyFingerprint":"<base64>"}
  body      ← ephPub(65) ‖ iv(12) ‖ AES-256-GCM(KEK, payload, aad = AAD)
```

A new frozen label rather than a version of the share label: different purpose,
same reasoning that put the curve in the name.

**The AAD carries no account id, and neither does any study-side response.**
This is the deliberate inversion of §5.16, where `grantorAccountId` is required
because §3.2's AAD binds it. Every AAD field here is reconstructible by the
researcher before decryption — four ride in the response, and the fingerprint she
computes locally from her own key.

**The payload is a fixed tier**, selected by name. A study chooses a tier and a
window; it never supplies a field list. v1 defines one:

`daily-intake:v1` — one row per calendar day in the window, with `date` (day
granularity, no timestamps), `energyKcal`, `proteinG`, `carbsG`, `fatG`,
`fiberG`, `loggedEntryCount`. The count exists because a researcher cannot
otherwise tell "ate nothing" from "did not log"; it is a count, never the
entries.

A new field is a protocol revision, never a configuration. See ADR-0003.

## 4. Transport conventions

- All request and response bodies are `application/json`.
- Binary fields (`ciphertext`, `wrappedDek`) are **base64** strings (standard alphabet, with padding). They are not sent as a binary content type, deliberately: every field of every request should be readable by a self-hoster debugging their own instance.
- Timestamps are ISO-8601 UTC strings, e.g. `2026-08-04T10:11:12.000Z`.
- Every non-2xx response body is `{"error": "<human-readable text>"}`. The text is diagnostic only — clients must branch on the **status code**, never on the message.
- Requests exceeding the body limit are rejected with `413`.

### 4.1 Authentication

A bearer token in an `Authorization: Bearer <token>` header. **No cookies, in either direction.**

- `Access-Control-Allow-Origin: *`, and `Access-Control-Allow-Credentials` is never sent. Any openplate client — ours, a self-hoster's on their own domain, or a third-party implementation — can therefore talk to any instance of this service regardless of origin.
- That combination is safe precisely _because_ there is no ambient credential. A hostile page can issue a cross-origin request and will get a `401`, because the browser has nothing to attach automatically. This is the CSRF property cookies lack, and it is the reason the wide-open origin is a considered choice rather than a shortcut.
- Unauthenticated callers get `401`. Authenticated-but-not-permitted callers get `403`. A conforming server must not conflate them.

This replaced a same-origin session cookie that existed while the handler cores were mounted inside the openplate app. That change, and the move of the sync routes from `/api/sync` to `/v1/sync`, are **pre-1.0 and do not bump `PROTOCOL_VERSION`**: zero production blobs exist, there are no third-party implementations, and no deployed client can be broken by them. Once this document is published alongside a public release, that latitude ends — see §7.

### 4.2 Token lifecycle

Two token kinds, both opaque random strings, both stored **only as SHA-256 digests**. A dumped token table yields nothing replayable, and unstretched SHA-256 is correct here because the pre-image is 256 bits of randomness — there is no dictionary to run.

| Token     | Lifetime | Purpose                                                                               |
| --------- | -------- | ------------------------------------------------------------------------------------- |
| `access`  | 15 min   | Sent on every request. Short, because a leaked one is useful for as long as it lives. |
| `refresh` | 30 days  | Exchanged for a new pair. Rotating — every use spends it.                             |

**Why an opaque pair and not a JWT.** Revocation is load-bearing in this protocol: a passphrase change and both reset paths must invalidate every outstanding session _immediately_, and a user changing their passphrase under suspicion expects exactly that. A stateless token can only be made to expire, never to stop working, without adding the same server-side denylist that a database-backed opaque token already is.

**Why a pair at all.** The client must never persist the passphrase, so it cannot silently re-derive an auth-hash to log in again. A long-lived rotating refresh token is the only thing that makes silent re-authentication possible in a zero-knowledge design.

**Rotation and reuse detection.** Each pair carries a _family_ identifier that survives rotation.

- `POST /v1/auth/refresh` with a valid refresh token revokes it and returns a fresh pair in the same family.
- Presenting a refresh token that is **already revoked** is the reuse signal: the legitimate client rotated it, so whoever is presenting it now holds a copy they should not. The whole family is revoked. This logs out the attacker _and_ the real user, which is the correct outcome — the alternative leaves a thief with a working session.
- Access tokens minted by earlier rotations are deliberately left alone; they expire within minutes on their own, and revoking them at rotation time would break a request that is legitimately in flight.

**Revocation triggers.** Every one of these revokes **all** outstanding `access` and `refresh` tokens for the account:

- `POST /v1/auth/change-passphrase`
- `POST /v1/auth/reset`
- account deletion (by row cascade)

`POST /v1/auth/logout` revokes one family — that device — and leaves the account's other sessions alone.

Link tokens (email verification, reset) live in the same store with their own kinds and lifetimes (24 h and 1 h respectively). They are single-use, and requesting a new reset link revokes any outstanding one.

## 5. Endpoints

Two families, under one versioned namespace:

| Family               | Prefix                         | Auth                        |
| -------------------- | ------------------------------ | --------------------------- |
| Sync (§5.1–§5.5)     | `/v1/sync` (`SYNC_API_PREFIX`) | Bearer, always              |
| Handshake (§5.6)     | `/health`                      | None                        |
| Account (§5.7–§5.15) | `/v1/auth`                     | Mixed — stated per endpoint |

Paths in §5.1–§5.5 are written relative to `SYNC_API_PREFIX`; everything else is absolute.

### 5.1 `POST /blob` — push (compare-and-swap)

Request:

```json
{ "baseVersion": 3, "envelopeVersion": 1, "ciphertext": "<base64>" }
```

- `baseVersion` — the `blobVersion` the client believes is currently stored. `0` asserts "this account has no blob yet".
- The write is accepted **only if** `baseVersion` equals the account's current version. This is the entire concurrency model. There is no force-push and no `If-Match`-less write.

Responses:

| Status      | Body                    | Meaning                                                                                                                       |
| ----------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| `200`       | `{"newVersion": 4}`     | Accepted. The blob is now at `newVersion`.                                                                                    |
| `409`       | `{"currentVersion": 5}` | Lost the race. Another device wrote first.                                                                                    |
| `400`       | `{"error": "..."}`      | `baseVersion` not a non-negative integer, `envelopeVersion` not a positive integer, `ciphertext` absent/not base64, or empty. |
| `413`       | `{"error": "..."}`      | Blob exceeds `MAX_BLOB_BYTES`.                                                                                                |
| `401`/`403` | `{"error": "..."}`      | Not authenticated / not permitted.                                                                                            |

**The 409 recovery loop is mandatory client behaviour**, not an optimization: pull `currentVersion`, decrypt it, merge it with local state (§3.3), re-encrypt with the AAD bound to the _new_ `blobVersion`, and push again with `baseVersion: currentVersion`. A client that treats `409` as a fatal error will strand the user's device permanently out of sync.

### 5.2 `GET /blob` — pull

| Status | Body                                                                                                                |
| ------ | ------------------------------------------------------------------------------------------------------------------- |
| `200`  | `{"blobVersion": 4, "envelopeVersion": 1, "ciphertext": "<base64>", "createdAt": "<iso>"}`                          |
| `404`  | `{"error": "..."}` — this account has never pushed a blob. Not an error condition; it is how a fresh account looks. |

### 5.3 `GET /key-records` — list

```json
{
  "records": [
    {
      "kind": "passphrase",
      "kdfDescriptor": { "salt": "<base64>", "params": { "memorySizeKib": 65536, "iterations": 3, "parallelism": 1 } },
      "wrappedDek": "<base64>",
      "updatedAt": "<iso>"
    },
    { "kind": "recovery", "kdfDescriptor": null, "wrappedDek": "<base64>", "updatedAt": "<iso>" }
  ]
}
```

Returns `{"records": []}` for an account that has not completed setup. At most one record per `kind`.

### 5.4 `PUT /key-records/:kind` — create or rotate (compare-and-swap)

`:kind` is `passphrase` or `recovery`; anything else is `400`.

Request:

```json
{ "kdfDescriptor": { "...": "..." } | null, "wrappedDek": "<base64>", "expectedUpdatedAt": "<iso>" | null }
```

- `expectedUpdatedAt: null` asserts **"no record of this kind exists yet"** (first-time setup).
- Any other value asserts **"the record I last read had exactly this `updatedAt`"** (rotation).
- **The key must be present.** An absent `expectedUpdatedAt` is a `400`, deliberately: a caller must not be able to skip the concurrency check by forgetting a field.

Validation, all `400`:

- empty `wrappedDek`
- `kind: "recovery"` with a non-null `kdfDescriptor` (the recovery path is HKDF-only; there are no parameters to record)
- `kind: "passphrase"` with a null `kdfDescriptor`

Responses:

| Status | Body                                                                      |
| ------ | ------------------------------------------------------------------------- |
| `200`  | The stored record, same shape as a `GET /key-records` entry.              |
| `409`  | `{"currentUpdatedAt": "<iso>" \| null}` — the CAS assertion did not hold. |

### 5.5 `DELETE /key-records/:kind`

`204`, no body. Idempotent — deleting a record that does not exist is still `204`.

> Deleting the **only remaining** key record makes every stored blob permanently undecryptable. The server does not prevent this; a client must not offer it without an unmistakable warning.
>
> **A share (§5.16) does not count as a key record here.** It is cryptographically a third wrap of the same DEK, but it is another person's capability — revocable by them, unverifiable by you, and dependent on their continued cooperation and honesty. Deleting both key records still bricks the account with live shares in existence, and no client may ever offer "recover your data through your dietician" as a recovery path.

### 5.6 `GET /health` — version handshake

Unauthenticated, deliberately: a client must be able to discover that it is incompatible _before_ it has credentials, and a healthcheck that needed a token would be reporting on the token.

```json
{ "protocolVersion": 1, "envelopeVersion": 1, "serviceVersion": "0.1.0" }
```

---

### 5.7 `POST /v1/auth/kdf` — pre-login KDF descriptor

Unauthenticated, IP-throttled. Returns the Argon2id salt and parameters a device needs to derive `authHash` before it can log in.

POST rather than GET, for what is a read: a GET puts the email in the request line, and from there into access logs, proxy logs, `Referer` headers and browser history. An endpoint whose whole purpose is not disclosing who has an account should not scatter the address it was asked about.

Request: `{"email": "person@example.com"}` · Response `200`:

```json
{
  "kdfDescriptor": {
    "salt": "<base64, 16 bytes>",
    "params": { "memorySizeKib": 65536, "iterations": 3, "parallelism": 1 }
  }
}
```

**An unknown email gets a descriptor too.** It is derived deterministically as `HMAC(serverSecret, email)` — stable across requests, identical in shape, produced by the same code path. A `400` is returned only for input that could not be an email address at all.

This matters more than it looks. A zero-knowledge login _requires_ an unauthenticated, email-keyed endpoint that answers before authentication; done naively it is a free, silent, unthrottleable list of which addresses hold accounts. Stability is as load-bearing as the shape: a random dummy would be distinguishable by asking twice.

A conforming server MUST NOT return `404`, an empty body, or a different shape for an unknown address. It must also:

- **Do the same work on both branches.** Derive the dummy unconditionally, including for accounts that exist and will never use it, so a hit and a miss cost the same lookup and the same HMAC. Deriving it lazily leaves a timing delta — the response says nothing, but how long it took to produce does.
- **Rate-limit by source address**, returning `429` with `Retry-After`. This is the other half of the same defence: the residual timing signal is statistical, and only emerges from many samples per address. Denying the samples is what closes it. Keying the limit by the submitted email would be worse than nothing — probing many addresses _is_ the attack, so a per-email bucket hands out a fresh allowance for every address the attacker wants to test.

### 5.8 `POST /v1/auth/signup`

Unauthenticated, IP-throttled.

```json
{
  "email": "...",
  "authHash": "<base64, 32 bytes>",
  "kdfDescriptor": { "...": "..." },
  "displayName": "optional or null"
}
```

| Status | Meaning                                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------------------------- |
| `201`  | `{"account": {...}, "tokens": {...} \| null}`. `tokens` is `null` when the server requires email verification.         |
| `400`  | Malformed email, `authHash` not 32 decoded bytes, or a descriptor without a 16-byte salt and positive Argon2id params. |
| `403`  | This instance is not accepting new accounts (`SIGNUPS_OPEN=false`).                                                    |
| `409`  | An account already exists for this email.                                                                              |
| `429`  | Throttled. `Retry-After` in seconds.                                                                                   |

The server stores `HMAC-SHA-256(serverPepper, authHash)`, **not** a second slow KDF over it. The client has already paid the memory-hard cost; hashing again server-side would add no brute-force resistance (an attacker holding the auth-hash has already skipped Argon2id) while creating a login-flood DoS in which every attempt pins 64 MiB. Peppering still defeats what peppering is for: with the pepper outside the database, a dumped table cannot be replayed against a live instance or checked offline against guesses.

**The `409` is a genuine account-enumeration oracle — the only one in this protocol — and it is accepted rather than removed.** The usual fix (always `202`, move the truth into an email) requires guaranteed mail delivery, and this service's default configuration has none: with `REQUIRE_EMAIL_VERIFICATION` off and the console mail transport, a duplicate signup answered with `202` would tell the user their account was created when it was not, with no email arriving to correct it. The oracle-free variant is therefore unavailable in the configuration most self-hosters run, not merely inconvenient.

It is bounded by the per-IP signup throttle, removed entirely by `SIGNUPS_OPEN=false`, and deliberately not repeated anywhere else: `kdf`, `login` and `request-reset` all stay indistinguishable. Full reasoning: [`SECURITY.md`](./SECURITY.md).

### 5.9 `POST /v1/auth/login`

Unauthenticated, throttled per IP **and** email.

Request `{"email": "...", "authHash": "..."}` → `200` `{"account": {...}, "tokens": {...}}`.

`401` for an unknown account and for a wrong auth-hash, with **identical** body text. `403` if verification is required and the address is unconfirmed. `429` when throttled.

### 5.10 `POST /v1/auth/refresh`

Unauthenticated (the refresh token is the credential). Request `{"refreshToken": "..."}` → `200` `{"tokens": {...}}`. See §4.2 for rotation and reuse detection. Every failure is `401`.

### 5.11 `POST /v1/auth/logout`

Bearer. `204`. Revokes the caller's token family — this device only.

### 5.12 `POST /v1/auth/verify-email`

Unauthenticated. Request `{"token": "..."}` → `200` `{"verified": true}`. Single-use; an invalid, expired or already-redeemed token is `400`.

### 5.13 `POST /v1/auth/request-reset`

Unauthenticated, IP-throttled. Request `{"email": "..."}` → **always** `202`, whether or not the address has an account. The only channel that reveals anything is the email itself, and only to whoever controls the inbox.

### 5.14 `POST /v1/auth/reset` and `POST /v1/auth/change-passphrase`

The two credential-rotation endpoints. They take the same submission shape because they do the same thing; only the proof differs.

```jsonc
// POST /v1/auth/reset — unauthenticated, proof is the emailed token
{ "token": "...", "authHash": "<new>", "kdfDescriptor": {...}, "keyRecords": [ ... ] }

// POST /v1/auth/change-passphrase — bearer, proof is the current passphrase
{ "currentAuthHash": "...", "newAuthHash": "...", "kdfDescriptor": {...}, "keyRecords": [ ... ] }
```

`keyRecords` entries are `{"kind": "passphrase" | "recovery", "kdfDescriptor": {...} | null, "wrappedDek": "<base64>"}`, at most one per kind, obeying the same rules as §5.4 (a `recovery` record's descriptor must be `null`; a `passphrase` record's must not be).

Both return `200` `{"tokens": {...}}` — a fresh pair for the caller.

**The whole submission is applied atomically.** New verifier, new account KDF descriptor, upserted key records, revocation of every outstanding session, and the caller's new pair either all commit or none do. This is not an implementation detail: a new verifier stored without the re-wrapped DEK produces an account that logs in fine and can never decrypt its own blob again, with nothing to tell the user until they try.

**`keyRecords` must be present**, even as `[]`. An absent key is a `400`, for the same reason `expectedUpdatedAt` is required in §5.4: silence must never be read as consent on a path that can strand data.

Kinds _not_ submitted are left untouched. A passphrase change re-wraps the DEK under a new `KEK_p`; the `recovery` record still wraps the same, unchanged DEK and remains valid.

**What reset can and cannot do.** It restores **login**. It cannot restore **data** — the server never held a key. A client that submits `keyRecords: []` gets a working account whose blob is permanently undecryptable. A conforming client must say so, in those terms, before the user commits to the flow.

### 5.15 `GET /v1/auth/account` and `POST /v1/auth/delete`

Both bearer.

`GET /v1/auth/account` → `200` `{"account": {"id": 1, "email": "...", "displayName": null, "emailVerified": false}}`.

`POST /v1/auth/delete` takes `{"authHash": "..."}` and returns `204`. **Re-authentication is required even though the caller already holds a valid token**: a session left behind on a shared device must not be enough to destroy someone's data irreversibly.

Deletion removes the account and, by cascade, every blob and key record it owns. There is no soft delete and no grace period. This is the self-serve erasure path, and it is complete by construction rather than by a cleanup job someone has to remember to run.

### 5.16 Shares — `/v1/sync/shares` and `/v1/sync/shared` (ADR-0002)

**Present only when the deployment sets `SYNC_SHARING`.** Without it every path
below answers the ordinary unknown-route `404`, to every caller, credentialed or
not — the terminator is mounted *ahead* of authentication, so an unconfigured
instance is indistinguishable from one where the feature was never written.

Both sides address a share by the **counterpart's account id**, never by a
synthetic share id: the stable identity of a share is the (grantor, grantee)
pair, and that is what survives a DEK rotation.

**Grantor side.**

| Verb | Path | Notes |
| --- | --- | --- |
| `PUT` | `/shares/:granteeAccountId` | `{"wrappedDek": "<base64>", "recipientKeyFingerprint": "<string>", "expectedUpdatedAt": "<iso>" \| null}`. CAS exactly as §5.4: `null` asserts no share exists yet, any other value asserts the row last read had this `updatedAt`, and an **absent** key is a `400`. `409` returns `{"currentUpdatedAt": "<iso>" \| null}`. |
| `GET` | `/shares` | The grantor's own grants. **Never returns `wrappedDek`** — a blob addressed to somebody else's key has no use here, so it does not travel where nobody needs it. |
| `DELETE` | `/shares/:granteeAccountId` | `204`, idempotent. A **hard delete**; there is no tombstone. |

**Grantee side.**

| Verb | Path | Notes |
| --- | --- | --- |
| `GET` | `/shared` | Shares addressed to this caller, each with its `wrappedDek` — only this caller can open it. |
| `GET` | `/shared/:grantorAccountId/blob` | `{"grantorAccountId": <int>, "blobVersion": <int>, "envelopeVersion": <int>, "ciphertext": "<base64>", "createdAt": "<iso>"}`. **`grantorAccountId` is required**: §3.2's AAD binds it, so a grantee without it cannot decrypt at all. |
| `DELETE` | `/shared/:grantorAccountId` | `204`, idempotent. Lets a grantee drop a share aimed at them. |

- **The grantee surface has no write verbs against the grantor**, and serves only
  the caller's own share row, the grantor's current blob, and `grantorAccountId`.
  Never the grantor's key records, KDF descriptor, verifier, email or display
  name. A grantee who could pull the grantor's `recovery` wrapped DEK would be
  one brute-forced recovery code away from rotation authority over that account.
- **Only the current blob.** The retained version ring is an owner-recovery
  mechanism, not a grantee timeline.
- **Authorisation is a live row read on every request, never cached.** That is
  what makes a `DELETE` effective on the very next call.
- Unknown, foreign and never-pushed all answer the **same** `404`. Absence of a
  share must not confirm that an account exists.

### 5.17 `POST /v1/sync/rotate-dek` — atomic DEK rotation (ADR-0002)

Bearer, as the account **owner**. One submission, one transaction:

```json
{
  "blob": { "baseVersion": 3, "envelopeVersion": 1, "ciphertext": "<base64>" },
  "keyRecords": [{ "kind": "passphrase", "kdfDescriptor": { "...": "..." }, "wrappedDek": "<base64>" }],
  "shares": [{ "granteeAccountId": 7, "wrappedDek": "<base64>", "recipientKeyFingerprint": "<string>" }]
}
```

The client generates a new DEK, re-encrypts its whole snapshot under it,
re-wraps it under both KEKs, and re-wraps it to every share it is keeping. The
service stores the result **all or nothing**.

**Present on every deployment**, unlike §5.16. Rotation is not part of the
sharing surface: it rewrites the caller's own blob and their own two key
records, rows that exist on every account everywhere, and it is the answer to
any belief that a DEK leaked — a restored backup, a lost device — on an
instance that has never shared anything. Gating the only mechanism that can
retire a compromised DEK behind an unrelated flag would leave such an operator
with no way to retire one.

- **All-or-nothing, in one database transaction.** ADR-0002 prohibition 8: a
  rotation is atomic or it does not exist, and no sequence of individually
  committing endpoints may be documented or used as one. A partial application
  is the "logs in fine, decrypts nothing" brick §5.14 already refuses to
  permit, with one more participant — a key record re-wrapped while the blob
  write lost its CAS strands the owner, and a share re-wrapped while the blob
  write lost its CAS strands the clinician.
- **`blob` is compare-and-swapped on `baseVersion`**, exactly as §5.1. A stale
  value is a `409` `{"currentVersion": n}` and nothing at all is written.
- **`keyRecords` must carry BOTH kinds.** A missing kind is a `400`, never a
  silent partial rotation: submitting only the `passphrase` wrap would leave
  the `recovery` record wrapping a DEK that no longer opens anything, so the
  recovery code would still log the account in and never again decrypt it.
  Each entry obeys §5.4's rules (a `recovery` descriptor must be `null`, a
  `passphrase` descriptor must not). There is no per-record
  `expectedUpdatedAt`: the submission itself is the concurrency unit.
- **`shares` is the KEEP list, and every share row not named in it is deleted
  in the same transaction.** This inverts §5.14, where an untouched key record
  is kept — deliberately, because these rows are somebody else's capability on
  the caller's diary and silence must be the safe default. `shares: []`
  therefore revokes everything, and is valid; an **absent** `shares` key is a
  `400`, for the reason §5.4 requires `expectedUpdatedAt` to be written out.
  On a deployment without `SYNC_SHARING` the list must be empty — a non-empty
  one is a `400`, since it asserts state that instance cannot hold.
- **A named share that does not exist is a `400`**, rolled back whole, never
  treated as a grant. The grantee may have dropped their side; re-read
  `GET /v1/sync/shares` and resubmit.
- **The retained older blob versions (§8) stay sealed under the OLD DEK** and
  become dead weight the moment a rotation commits — unreadable to everyone,
  including their owner. They are not deleted here: pruning clears them within
  five further pushes, and dropping them during a rotation would throw away
  the owner's only defence against a bad client write in the same operation.

| Status | Body |
| ------ | ---- |
| `200` | `{"newVersion": 4, "keptShares": 1, "revokedShares": 2}` |
| `400` | `{"error": "..."}` — a missing key-record kind, a malformed or absent field, a keep list naming a share that is not there. |
| `409` | `{"currentVersion": 5}` — the blob CAS did not hold. Nothing was written. |
| `413` | `{"error": "..."}` — the new blob exceeds `MAX_BLOB_BYTES`. |

**Rotation is Tier 2 revocation, and the wording rules of §5.16 still bind.**
Deleting a share row stops the server serving; rotating adds that future
entries are sealed with a key the revoked party never had. Neither repossesses
what was already downloaded, and no client may say otherwise.

### 5.18 Research contributions — `/v1/sync/contributions` and `/v1/sync/study` (ADR-0003)

**Present only when the deployment sets `SYNC_RESEARCH`.** Absent, every path
below answers the ordinary unknown-route 404 to every caller, credentialed or
not, with the terminator mounted ahead of authentication. Independent of
`SYNC_SHARING`; neither flag implies the other.

**Contributor side**, authenticated as the contributor:

| Verb | Path | Notes |
| --- | --- | --- |
| `PUT` | `/contributions/:studyAccountId` | `{"pseudonym","schemaTier","body","contributionVersion"}`. CAS on a monotonic `contributionVersion`. The contribution is the cumulative dataset for the window, recomputed and re-pushed whole — the client always holds the source, so this row is a projection, never a primary copy. |
| `GET` | `/contributions` | The contributor's own enrolments. Never returns `body`. |
| `DELETE` | `/contributions/:studyAccountId` | **Withdrawal.** One transaction: hard-delete the row, insert a pseudonym-keyed tombstone. `204`, idempotent. |

**Study side**, authenticated as the study account:

| Verb | Path | Notes |
| --- | --- | --- |
| `GET` | `/study/contributions` | `{"pseudonym","contributionVersion","schemaTier","body","createdAt"}` per row. **No account id, ever.** |
| `GET` | `/study/withdrawals` | Pseudonyms that withdrew, with timestamps. The study client must purge these before presenting or exporting anything. |

`GET /study/contributions` echoes `studyAccountId` **once, at the top level of
the envelope**, not on every row: it is the caller's own id, it authenticated as
it, it is identical for every row, and it is not a contributor identifier. The
researcher needs it to rebuild §3.5's AAD, and per-row it would be noise.

**The `contributionVersion` compare-and-swap.** The submitted value **is the new
version**, not a base — it binds into the AAD, so it must be the value the
ciphertext was sealed under. The rule is **strictly greater than the stored
one**: a client that recomputes and re-pushes the whole projection must never be
wedged by a version that never left the device. A losing write is `409
{"currentVersion": <int>}`, matching §5.1's shape.

**The server validates `schemaTier` against the tiers this protocol defines.**
The tier name is metadata, not content — it travels in the clear and the server
already stores it — and without this check ADR-0003's prohibition 1 has no teeth
anywhere but the client. An unknown tier is `400`.

**The server does not validate the pseudonym's shape**, only that it is present
and bounded. It cannot verify one — that would need the contributor's root — and
a structural check would imply an authority it does not have.

| Status | When |
| --- | --- |
| `400` | malformed body, unknown `schemaTier`, absent `contributionVersion` |
| `404` | unknown study, unknown contribution, and any other not-found — one code path |
| `409` | `contributionVersion` not strictly greater than the stored one |
| `413` | contribution exceeds `MAX_CONTRIBUTION_BYTES` (256 KiB) |

**One pseudonym per study, enforced by the database.** Two contributors
submitting the same pseudonym would silently merge into one participant series,
and a researcher would analyse two people as one with nothing failing. An
accidental collision is about 2^-128, so the constraint should never fire —
which is the point: it makes the corruption impossible rather than improbable.

**Withdrawal is genuinely erasing on this side.** A contribution the study has
not yet pulled reaches nobody. What the study already pulled cannot be
repossessed — the tombstone carries the instruction, and honouring it is an
ethics obligation this system states and cannot enforce.

## 6. Version handshake — required, and required to fail closed

**A client MUST read this document from the service and check it before its first sync of a session.**

This replaces an in-process version check that existed when the client and server shipped as one artifact. They no longer do: a deployed client and a deployed service can drift by a release in either direction, and a self-hoster can point a current client at a service they upgraded eight months ago. Nothing about that situation is detectable from a successful `200` on a push.

Rules:

1. `protocolVersion` **must equal** the client's own. Not "≥", not "compatible-ish".
2. `envelopeVersion` **must equal** the client's own.
3. On any **mismatch**, the client **refuses to sync** and shows the user which side is older. It does not push, does not pull, does not retry, and does not silently degrade.
4. If the handshake is unreachable or malformed, treat it as a mismatch. An unverifiable service is not a compatible one.

The reference implementation is `checkProtocolCompatibility()` in both `protocol.ts` files — pure, total, and returning a user-presentable sentence rather than a boolean.

**Why refusal rather than best-effort:** the blob is frequently the user's only copy of their data. A client that pushes an envelope a newer service frames differently, or decrypts one it half-understands, can corrupt that copy irrecoverably. A refused sync is a visible inconvenience; a silently wrong sync is a data-loss incident discovered weeks later. This protocol chooses the inconvenience every time.

## 7. Versioning policy

- **`PROTOCOL_VERSION`** covers endpoints, request/response shapes, status-code semantics, the auth scheme, and CAS semantics. Bump for any breaking change to those. Purely additive changes (a new optional response field, a new endpoint older clients never call) do not bump it.
- **`ENVELOPE_VERSION`** covers the blob's crypto and framing only: cipher, IV placement, compression codec, tag handling. Bump for any of those. **Never** bump it for a payload schema change.
- **`payloadSchemaVersion`** is the client's local-store schema version. It travels through this protocol as an opaque integer bound into the AAD. The server never interprets it, and it never affects either version above.

The two version numbers are independent on purpose: re-framing the crypto and re-shaping the HTTP API are different kinds of change with different blast radii.

**Pre-1.0 latitude.** Until the first public release, `PROTOCOL_VERSION` stays `1` through breaking changes. Two have already been taken under it: the move from cookie to bearer authentication, and the move of the sync routes from `/api/sync` to `/v1/sync`. There are zero production blobs and no third-party implementations, so there is nothing to break. This paragraph is deleted at public release, and from then on the rules above are followed literally.

## 8. Size limits and the capacity plan

| Limit                   | Value                        | Enforced by                                              |
| ----------------------- | ---------------------------- | -------------------------------------------------------- |
| Max blob size           | 2 MiB (`MAX_BLOB_BYTES`)     | Service (`413`), mirrored client-side for a better error |
| Blob versions retained  | 5 (`BLOB_VERSION_RETENTION`) | Service, pruned oldest-first after each accepted write   |
| Key records per account | 2 (one per `kind`)           | Service                                                  |

**The capacity cliff, stated plainly.** One blob holds the account's _entire_ store. Food-log entries run roughly 400–700 bytes of JSON each before compression, so an uncompressed blob would cross 2 MiB within about 2–4 years of daily logging. That is not a theoretical concern; it is a date.

`ENVELOPE_VERSION` 1 gzips the plaintext, which buys roughly an order of magnitude on JSON this repetitive (the same key names on every one of thousands of records) and pushes the cliff far enough out to not be the near-term problem. It does not remove it.

**The planned fix, so it is not discovered under pressure:** chunked or per-entity blobs — many small ciphertexts with independent versions, instead of one monolith. That is a genuine change to the framing and the endpoints, so it will be a **protocol version bump**, not a patch. Operationally, the trigger to start that work is blob sizes crossing ~80% of the cap in the field, which the service logs a warning for (M128 spec 02). The cliff should be observable long before any user reaches it.

## 9. What the server knows

### 9.1 What it cannot know

The server never receives the DEK, either KEK, the passphrase, or the recovery code. It stores `wrappedDek` blobs it has no key for. Decryption is not withheld by policy — it is unavailable.

### 9.2 What it does know

Being honest about the metadata, because "end-to-end encrypted" is often heard as "the server knows nothing":

- **Blob size**, and therefore an approximation of how much data the account holds. Compression makes this a fuzzier signal than it was, not a hidden one.
- **Write frequency and timing** — when a device syncs, and how often.
- **Version numbers**: `blobVersion`, `envelopeVersion`, and the number of retained versions.
- **KDF parameters and salt** for the passphrase record. These are not secrets; they exist to be served to a new device before login.
- **Whether an account has completed setup** (has key records) and whether it has ever synced (has a blob).
- **The account itself**: an email address, an optional display name, an authentication verifier (a keyed hash of a keyed hash of the passphrase — see §5.8), the account's KDF parameters, and whether the address has been confirmed.
- **Session metadata**: how many active sessions exist, when each was created, and when tokens were last rotated or revoked. Token values themselves are stored only as digests.
- **The study graph**, on a deployment with `SYNC_RESEARCH` set (§5.18): which
  account contributes to which study, when, how often, and how large each
  contribution is. An edge here says "this person's health data is in study Y",
  which is health-adjacent personal data of the same class as the care edge
  below. It is **unavoidable**, and withdrawal is the proof: erasing a
  contributor's row requires locating it, account deletion must cascade through
  it, and both the compare-and-swap and abuse control key on the account. A
  scheme that blinded the server would break one of those and traffic analysis
  would un-blind it anyway, so this is disclosed rather than half-avoided. The
  researcher never receives the mapping (§5.18 carries no account id),
  withdrawal hard-deletes the edge and leaves only a pseudonym, and a deployment
  without the flag has no table to hold a study graph.
- **The sharing graph**, on a deployment with `SYNC_SHARING` set (§5.16): which account has granted read access to which other account, when the grant was made, and when the grantee exercises it. That is a relationship graph, and a genuine expansion of what this service knows, and in the setting the feature was built for — a patient and their dietician — an edge in that graph is itself health-adjacent personal data, because it says someone is under care. It is the minimum needed to authorise the read; both ends consent, since the grantor creates the row and the grantee can delete their side; and the edge is hard-deleted on revocation and cascades away when either account is deleted. A deployment that does not set `SYNC_SHARING` stores no such graph and has no table to put one in.

Not knowable from the above: what was eaten, when, how much, or anything else inside the payload.

## 10. Implementing an alternative server

A conforming **sync** server needs, in full:

1. The five endpoints of §5.1–§5.5 plus the `/health` handshake of §5.6.
2. Per-account CAS on `blobVersion` — atomic. The reference implementation uses a `UNIQUE (accountId, blobVersion)` index and treats a unique-violation as a conflict, rather than row locking; that stays correct under `READ COMMITTED` and is simpler than `SELECT ... FOR UPDATE`. Any mechanism with the same guarantee is fine; a read-then-write without atomicity is **not**.
3. Per-account-and-kind CAS on key records via `expectedUpdatedAt`, with the same "absent field is a `400`" rule.
4. Retention pruning to `BLOB_VERSION_RETENTION`.
5. Byte-exact storage of `ciphertext` and `wrappedDek`. Never re-encode, normalize, trim, or "fix" them. Any mutation destroys the GCM tag and with it the user's data.

Additionally, a server that also implements the **account** endpoints of §5.7–§5.15 must:

6. Serve a stable, real-shaped KDF descriptor for unknown emails (§5.7), doing identical work on both branches, and rate-limit the endpoint by source address. A `404`, a lazily-derived dummy, or an unthrottled endpoint each re-opens — by response, by timing, or by volume — the enumeration oracle the rest of the design closes.
7. Store the verifier as a keyed hash of the submitted `authHash` under a secret held outside the database — never the `authHash` itself, and never in plaintext.
8. Apply §5.14's rotation submissions atomically, and revoke every outstanding session on each of the triggers in §4.2.
9. Cascade account deletion to blobs and key records.

A conforming server needs **none** of: the crypto in §3, JSON parsing of any payload, or knowledge of what a food log is.

## 11. Implementing an alternative client

Beyond §3 and the 409 loop of §5.1:

- Perform the §6 handshake before the first sync and refuse on mismatch.
- Never persist the passphrase, either KEK, or the DEK to any durable storage. Derive on unlock, hold in memory, discard.
- Run Argon2id off the main thread. At 64 MiB it visibly freezes low-end phones.
- Show the recovery code exactly once, at setup, behind an explicit "I have saved this" acknowledgment. It is the only data-preserving recovery path that exists; an email-based reset can restore _login_, never data.
- Treat `404` from `GET /blob` as "new account", not as an error.
- Send `authHash` — the `auth` HKDF branch of §3.1 — and never the passphrase, the Argon2id output, or `KEK_p`. Deriving the wrong branch is silent: it authenticates fine and produces a key that decrypts nothing.
- Fetch the KDF descriptor (§5.7) before deriving anything on a new device. Do not assume the defaults; an account created under raised parameters will not derive correctly from them.
- Keep the refresh token in the same storage tier as the access token and **never** reuse a spent one — a replay revokes the whole family and logs the user out (§4.2). Serialize refreshes; two tabs racing the same refresh token look exactly like a theft.
- On `401`, refresh once and retry once. On a second `401`, send the user to log in rather than looping.
