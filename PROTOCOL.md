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
| **Handle**        | An opaque per-server account identifier. Never an address; may not contain an `@`.           |

## 3. Cryptography (client-side; the server implements none of it)

A conforming server needs none of this section — it is here so an alternative _client_ can interoperate, and so a reviewer can check the claims.

### 3.1 Key derivation

```
                          ┌─HKDF-SHA-256(salt, info=PASSPHRASE_KEK)──► KEK_p   (never sent)
passphrase ─Argon2id(salt, m, t, p)─► hash ─┤
                          └─HKDF-SHA-256(salt, info=AUTH)───────────► authHash (sent to the server)

                                     ┌─HKDF-SHA-256(salt="", info=RECOVERY_KEK)──► KEK_r            (never sent)
recovery code ───────────────────────┤
                                     └─HKDF-SHA-256(salt="", info=RECOVERY_AUTH)─► recoveryAuthHash (sent)
```

- **Argon2id** parameters (recorded per account in the passphrase key record's `kdfDescriptor` and in the account's own KDF descriptor, so they can be raised later without breaking existing accounts): `memorySizeKib: 65536` (64 MiB), `iterations: 3`, `parallelism: 1`, `hashLength: 32`. Salt: 16 random bytes.
- **HKDF `info` labels** are frozen byte strings, UTF-8 encoded. They provide domain separation so the derived values are cryptographically independent:
  - `openplate-sync:passphrase-kek:v1`
  - `openplate-sync:recovery-kek:v1`
  - `openplate-sync:auth:v1`
  - `openplate-sync:recovery-auth:v1`
- **The `auth` branch is what the client sends as its password.** It is a sibling of `KEK_p`, not a parent and not a child: both are HKDF outputs over the same Argon2id hash under different `info` labels, so possession of one gives no information about the other. This is the whole reason the server can authenticate a user it cannot decrypt for. `authHash` is 32 bytes, base64 on the wire.
- **The `recovery-auth` branch is what the client sends to prove possession of the recovery code** (§5.14). It is a sibling of `KEK_r` in exactly the sense `authHash` is a sibling of `KEK_p`, and it is 32 bytes, base64 on the wire.
- **The `recovery-auth` label is never the `recovery-kek` label.** That domain separation is load-bearing, not tidiness. The KEK branch derives the key that opens the diary; were the same output also sent to the server, this service would store an HMAC of the material that unwraps a DEK, and "the operator cannot read your data" would rest on SHA-256 being one-way rather than on the operator never having held the value. Both labels are frozen, neither is derived from the other, and a future change to either is a new `:v2` label rather than a redefinition (ADR-0004).
- The server never stores `authHash` or `recoveryAuthHash` either. It stores `HMAC-SHA-256(serverPepper, ...)` of each, with the pepper held outside the database. See §5.8.
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

**Why an opaque pair and not a JWT.** Revocation is load-bearing in this protocol: a passphrase change and a recovery-code rotation must invalidate every outstanding session _immediately_, and a user changing their passphrase under suspicion expects exactly that. A stateless token can only be made to expire, never to stop working, without adding the same server-side denylist that a database-backed opaque token already is.

**Why a pair at all.** The client must never persist the passphrase, so it cannot silently re-derive an auth-hash to log in again. A long-lived rotating refresh token is the only thing that makes silent re-authentication possible in a zero-knowledge design.

**Rotation and reuse detection.** Each pair carries a _family_ identifier that survives rotation.

- `POST /v1/auth/refresh` with a valid refresh token revokes it and returns a fresh pair in the same family.
- Presenting a refresh token that is **already revoked** is the reuse signal: the legitimate client rotated it, so whoever is presenting it now holds a copy they should not. The whole family is revoked. This logs out the attacker _and_ the real user, which is the correct outcome — the alternative leaves a thief with a working session.
- Access tokens minted by earlier rotations are deliberately left alone; they expire within minutes on their own, and revoking them at rotation time would break a request that is legitimately in flight.

**Revocation triggers.** Every one of these revokes **all** outstanding `access` and `refresh` tokens for the account:

- `POST /v1/auth/change-passphrase`
- `POST /v1/auth/recover-rotate`
- account deletion (by row cascade)

`POST /v1/auth/logout` revokes one family — that device — and leaves the account's other sessions alone.

**Session tokens are now the only kind.** Until 0.5.0 this store also held two single-use LINK kinds, minted to be put in a message: one confirmed an address, the other redeemed a mailed recovery link. Both went with the mailer (§5.12, §5.13). A service that holds no address cannot send a link, and `POST /v1/auth/recover` needs none: the credential it checks is the recovery code the user already holds.

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
{ "protocolVersion": 1, "envelopeVersion": 1, "serviceVersion": "0.1.0", "signupMode": "invite" }
```

`signupMode` is `open`, `invite` or `closed` (§5.8.1), and it is **optional**: a service older than the field omits it, and a client must treat its absence as "attempt the signup and handle the `403`" rather than as a refusal to talk. It is published because it is not a secret — `POST /v1/auth/signup` already discloses it to anyone who calls it — and it saves a client from provoking an error to decide which form to draw.

`notice` is the operator's message to every client, and it is **optional** in exactly the same sense: an instance with nothing to say omits the field, and a client that has never heard of it ignores it.

```json
{
  "protocolVersion": 1,
  "envelopeVersion": 1,
  "serviceVersion": "0.1.0",
  "notice": { "text": "This instance moves to a new address on 1 March.", "url": "https://example.org/moving" }
}
```

`text` is required when the field is present; `url` is optional and, when present, is an absolute `https:`/`http:` URL. The service caps `text` at 280 characters and refuses to boot on a longer one, because `/health` is also the container's HEALTHCHECK path and is polled continuously.

This is a **pull** channel and nothing more. The service holds no addresses (M181), never initiates, and cannot know who read a notice: a person who opens the app sees it, and a person who does not, does not. It is not a notification mechanism and must not be relied on as one — an operator who needs to be able to reach their users keeps that contact list themselves, outside this service.

A client MUST treat `text` and `url` as hostile input. They come from whatever server the user pointed at. Render `text` as text and never as markup, and follow `url` only after checking its scheme explicitly.

---

### 5.7 `POST /v1/auth/kdf` — pre-login KDF descriptor

Unauthenticated, IP-throttled. Returns the Argon2id salt and parameters a device needs to derive `authHash` before it can log in.

POST rather than GET, for what is a read: a GET puts the handle in the request line, and from there into access logs, proxy logs, `Referer` headers and browser history. An endpoint whose whole purpose is not disclosing who has an account should not scatter the identifier it was asked about.

Request: `{"handle": "qr7k4m2p"}` · Response `200`:

```json
{
  "kdfDescriptor": {
    "salt": "<base64, 16 bytes>",
    "params": { "memorySizeKib": 65536, "iterations": 3, "parallelism": 1 }
  }
}
```

**An unknown handle gets a descriptor too.** It is derived deterministically as `HMAC(serverSecret, handle)` over the canonical handle (§5.8), so it is stable across requests, identical in shape, and produced by the same code path. A `400` is returned only for input that could not be a handle at all. The move from addresses to handles changed nothing here: the derivation runs over an opaque string, and a handle is one.

This matters more than it looks. A zero-knowledge login _requires_ an unauthenticated, handle-keyed endpoint that answers before authentication; done naively it is a free, silent, unthrottleable list of which handles hold accounts. Stability is as load-bearing as the shape: a random dummy would be distinguishable by asking twice.

A conforming server MUST NOT return `404`, an empty body, or a different shape for an unknown handle. It must also:

- **Do the same work on both branches.** Derive the dummy unconditionally, including for accounts that exist and will never use it, so a hit and a miss cost the same lookup and the same HMAC. Deriving it lazily leaves a timing delta: the response says nothing, but how long it took to produce does.
- **Derive it over the canonical handle**, so two spellings of one unknown handle cannot be told apart by their descriptors.
- **Rate-limit by source address**, returning `429` with `Retry-After`. This is the other half of the same defence: the residual timing signal is statistical, and only emerges from many samples per handle. Denying the samples is what closes it. Keying the limit by the submitted handle would be worse than nothing, because probing many handles _is_ the attack, so a per-handle bucket hands out a fresh allowance for every handle the attacker wants to test.

### 5.8 `POST /v1/auth/signup`

Unauthenticated, IP-throttled.

```json
{
  "handle": "qr7k4m2p",
  "authHash": "<base64, 32 bytes>",
  "kdfDescriptor": { "...": "..." },
  "displayName": "optional or null",
  "recoveryAuthHash": "<base64, 32 bytes>, optional or null"
}
```

`handle` is the account's identifier: an opaque per-server string, canonicalised NFKC then trimmed then lowercased, non-empty, at most 64 characters, unique on the instance, and **never containing an `@`**. The client mints it and the user may edit it. The service has no other opinion about its shape and cannot resolve it to a person. The `@` rejection is what stops this field drifting back into an address register one signup at a time, and it is never relaxed (ADR-0004).

`recoveryAuthHash` is the second authenticator (§5.14), the `recovery-auth` HKDF branch of §3.1. It is **optional**, and absent and `null` both mean the same thing: this account has no second authenticator, so a lost passphrase ends it. A client that omits the field must say so to the user in those terms, at signup, while the recovery code is still on screen.

| Status | Meaning                                                                                                                                                                                                                                                          |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `201`  | `{"account": {"id": 1, "handle": "...", "displayName": null}, "tokens": {...}}`. A session is always issued; there is nothing left to confirm.                                                                                                                   |
| `400`  | A handle that is empty, over 64 characters or contains `@`; an `authHash` or `recoveryAuthHash` that is not 32 decoded bytes; or a descriptor without a 16-byte salt and positive Argon2id params.                                                               |
| `403`  | Either this instance is not accepting new accounts (`SIGNUP_MODE=closed`), or it requires an invite and none was given, or the one given was not valid (`SIGNUP_MODE=invite`). The two carry different `error` text; show the message rather than infer a cause. |
| `409`  | An account already exists for this handle.                                                                                                                                                                                                                       |
| `429`  | Throttled. `Retry-After` in seconds.                                                                                                                                                                                                                             |

The server stores `HMAC-SHA-256(serverPepper, authHash)`, and the same construction over `recoveryAuthHash` when one is supplied, **not** a second slow KDF over either. The client has already paid the memory-hard cost; hashing again server-side would add no brute-force resistance (an attacker holding the auth-hash has already skipped Argon2id) while creating a login-flood DoS in which every attempt pins 64 MiB. Peppering still defeats what peppering is for: with the pepper outside the database, a dumped table cannot be replayed against a live instance or checked offline against guesses.

**The `409` is a genuine account-enumeration oracle, the only one in this protocol, and it is accepted rather than removed.** The usual fix (always `202`, and move the truth into a message) needs a channel to send that message on. This service has none: it stores no address and has no mailer (§5.12, §5.13). A duplicate signup answered with `202` would tell the user their account was created when it was not, and nothing would ever arrive to correct it. The oracle-free variant is not merely inconvenient here; it does not exist.

**What it discloses is now strictly less.** It confirms that an opaque per-server handle is taken. It used to confirm that a named person's email address held an account, which is a value an attacker can also phish, correlate across services and sell. A handle is minted by the client, means nothing off this instance, and gives nobody a way to reach or identify its holder.

It is bounded by the per-IP signup throttle, removed entirely by `SIGNUP_MODE=closed`, narrowed but NOT removed by `SIGNUP_MODE=invite`, and deliberately not repeated anywhere else: `kdf`, `login`, `recover` and `recover-rotate` all stay indistinguishable. Full reasoning: [`SECURITY.md`](./SECURITY.md).

#### 5.8.1 Invites

On an instance running `SIGNUP_MODE=invite`, the signup body carries one extra field:

```json
{ "inviteToken": "<the token the operator gave you>" }
```

An invite is a single-use, expiring capability. It is **not** bound to a handle or to any identity, so anyone holding it may use it, once. Unknown, malformed, missing, expired and already-redeemed tokens all produce the SAME `403` and the same message: telling them apart would let a caller probe which tokens exist, and would disclose that a token had once been real.

**An invite token begins with `si_`, and the service refuses anything that does not.** The prefix binds the token to this service. A person is handed an invite in a chat message, and in a join link it may sit beside an `openplate-gateway` invite, which begins with `gi_`; without the prefix the two are interchangeable strings and one can be posted to the wrong service. The check is a **shape gate before the lookup**: a token of the wrong shape is never hashed against the invite table, and it is refused with the same `403` and the same message as every other bad invite, so the gate adds no oracle. Session tokens carry no prefix and are unchanged.

A signup that fails for any other reason does **not** consume the invite. In particular a `409` (handle already registered) leaves it spendable, so a typo does not cost somebody their invitation. The service enforces this with a conditional update inside a transaction, so concurrent redemptions of one invite still produce exactly one account.

Instances advertise their mode on the `/health` handshake as `signupMode` (§5.6). Treat it as a hint for rendering the right form; the `403` remains the contract, because an operator can change the mode between the handshake and the submit.

### 5.9 `POST /v1/auth/login`

Unauthenticated, throttled per IP **and** handle. A `401` counts against that bucket and a success clears it, which slows a single-source brute force without letting anyone lock a victim out of their own account from another address.

Request `{"handle": "...", "authHash": "..."}` → `200` `{"account": {...}, "tokens": {...}}`.

`400` when `handle` is not a plausible handle or `authHash` is not 32 base64-decoded bytes: the request never reaches the credential check, so this status carries no information about whether the account exists. `401` for an unknown account and for a wrong auth-hash, with **identical** body text and after **identical work**, because the verifier comparison runs on both branches against a full-width stand-in. `429` when throttled.

### 5.10 `POST /v1/auth/refresh`

Unauthenticated (the refresh token is the credential). Request `{"refreshToken": "..."}` → `200` `{"tokens": {...}}`. See §4.2 for rotation and reuse detection. Every failure is `401`.

### 5.11 `POST /v1/auth/logout`

Bearer. `204`. Revokes the caller's token family — this device only.

### 5.12 `POST /v1/auth/verify-email` — removed in 0.5.0

Gone with the mailer. This service stores no address, so there is nothing to confirm.

The number is retired rather than reused, and §5.13 with it. `§5.n` references appear in source comments across both repos, and silently renumbering would turn every one of them into a lie.

### 5.13 `POST /v1/auth/request-reset` — removed in 0.5.0

Gone with the mailer, and this is the removal worth explaining.

It mailed a link whose holder could replace the account's verifier, KDF descriptor and key records. On a zero-knowledge service that is an account-**takeover** path that returns no recovery: the DEK is wrapped under a passphrase-KEK and a recovery-KEK the server never sees, so whoever redeemed the link got a login to a diary they still could not read, and could destroy the real owner's access on the way. Whoever controlled a mailbox controlled the accounts registered to it, and got nothing readable for it.

Its replacement is the recovery code the user already holds (§5.14). Unlike a link, that code both authenticates **and** unwraps, because the user holds it and the server never has. Reasoning in full: [`docs/adr/0004-identity-without-email.md`](./docs/adr/0004-identity-without-email.md).

The one enumeration weakness this document used to record went with the endpoint. `request-reset` was the path where timing was _not_ equalised, because a known address cost a token write and a mail send that an unknown address did not. No such path exists now.

### 5.14 `POST /v1/auth/recover`, `POST /v1/auth/recover-rotate` and `POST /v1/auth/change-passphrase`

The recovery-code authenticator, and the two credential rotations. `recover-rotate` and `change-passphrase` take the same submission shape because they do the same thing; only the proof differs.

**`POST /v1/auth/recover`** — unauthenticated, throttled per IP **and** handle. Request `{"handle": "...", "recoveryAuthHash": "<base64, 32 bytes>"}` → `200` `{"account": {...}, "tokens": {...}}`.

What comes back is an ordinary session, deliberately not a lesser one: the holder of the recovery code is the account owner by construction, and a restricted "recovery mode" token would add a second authorization surface carrying no property the code does not already carry.

```jsonc
// POST /v1/auth/recover-rotate — unauthenticated, proof is the recovery code
{
  "handle": "...",
  "recoveryAuthHash": "<the current recovery proof>",
  "newAuthHash": "<new>",
  "kdfDescriptor": {...},
  "keyRecords": [ ... ],
  "newRecoveryAuthHash": "<a new recovery proof>" | null  // optional: rotate the code too
}

// POST /v1/auth/change-passphrase — bearer, proof is the current passphrase
{ "currentAuthHash": "...", "newAuthHash": "...", "kdfDescriptor": {...}, "keyRecords": [ ... ] }
```

`keyRecords` entries are `{"kind": "passphrase" | "recovery", "kdfDescriptor": {...} | null, "wrappedDek": "<base64>"}`, at most one per kind, obeying the same rules as §5.4 (a `recovery` record's descriptor must be `null`; a `passphrase` record's must not be).

`change-passphrase` returns `200` `{"tokens": {...}}`. `recover-rotate` returns `200` `{"account": {...}, "tokens": {...}}`, because the caller arrived without a session and needs to know which account it just re-entered. Both hand back a fresh pair.

**The whole submission is applied atomically.** New verifier, new account KDF descriptor, an optionally new recovery verifier, upserted key records, revocation of every outstanding session, and the caller's new pair either all commit or none do. This is not an implementation detail. Every half-state is a distinct disaster the user cannot see until they try to read their own diary: a verifier without its re-wrapped record logs in and decrypts nothing, a record without its verifier cannot log in at all, and a rotated recovery verifier without its record leaves a code that authenticates and then unwraps nothing.

**`keyRecords` must be present**, even as `[]`. An absent key is a `400`, for the same reason `expectedUpdatedAt` is required in §5.4: silence must never be read as consent on a path that can strand data.

Kinds _not_ submitted are left untouched. A passphrase change re-wraps the DEK under a new `KEK_p`; the `recovery` record still wraps the same, unchanged DEK and remains valid.

Four rules apply to `recover-rotate` alone:

- **A `passphrase` key record is required**, and `[]` is a `400`. Unlike a passphrase change, this path necessarily changed `KEK_p`, so accepting a submission without the re-wrap would mint an account that logs in perfectly and decrypts nothing.
- **Rotating the recovery code is all-or-nothing.** `newRecoveryAuthHash` and a `recovery` key record must arrive together or not at all; either alone is a `400`. Half of that pair leaves a code that authenticates and unwraps nothing, or one that unwraps and cannot log in.
- **The write is a compare-and-swap on the recovery verifier the proof matched**, re-asserted inside the transaction. It is not the authentication, which already happened; it is what stops two concurrent recoveries from overwriting a credential the user has already been told is theirs.
- **One failure, four causes.** An unknown handle, an account that never set a recovery code, a wrong code, and a rotation that lost that compare-and-swap race all answer `401` with identical text, after identical work. A race must not be distinguishable from a bad guess, and a missing second authenticator must not be distinguishable from a missing account.

Both recovery endpoints share **one** throttle bucket per (IP, handle), and neither clears it on success. They authenticate the same secret, so a separate allowance for each would halve the cost of guessing it, and a legitimate recovery happens once, so no honest client needs its allowance back.

**What a rotation can and cannot do.** It restores **login**. It cannot restore **data**, because the server never held a key. A `change-passphrase` submitting `keyRecords: []` leaves a working account whose blob is permanently undecryptable, which is exactly why `recover-rotate` refuses that submission outright. A conforming client must say so, in those terms, before the user commits to the flow.

**If the passphrase and the recovery code are both lost, the account cannot be recovered.** Not by an endpoint, not by the operator, not by a support path: the server holds no key material with which to do it, which is the same fact that stops it reading the diary. What remains is an account nobody can open, and the only useful operation on it is deletion. A conforming client says this before it shows a recovery code, not after.

### 5.15 `GET /v1/auth/account` and `POST /v1/auth/delete`

Both bearer.

`GET /v1/auth/account` → `200` `{"account": {"id": 1, "handle": "...", "displayName": null}}`.

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
  Never the grantor's key records, KDF descriptor, verifier, handle or display
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

**Pre-1.0 latitude.** Until the first public release, `PROTOCOL_VERSION` stays `1` through breaking changes. Three have now been taken under it: the move from cookie to bearer authentication, the move of the sync routes from `/api/sync` to `/v1/sync`, and 0.5.0's removal of email. There are zero production blobs and no third-party implementations, so there is nothing to break. This paragraph is deleted at public release, and from then on the rules above are followed literally.

**0.5.0 is a breaking change to the auth contract**, and by the rules above it would bump `PROTOCOL_VERSION` on a released protocol. The auth field is `handle`, not `email`; `verify-email` and `request-reset` are gone (§5.12, §5.13); `recover` and `recover-rotate` are new (§5.14). It is taken under the latitude above, which means the §6 handshake does **not** catch it: a client older than 0.5.0 posting `email` gets a `400` it cannot repair, and the version numbers still match. That is acceptable exactly once, on a service with one test account that is deleted rather than migrated, and it is recorded here so nobody reads §6 as covering it. Reasoning: [`docs/adr/0004-identity-without-email.md`](./docs/adr/0004-identity-without-email.md).

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
- **The account itself**: a **handle**, an optional display name, an authentication verifier (a keyed hash of a keyed hash of the passphrase, see §5.8), a second verifier of the same construction over the recovery proof when the account has set one, and the account's KDF parameters. A handle is an opaque per-server identifier that the user chose or their client generated: it may not contain an `@`, it means nothing on any other instance, and this service cannot resolve it to a person. Since 0.5.0 it is the only field naming an account holder, and it names them to nobody. **No mailbox, no address, and no field that identifies a holder in the world outside this instance is stored.**
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

6. Serve a stable, real-shaped KDF descriptor for unknown handles (§5.7), doing identical work on both branches, and rate-limit the endpoint by source address. A `404`, a lazily-derived dummy, or an unthrottled endpoint each re-opens the enumeration oracle the rest of the design closes, by response, by timing, or by volume.
7. Store both verifiers as keyed hashes of the submitted `authHash` and `recoveryAuthHash` under a secret held outside the database. Never the submitted value itself, and never in plaintext.
8. Apply §5.14's rotation submissions atomically, and revoke every outstanding session on each of the triggers in §4.2.
9. Reject any handle containing `@` (§5.8), and throttle `recover` and `recover-rotate` on one shared bucket per (IP, handle). A server that accepts addresses as handles is not implementing this protocol; it is re-introducing the field 0.5.0 removed.
10. Cascade account deletion to blobs and key records.

A conforming server needs **none** of: the crypto in §3, JSON parsing of any payload, or knowledge of what a food log is.

## 11. Implementing an alternative client

Beyond §3 and the 409 loop of §5.1:

- Perform the §6 handshake before the first sync and refuse on mismatch.
- Never persist the passphrase, either KEK, or the DEK to any durable storage. Derive on unlock, hold in memory, discard.
- Run Argon2id off the main thread. At 64 MiB it visibly freezes low-end phones.
- Show the handle and the recovery code together, once, at setup, as one saved account card behind an explicit "I have saved this" acknowledgment. A handle is not memorable the way an address was, and the code is the only recovery path that exists at all: there is no mailed reset, and nothing the operator can do (§5.14).
- Derive the recovery proof under `openplate-sync:recovery-auth:v1` and **never** send `KEK_r`. The two are siblings over the same code, and sending the KEK branch would hand the server an HMAC of the value that opens the diary (§3.1).
- Say, before the user commits, that losing the passphrase _and_ the recovery code ends the account. Say it in those words. Any softer phrasing promises a recovery that cannot exist.
- Treat `404` from `GET /blob` as "new account", not as an error.
- Send `authHash` — the `auth` HKDF branch of §3.1 — and never the passphrase, the Argon2id output, or `KEK_p`. Deriving the wrong branch is silent: it authenticates fine and produces a key that decrypts nothing.
- Fetch the KDF descriptor (§5.7) before deriving anything on a new device. Do not assume the defaults; an account created under raised parameters will not derive correctly from them.
- Keep the refresh token in the same storage tier as the access token and **never** reuse a spent one — a replay revokes the whole family and logs the user out (§4.2). Serialize refreshes; two tabs racing the same refresh token look exactly like a theft.
- On `401`, refresh once and retry once. On a second `401`, send the user to log in rather than looping.
