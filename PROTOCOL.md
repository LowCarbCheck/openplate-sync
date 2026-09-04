# openplate sync protocol

**Protocol version: 2** · **Envelope version: 1** · Status: pre-1.0, nothing shipped

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
| **Email**         | The account identifier: a canonical address (NFKC, trimmed, lowercased). Unique per server.  |
| **Invite**        | A single-use capability ADDRESSED to one email, minted by an operator. The only way in.      |
| **Escrow**        | The account's recovery code, sealed on the server under a subkey of `SERVER_SECRET`.         |
| **Role**          | `admin` or `member`. An admin's own access token authenticates `/v1/admin`.                  |

**Protocol 2 replaced the handle with an email** (ADR-0005). Version 1's
`Handle` — an opaque per-server identifier that could not contain an `@` — is
gone: the column, the parser and the rule. A client speaking version 1 must
refuse to talk to a version 2 service rather than half-work; see §6.

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
- **Recovery code**: 20 random bytes (160 bits), rendered in a Crockford-style base32 alphabet (`0123456789ABCDEFGHJKMNPQRSTVWXYZ` — no `O`, `I`, `L` to survive transcription) in groups of 5. Canonically, 32 characters with the grouping removed and uppercased; that is the form the server seals.
- **The recovery code is ESCROWED on the server** (protocol 2, ADR-0005). The client no longer shows it to the person: it sends the raw code once in the signup body, and the server stores `iv(12) ‖ AES-256-GCM(escrowKey, code) ‖ tag(16)` in `accounts.recovery_code_escrow`, where `escrowKey` is a third frozen HMAC subkey of `SERVER_SECRET` (`openplate-sync:escrow-key:v1`, beside the verifier pepper and the dummy-descriptor key). A mailed reset (§5.12) hands the code back to the account holder, who then runs the ordinary §5.14 rotation with it. **The operator of a managed instance therefore holds what it takes to open a diary.** That is a real change to what this service is, it is stated here rather than buried, and it is argued in full in [`docs/adr/0005-organization-accounts-and-escrowed-recovery.md`](./docs/adr/0005-organization-accounts-and-escrowed-recovery.md).
- The escrow is over the CODE, not over `KEK_r` and not over the DEK. Nothing on the server derives a KEK, unwraps a DEK, or holds one — the code becomes a key only after a client runs HKDF over it. That buys no secrecy from the operator, who can run HKDF too; it buys a server whose code path contains no decryption of user data, which is what makes the claim checkable rather than promised.
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

- **Length is 125 bytes**, always. Note this is a _different_ invariant from
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
_not_ have that last property: with public inputs it reverses by enumeration.

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
- **A recovery code on the wire is Crockford base32 TEXT**, wherever it appears
  (`signup.recoveryCode`, `recover-rotate.recoveryCode`,
  `rotate-dek.recoveryCode`, and `reset/open`'s response). A server MUST accept
  it grouped or ungrouped and in either case, canonicalise it to **32 uppercase
  characters** with spaces and hyphens removed, seal THAT, and return that same
  canonical form from `reset/open`. One code therefore has one sealed form, so
  a re-escrow after a rotation is comparable with what was there before, and a
  client that renders the code in groups of five can post back what it rendered.
  A conforming client accepts both forms too.
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
- suspension by an operator
- account deletion (by row cascade)

`POST /v1/auth/logout` revokes one family — that device — and leaves the account's other sessions alone.

**Session tokens are the only kind in `account_tokens`.** Until 0.5.0 that table also held two single-use LINK kinds, minted to be put in a message: one confirmed an address, the other redeemed a mailed recovery link. Both went with the mailer, and neither came back. Protocol 2 has no address confirmation at all (the invitation is the verification, §5.8) and its reset link **replaces no credential** (§5.12).

**Two capability tokens live outside that table**, and both wear a prefix so one cannot be posted where the other belongs:

| Token          | Prefix | Lifetime | Stored in         | What it buys                                          |
| -------------- | ------ | -------- | ----------------- | ----------------------------------------------------- |
| Signup invite  | `si_`  | 7 d      | `signup_invites`  | Creates ONE account, at the address the invite names. |
| Password reset | `sr_`  | 60 min   | `password_resets` | Returns the account's escrowed recovery code, once.   |

Both are 256 bits of randomness, both are stored only as a SHA-256 digest, and both are single-use. Neither is ever accepted as an `Authorization: Bearer` credential, and a session token is never accepted in their place: the prefix is a shape gate applied before any lookup, and its rejection is the same generic failure a wrong token gets, so it adds no oracle.

**Suspension revokes too.** `accounts.suspended_at` being set revokes every outstanding `access` and `refresh` token in the same transaction, so a suspension takes effect immediately rather than when the current access token expires.

## 5. Endpoints

Two families, under one versioned namespace:

| Family               | Prefix                         | Auth                        |
| -------------------- | ------------------------------ | --------------------------- |
| Sync (§5.1–§5.5)     | `/v1/sync` (`SYNC_API_PREFIX`) | Bearer, always              |
| Handshake (§5.6)     | `/health`                      | None                        |
| Account (§5.7–§5.15) | `/v1/auth`                     | Mixed — stated per endpoint |

**A suspended account is refused everywhere.** `POST /login`, `POST /refresh`, `POST /recover`, `POST /recover-rotate`, every bearer-guarded route and the admin tree answer `403 {"error":"account-suspended"}` — that exact string, so a client can recognise it and say what happened. On `login` and the recovery paths the check runs AFTER the credential is verified, so an unknown address still gets the ordinary indistinguishable `401`.

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
{
  "protocolVersion": 2,
  "envelopeVersion": 1,
  "serviceVersion": "0.6.0",
  "instance": { "name": "openplate", "language": "de", "mail": true, "ai": { "model": "google/gemini-3.7-flash" } }
}
```

`instance` describes what this deployment is and what it can do, and it is **optional**: a service older than the field omits it, and a client that requires it would refuse to talk to every such instance. `name` is the operator's label for the instance, `language` is `en` or `de` (the two languages its mail is written in), `mail` says whether it can send a letter at all, and `ai` is `null` when no upstream key is configured.

It is **descriptive, never authoritative**. `mail: true` does not promise a letter arrives, and `ai` reports what the operator configured rather than granting anything — an account with `dailyAiLimit: 0` gets a `403` whatever this says.

`signupMode` is **gone** in protocol 2, along with the setting it described: signup is invite-only on every instance, always (§5.8). A service that still publishes it is speaking version 1.

`notice` is the operator's message to every client, and it is **optional** in exactly the same sense as `instance`: an instance with nothing to say omits the field, and a client that has never heard of it ignores it.

```json
{
  "protocolVersion": 2,
  "envelopeVersion": 1,
  "serviceVersion": "0.6.0",
  "notice": { "text": "This instance moves to a new address on 1 March.", "url": "https://example.org/moving" }
}
```

`text` is required when the field is present; `url` is optional and, when present, is an absolute `https:`/`http:` URL. The service caps `text` at 280 characters and refuses to boot on a longer one, because `/health` is also the container's HEALTHCHECK path and is polled continuously.

This is a **pull** channel and nothing more. It cannot know who read a notice: a person who opens the app sees it, and a person who does not, does not. It is not a notification mechanism and must not be relied on as one. Protocol 2 does give the service two letters it can send (an invitation and a password reset, §5.8 and §5.12), and neither is a channel for anything else: an operator who needs to announce something to their users keeps that contact list themselves, outside this service.

A client MUST treat `text` and `url` as hostile input. They come from whatever server the user pointed at. Render `text` as text and never as markup, and follow `url` only after checking its scheme explicitly.

---

### 5.7 `POST /v1/auth/kdf` — pre-login KDF descriptor

Unauthenticated, IP-throttled. Returns the Argon2id salt and parameters a device needs to derive `authHash` before it can log in.

POST rather than GET, for what is a read: a GET puts the address in the request line, and from there into access logs, proxy logs, `Referer` headers and browser history. An endpoint whose whole purpose is not disclosing who has an account should not scatter the identifier it was asked about. That argument was already true for a handle; with an address back on the wire it is the difference between a leak and a mailing list.

Request: `{"email": "anna@example.org"}` · Response `200`:

```json
{
  "kdfDescriptor": {
    "salt": "<base64, 16 bytes>",
    "params": { "memorySizeKib": 65536, "iterations": 3, "parallelism": 1 }
  }
}
```

**An unknown address gets a descriptor too.** It is derived deterministically as `HMAC(serverSecret, email)` over the canonical address (§5.8), so it is stable across requests, identical in shape, and produced by the same code path. A `400` is returned only for input that could not be an address at all. Neither the M181 move to handles nor the M192 move back to addresses changed a line of the derivation: it runs over an opaque string, and both are one.

This matters more than it looks. A zero-knowledge login _requires_ an unauthenticated, identifier-keyed endpoint that answers before authentication; done naively it is a free, silent, unthrottleable list of which addresses hold accounts. Stability is as load-bearing as the shape: a random dummy would be distinguishable by asking twice.

A conforming server MUST NOT return `404`, an empty body, or a different shape for an unknown address. It must also:

- **Do the same work on both branches.** Derive the dummy unconditionally, including for accounts that exist and will never use it, so a hit and a miss cost the same lookup and the same HMAC. Deriving it lazily leaves a timing delta: the response says nothing, but how long it took to produce does.
- **Derive it over the canonical address**, so two spellings of one unknown address cannot be told apart by their descriptors.
- **Rate-limit by source address**, returning `429` with `Retry-After`. This is the other half of the same defence: the residual timing signal is statistical, and only emerges from many samples per address. Denying the samples is what closes it. Keying the limit by the submitted address would be worse than nothing, because probing many addresses _is_ the attack, so a per-address bucket hands out a fresh allowance for every address the attacker wants to test.

### 5.8 `POST /v1/auth/signup`

Unauthenticated, IP-throttled. **An invite is the only way to create an account**, on every instance. There is no open mode and no closed mode; `SIGNUP_MODE` is a boot failure.

```json
{
  "inviteToken": "si_…",
  "authHash": "<base64, 32 bytes>",
  "kdfDescriptor": { "...": "..." },
  "displayName": "optional or null",
  "recoveryAuthHash": "<base64, 32 bytes>",
  "recoveryCode": "ABCDE-FGHJK-MNPQR-STVWX-YZ012-3456",
  "keyRecords": [
    { "kind": "passphrase", "kdfDescriptor": { "...": "..." }, "wrappedDek": "<base64>" },
    { "kind": "recovery", "kdfDescriptor": null, "wrappedDek": "<base64>" }
  ]
}
```

**There is no `email` field, and that is the point.** The address comes from the invite row, inside the transaction. A body cannot claim a mailbox the operator did not write to, which is what makes the invitation itself the address verification: the person who received the letter is the person redeeming it, so there is no confirmation link and nothing left to confirm afterwards. `role` and `dailyAiLimit` come from the invite for the same reason — an account never asks for its own standing.

`recoveryAuthHash`, `recoveryCode` and BOTH key records are **required**. Each was optional in protocol 1 and none is now:

- The client no longer shows the recovery code to the person (§3.1), so an account created without an escrow is one no reset can ever restore, and its owner was never warned.
- A `passphrase` record is what lets the passphrase decrypt anything; without it the account logs in and reads nothing, and the client has discarded the passphrase by the time it would find out.
- A `recovery` record is what lets the escrowed code unwrap; without it a mailed reset delivers a credential that authenticates and opens nothing, discovered on the day it is needed.

`recoveryCode` is validated as Crockford base32 of 20 bytes — 32 characters once spaces and hyphens are stripped and the value is uppercased — and canonicalised to that form before it is sealed. It is never logged, in any form, on any path.

| Status | Meaning                                                                                                                                                                   |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `201`  | `{"account": AccountView, "tokens": {...}}` (§5.15). A session is always issued; there is nothing left to confirm.                                                        |
| `400`  | An `authHash`, `recoveryAuthHash` or `recoveryCode` of the wrong shape; a descriptor without a 16-byte salt and positive Argon2id params; or `keyRecords` missing a kind. |
| `403`  | `{"error":"invite-invalid"}` — the invite is missing, malformed, of another service, unknown, expired, revoked or already redeemed. All seven, one answer.                |
| `409`  | An account already exists for the invite's address. The invite is NOT consumed.                                                                                           |
| `429`  | Throttled. `Retry-After` in seconds.                                                                                                                                      |

The server stores `HMAC-SHA-256(serverPepper, authHash)`, and the same construction over `recoveryAuthHash`, **not** a second slow KDF over either. The client has already paid the memory-hard cost; hashing again server-side would add no brute-force resistance (an attacker holding the auth-hash has already skipped Argon2id) while creating a login-flood DoS in which every attempt pins 64 MiB. Peppering still defeats what peppering is for: with the pepper outside the database, a dumped table cannot be replayed against a live instance or checked offline against guesses.

**The whole submission commits in one transaction**: the invite redemption, the account row, the sealed escrow and both key records. Every half-state is a distinct disaster the user cannot see until they try to read their own diary.

**The `409` is the one enumeration oracle in this protocol, and protocol 2 made it almost nothing.** It is reachable only by somebody holding a live invite that was ADDRESSED to the very address it reports as taken, so it confirms only what the operator wrote on the letter. In protocol 1 an invite holder could probe arbitrary handles with one invite; they cannot now, because the address is not theirs to choose. It does not consume the invite, so an operator who invited somebody twice by mistake has not destroyed the live invitation. Full reasoning: [`SECURITY.md`](./SECURITY.md).

#### 5.8.1 Invites

An invite is a single-use, expiring capability **addressed to one person**. It carries the address the account will be created with, the operator's guess at a name, the role and the daily AI allowance. Unknown, malformed, missing, wrong-service, expired, revoked and already-redeemed tokens all produce the SAME `403` and the same body, `{"error":"invite-invalid"}`: telling them apart would let a caller probe which tokens exist, and would disclose that a token had once been real.

**An invite token begins with `si_`, and the service refuses anything that does not.** The prefix binds the token to this service and to this endpoint. A person is handed an invite in a mail, beside a password-reset token that begins with `sr_`; without the prefixes the two are interchangeable strings and one can be posted to the wrong endpoint. The check is a **shape gate before the lookup**, refused with the same status and the same body as every other bad invite, so the gate adds no oracle. Session tokens carry no prefix and are unchanged.

Minting is `POST /v1/admin/invites`. An older PENDING invite for the same address is revoked by a new one, so there is never more than one live capability per address; an address that already has an account cannot be invited at all (`409`).

#### 5.8.2 `POST /v1/auth/invite-lookup`

Unauthenticated, IP-throttled. Request `{"inviteToken": "si_…"}`.

```json
{ "email": "anna@example.org", "displayName": "Anna", "expiresAt": "2026-09-11T10:00:00.000Z" }
```

The client calls it when a person opens the link in their mail, so the sign-up form can SHOW the address the letter went to instead of asking them to type it. That is the whole point of an addressed invite: they cannot mistype their own address into an account nobody can reach.

It shows nothing else. The role and the allowance the invite grants are deliberately absent: a person who has not signed up has no business learning that the operator made them an admin, and a caller holding a stranger's link has less business still.

Unknown, malformed, wrong-service, expired, revoked and spent tokens are ONE `404 {"error":"invite-invalid"}`, after identical work: the token is hashed and the table is queried on every branch. A valid lookup consumes nothing, so a person who opens the link twice still has an invitation.

### 5.9 `POST /v1/auth/login`

Unauthenticated, throttled per IP **and** email. A `401` counts against that bucket and a success clears it, which slows a single-source brute force without letting anyone lock a victim out of their own account from another address.

Request `{"email": "...", "authHash": "..."}` → `200` `{"account": AccountView, "tokens": {...}}`.

`400` when `email` is not a plausible address or `authHash` is not 32 base64-decoded bytes: the request never reaches the credential check, so this status carries no information about whether the account exists. `401` for an unknown account and for a wrong auth-hash, with **identical** body text and after **identical work**, because the verifier comparison runs on both branches against a full-width stand-in. `403 {"error":"account-suspended"}` when the account is suspended — checked AFTER the credential, so only somebody who has proved they own the account is told why the door is shut. `429` when throttled.

### 5.10 `POST /v1/auth/refresh`

Unauthenticated (the refresh token is the credential). Request `{"refreshToken": "..."}` → `200` `{"tokens": {...}}`. See §4.2 for rotation and reuse detection. Every failure is `401`, except a suspended account, which is `403 {"error":"account-suspended"}` and does NOT spend the presented token: a suspension may be lifted, and burning it would log the person out of a device they are getting back. The distinct status is what stops a client looping on this endpoint forever.

### 5.11 `POST /v1/auth/logout`

Bearer. `204`. Revokes the caller's token family — this device only.

### 5.12 `POST /v1/auth/reset/request` and `POST /v1/auth/reset/open` — the mailed reset

These numbers were retired in 0.5.0, when `verify-email` and `request-reset` went with the mailer. Protocol 2 reuses them, and reusing them rather than taking two new ones is deliberate: what stands here now is the answer to what stood here before, and a reader following a `§5.12` reference from a source comment should land on the resolution rather than on a tombstone.

**§5.12.1 `POST /v1/auth/reset/request`** — unauthenticated, throttled per (IP, email), NEVER cleared on success.

Request `{"email": "anna@example.org"}` → `202 {}`, always.

`202` for a known address, an unknown one and a malformed one alike. A conforming server MUST do the same work on both branches: mint the token, digest it, and only then skip the store write and the send when there is no account. That symmetry is the whole anti-enumeration argument, and it is the one this document previously recorded as MISSING — the old `request-reset` did the expensive work only for addresses that existed, so its timing said what its body did not.

A `400` is never returned, not even for a value that is obviously not an address: the status code would become a free oracle for the shape of the addresses this instance holds, and there is nothing a caller could usefully do with the distinction.

The token is 32 random bytes, base64url, prefixed `sr_`. Only its SHA-256 digest is stored, in `password_resets`, with a **60-minute** TTL. **One live token per account**: a new request marks every older unconsumed row consumed, in the same transaction, so a person scrolling up in their inbox cannot redeem yesterday's letter.

When mail is not configured the send is a no-op and the endpoint still answers `202`. A self-hoster's users then have no reset; the operator's remedy is `POST /v1/admin/accounts/:id/reset-mail`, which returns the link.

**§5.12.2 `POST /v1/auth/reset/open`** — unauthenticated, IP-throttled.

Request `{"resetToken": "sr_…"}` → `200`:

```json
{ "email": "anna@example.org", "recoveryCode": "ABCDEFGHJKMNPQRSTVWXYZ0123456789" }
```

The token is consumed in the SAME statement that reads it (`UPDATE … WHERE consumed_at IS NULL AND expires_at > now RETURNING`), so two requests carrying one token cannot both be answered. Unknown, spent and expired tokens are ONE `404 {"error":"reset-invalid"}` after identical work.

**THIS ENDPOINT WRITES NOTHING TO THE ACCOUNT**, and that sentence is the whole difference from the flow §5.13 used to document. It hands back the recovery code the server already holds in escrow (§3.1); the client then runs the ORDINARY §5.14 `recover-rotate` ceremony with it — prove the code, set a new passphrase, re-wrap the DEK, mint a new code, re-escrow it, one transaction. Without the key records, what this returns is a string. A future change that let this path touch a verifier or a key record would have rebuilt the account-takeover flow ADR-0004 deleted, whatever it was called.

**What it costs, stated rather than implied.** The reset works because the operator holds the recovery code. Read §3.1 and [`docs/adr/0005-organization-accounts-and-escrowed-recovery.md`](./docs/adr/0005-organization-accounts-and-escrowed-recovery.md) before deciding to trust a hosted instance; the decision is about the operator, not about the cryptography.

### 5.13 `POST /v1/auth/verify-email` — removed in 0.5.0, and not restored

Gone with the mailer in 0.5.0, and protocol 2 does not bring it back even though this service mails again.

There is nothing left to confirm: an account is created by redeeming an invite ADDRESSED to a mailbox (§5.8), so the person who received the letter is the person who signed up. The invitation is the verification, and a second link would only ask somebody to prove twice what they have already demonstrably done once.

### 5.14 `POST /v1/auth/recover`, `POST /v1/auth/recover-rotate` and `POST /v1/auth/change-passphrase`

The recovery-code authenticator, and the two credential rotations. `recover-rotate` and `change-passphrase` take the same submission shape because they do the same thing; only the proof differs.

**`POST /v1/auth/recover`** — unauthenticated, throttled per IP **and** email. Request `{"email": "...", "recoveryAuthHash": "<base64, 32 bytes>"}` → `200` `{"account": AccountView, "tokens": {...}}`.

What comes back is an ordinary session, deliberately not a lesser one: the holder of the recovery code is the account owner by construction, and a restricted "recovery mode" token would add a second authorization surface carrying no property the code does not already carry.

```jsonc
// POST /v1/auth/recover-rotate — unauthenticated, proof is the recovery code
{
  "email": "...",
  "recoveryAuthHash": "<the current recovery proof>",
  "newAuthHash": "<new>",
  "kdfDescriptor": {...},
  "keyRecords": [ ... ],
  "newRecoveryAuthHash": "<a new recovery proof>" | null,  // optional: rotate the code too
  "recoveryCode": "<the new code, in the clear>"           // REQUIRED whenever newRecoveryAuthHash is present
}

// POST /v1/auth/change-passphrase — bearer, proof is the current passphrase
{ "currentAuthHash": "...", "newAuthHash": "...", "kdfDescriptor": {...}, "keyRecords": [ ... ] }
```

`keyRecords` entries are `{"kind": "passphrase" | "recovery", "kdfDescriptor": {...} | null, "wrappedDek": "<base64>"}`, at most one per kind, obeying the same rules as §5.4 (a `recovery` record's descriptor must be `null`; a `passphrase` record's must not be).

`change-passphrase` returns `200` `{"tokens": {...}}`. `recover-rotate` returns `200` `{"account": AccountView, "tokens": {...}}`, because the caller arrived without a session and needs to know which account it just re-entered. Both hand back a fresh pair.

**The whole submission is applied atomically.** New verifier, new account KDF descriptor, an optionally new recovery verifier, the re-sealed escrow, upserted key records, revocation of every outstanding session, and the caller's new pair either all commit or none do. This is not an implementation detail. Every half-state is a distinct disaster the user cannot see until they try to read their own diary: a verifier without its re-wrapped record logs in and decrypts nothing, a record without its verifier cannot log in at all, and a rotated recovery verifier without its record leaves a code that authenticates and then unwraps nothing.

**`keyRecords` must be present**, even as `[]`. An absent key is a `400`, for the same reason `expectedUpdatedAt` is required in §5.4: silence must never be read as consent on a path that can strand data.

Kinds _not_ submitted are left untouched. A passphrase change re-wraps the DEK under a new `KEK_p`; the `recovery` record still wraps the same, unchanged DEK and remains valid.

Four rules apply to `recover-rotate` alone:

- **A `passphrase` key record is required**, and `[]` is a `400`. Unlike a passphrase change, this path necessarily changed `KEK_p`, so accepting a submission without the re-wrap would mint an account that logs in perfectly and decrypts nothing.
- **Rotating the recovery code is all-or-nothing, and in protocol 2 that is a THREE-way rule.** `newRecoveryAuthHash`, a `recovery` key record, and `recoveryCode` must arrive together or not at all; any subset is a `400`. Each missing piece is its own disaster: a verifier without the record leaves a code that authenticates and unwraps nothing; a record without the verifier leaves one that unwraps and cannot log in; and an ESCROW still holding the old code turns the next mailed reset (§5.12) into a letter carrying a credential the account no longer accepts, discovered on the day it is needed.
- **The write is a compare-and-swap on the recovery verifier the proof matched**, re-asserted inside the transaction. It is not the authentication, which already happened; it is what stops two concurrent recoveries from overwriting a credential the user has already been told is theirs.
- **One failure, four causes.** An unknown address, an account that never set a recovery code, a wrong code, and a rotation that lost that compare-and-swap race all answer `401` with identical text, after identical work. A race must not be distinguishable from a bad guess, and a missing second authenticator must not be distinguishable from a missing account. A SUSPENDED account is the one exception: it answers `403 {"error":"account-suspended"}`, and only after the proof succeeded.

Both recovery endpoints share **one** throttle bucket per (IP, email), and neither clears it on success. They authenticate the same secret, so a separate allowance for each would halve the cost of guessing it, and a legitimate recovery happens once, so no honest client needs its allowance back. `POST /v1/auth/reset/request` is throttled under the same rule.

**What a rotation can and cannot do.** It restores **login**. It cannot restore **data**, because the server never held a key. A `change-passphrase` submitting `keyRecords: []` leaves a working account whose blob is permanently undecryptable, which is exactly why `recover-rotate` refuses that submission outright. A conforming client must say so, in those terms, before the user commits to the flow.

**If the passphrase is lost, §5.12 is the way back**, and it works because the operator holds the code in escrow (§3.1). Protocol 1 said here that a lost passphrase and a lost code together ended an account permanently, with nobody able to open it. That sentence is now true only of an instance whose `SERVER_SECRET` is also lost — which is why that secret must be backed up WITH the database, and why losing it is worse than it looks.

**The honest form of the old warning is about the operator, not the mathematics.** A managed instance can open any account on it. A self-hosted instance is its own operator, so the old promise holds for the personal case. A conforming client says which of the two it is talking to, before a person puts a diary in it.

### 5.15 `GET /v1/auth/account`, `PATCH /v1/auth/account` and `POST /v1/auth/delete`

All three bearer.

**`AccountView` is the ONE account shape in this protocol.** It comes back from `POST /signup`, `POST /login`, `GET /account`, `PATCH /account`, `POST /recover`, `POST /recover-rotate` and the admin account endpoints, so a client has exactly one account decoder:

```json
{
  "id": 1,
  "email": "anna@example.org",
  "displayName": null,
  "role": "member",
  "dailyAiLimit": 200,
  "aiUsedToday": 3,
  "suspendedAt": null,
  "createdAt": "2026-09-04T10:11:12.000Z"
}
```

Nothing secret is in it and nothing can be: no verifier, no KDF descriptor, no wrapped DEK, no escrow, no token. Every field is either the person's own information or the standing an operator granted them. `aiUsedToday` counts against `dailyAiLimit` on the current UTC day; `suspendedAt` is non-`null` while every authenticated call answers `403 account-suspended`.

The admin account endpoints return the same shape plus two operator fields, `blob` and `keyRecordKinds` (ADR-0001). A client decoding an `AccountView` from an admin response therefore works unchanged and reads two fields it did not ask for.

**`GET /v1/auth/account`** → `200` `{"account": AccountView}`.

**`PATCH /v1/auth/account`** takes `{"displayName": string | null}` → `200` `{"account": AccountView}`. The key MUST be present, even as `null`: an absent key is a `400`, the same rule `keyRecords` and `expectedUpdatedAt` follow, because a PATCH that quietly did nothing over a misspelled field name is a change the client believes it made.

That is the only field an account may change about itself. `email` is the identity and moves only through an operator; `role` and `dailyAiLimit` are standing an account must not be able to raise for itself; everything authentication-shaped moves through §5.14.

**`POST /v1/auth/delete`** takes `{"authHash": "..."}` and returns `204`. **Re-authentication is required even though the caller already holds a valid token**: a session left behind on a shared device must not be enough to destroy someone's data irreversibly.

Deletion removes the account and, by cascade, every blob, key record, reset token and usage row it owns. There is no soft delete and no grace period. This is the self-serve erasure path, and it is complete by construction rather than by a cleanup job someone has to remember to run.

### 5.16 Shares — `/v1/sync/shares` and `/v1/sync/shared` (ADR-0002)

**Present only when the deployment sets `SYNC_SHARING`.** Without it every path
below answers the ordinary unknown-route `404`, to every caller, credentialed or
not — the terminator is mounted _ahead_ of authentication, so an unconfigured
instance is indistinguishable from one where the feature was never written.

Both sides address a share by the **counterpart's account id**, never by a
synthetic share id: the stable identity of a share is the (grantor, grantee)
pair, and that is what survives a DEK rotation.

**Grantor side.**

| Verb     | Path                        | Notes                                                                                                                                                                                                                                                                                                                        |
| -------- | --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT`    | `/shares/:granteeAccountId` | `{"wrappedDek": "<base64>", "recipientKeyFingerprint": "<string>", "expectedUpdatedAt": "<iso>" \| null}`. CAS exactly as §5.4: `null` asserts no share exists yet, any other value asserts the row last read had this `updatedAt`, and an **absent** key is a `400`. `409` returns `{"currentUpdatedAt": "<iso>" \| null}`. |
| `GET`    | `/shares`                   | The grantor's own grants. **Never returns `wrappedDek`** — a blob addressed to somebody else's key has no use here, so it does not travel where nobody needs it.                                                                                                                                                             |
| `DELETE` | `/shares/:granteeAccountId` | `204`, idempotent. A **hard delete**; there is no tombstone.                                                                                                                                                                                                                                                                 |

**Grantee side.**

| Verb     | Path                             | Notes                                                                                                                                                                                                                                  |
| -------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET`    | `/shared`                        | Shares addressed to this caller, each with its `wrappedDek` — only this caller can open it.                                                                                                                                            |
| `GET`    | `/shared/:grantorAccountId/blob` | `{"grantorAccountId": <int>, "blobVersion": <int>, "envelopeVersion": <int>, "ciphertext": "<base64>", "createdAt": "<iso>"}`. **`grantorAccountId` is required**: §3.2's AAD binds it, so a grantee without it cannot decrypt at all. |
| `DELETE` | `/shared/:grantorAccountId`      | `204`, idempotent. Lets a grantee drop a share aimed at them.                                                                                                                                                                          |

- **The grantee surface has no write verbs against the grantor**, and serves only
  the caller's own share row, the grantor's current blob, and `grantorAccountId`.
  Never the grantor's key records, KDF descriptor, verifier, escrow, email or
  display name. A grantee who could pull the grantor's `recovery` wrapped DEK would be
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
  "newRecoveryAuthHash": "<base64, 32 bytes>",
  "recoveryCode": "ABCDE-FGHJK-MNPQR-STVWX-YZ012-3456",
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
- **`newRecoveryAuthHash` AND `recoveryCode` are REQUIRED**, and a submission
  missing either is a `400` that names the field. A rotation always mints a
  fresh recovery code, because the `recovery` key record it re-wraps is sealed
  under a KEK derived from that code; the server therefore replaces
  `accounts.recovery_verifier` and the escrow (§3.1) **inside the same
  transaction** as the blob, the key records and the shares. A rotation that
  left those two on the OLD code produced an account whose escrowed code
  authenticated and then unwrapped nothing — latent from the moment the
  recovery code became the second authenticator, and fatal once a mailed reset
  (§5.12) began handing that code to people. The client does not show the new
  code to the person; it goes into the escrow and stays there.
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

| Status | Body                                                                                                                       |
| ------ | -------------------------------------------------------------------------------------------------------------------------- |
| `200`  | `{"newVersion": 4, "keptShares": 1, "revokedShares": 2}`                                                                   |
| `400`  | `{"error": "..."}` — a missing key-record kind, a malformed or absent field, a keep list naming a share that is not there. |
| `409`  | `{"currentVersion": 5}` — the blob CAS did not hold. Nothing was written.                                                  |
| `413`  | `{"error": "..."}` — the new blob exceeds `MAX_BLOB_BYTES`.                                                                |

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

| Verb     | Path                             | Notes                                                                                                                                                                                                                                                                                   |
| -------- | -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PUT`    | `/contributions/:studyAccountId` | `{"pseudonym","schemaTier","body","contributionVersion"}`. CAS on a monotonic `contributionVersion`. The contribution is the cumulative dataset for the window, recomputed and re-pushed whole — the client always holds the source, so this row is a projection, never a primary copy. |
| `GET`    | `/contributions`                 | The contributor's own enrolments. Never returns `body`.                                                                                                                                                                                                                                 |
| `DELETE` | `/contributions/:studyAccountId` | **Withdrawal.** One transaction: hard-delete the row, insert a pseudonym-keyed tombstone. `204`, idempotent.                                                                                                                                                                            |

**Study side**, authenticated as the study account:

| Verb  | Path                   | Notes                                                                                                                 |
| ----- | ---------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `GET` | `/study/contributions` | `{"pseudonym","contributionVersion","schemaTier","body","createdAt"}` per row. **No account id, ever.**               |
| `GET` | `/study/withdrawals`   | Pseudonyms that withdrew, with timestamps. The study client must purge these before presenting or exporting anything. |

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

| Status | When                                                                         |
| ------ | ---------------------------------------------------------------------------- |
| `400`  | malformed body, unknown `schemaTier`, absent `contributionVersion`           |
| `404`  | unknown study, unknown contribution, and any other not-found — one code path |
| `409`  | `contributionVersion` not strictly greater than the stored one               |
| `413`  | contribution exceeds `MAX_CONTRIBUTION_BYTES` (256 KiB)                      |

**One pseudonym per study, enforced by the database.** Two contributors
submitting the same pseudonym would silently merge into one participant series,
and a researcher would analyse two people as one with nothing failing. An
accidental collision is about 2^-128, so the constraint should never fire —
which is the point: it makes the corruption impossible rather than improbable.

**Withdrawal is genuinely erasing on this side.** A contribution the study has
not yet pulled reaches nobody. What the study already pulled cannot be
repossessed — the tombstone carries the instruction, and honouring it is an
ethics obligation this system states and cannot enforce.

### 5.19 `POST /v1/chat/completions` — the AI proxy

**Present only when the operator configured an upstream key.** Without one the
path answers the ordinary unknown-path `404`, to everybody, credentialed or
not, and `instance.ai` is `null` on the handshake (§5.6). An implementation of
this protocol MAY omit the route entirely; a client MUST read `instance.ai`
before offering a scan rather than probing the path.

Authenticated with the account's ordinary **access token** (§4.1). The body is
an OpenAI-compatible chat-completion request and this specification does not
constrain it further: the service checks only that it is a JSON object, because
a stricter schema would reject every field the next provider adds. The response
is the provider's, relayed with its status.

```
POST /v1/chat/completions
Authorization: Bearer <accessToken>
Content-Type: application/json

{ "model": "…", "messages": [ … ], "stream": true }
```

Three properties a conforming implementation MUST hold, and each exists because
the request body is a photograph of somebody's food:

1. **The caller's credential is replaced, never merged.** The upstream request's
   headers are BUILT rather than copied from the inbound request and
   overwritten. A copy-then-overwrite forwards cookies, `x-api-key`, and
   whatever the next provider decides to read.
2. **No body is logged, in either direction.** Not a prefix, not a decoded
   buffer, not an error document. What may be logged: an account id, the
   upstream status, byte counts, a duration.
3. **Every string that came off the upstream wire is scrubbed** before it
   reaches a log line **or a response**. A provider that rejects a request
   routinely echoes the request back inside its error body, image and all.

#### The body limit

The request body carries a photograph, so the limit is sized for one:
**`AI_MAX_REQUEST_BYTES`, default 8,000,000 bytes**. Base64 inflates an image
by 4/3, so that carries a JPEG of about 5.7 MiB — a modern phone camera at
default quality, which is what the client sends after downscaling.

It is deliberately **unrelated to `MAX_BLOB_BYTES`** (§8). That bounds a diary
this service stores; this bounds an image it only forwards, and deriving one
from the other refuses every real photograph.

A body over the limit is `413`. **The error body on this route is
OpenAI-shaped, not the `{"error": "<sentence>"}` of §4**, because the caller is
an OpenAI-compatible client that reads `error.message` off an object:

```json
{
  "error": {
    "message": "Request body exceeds the maximum accepted size of 8000000 bytes. The operator can raise AI_MAX_REQUEST_BYTES.",
    "type": "invalid_request_error",
    "code": "request_too_large"
  }
}
```

A body that is not valid JSON is `400` in the same envelope with
`"code": "invalid_json"`. **Neither quotes the input back**, for the reason
hard rule 2 gives. An implementation MAY answer §4's shape instead, but a
client written against an OpenAI provider will then display nothing at all
rather than an error.

**Streaming is pass-through.** When the request asks for it, the response body
is relayed as it arrives, with `Cache-Control: no-cache, no-transform` and no
`Content-Length`. A service that buffered would still deliver every byte, so a
client cannot detect the difference except by the latency it was trying to
avoid.

#### The allowance

Each account carries `dailyAiLimit` — requests per **UTC day**, defaulting to
`0`. Every proxied response carries the account's position in it:

| Header          | Meaning                                        |
| --------------- | ---------------------------------------------- |
| `X-Quota-Used`  | Requests spent today, after this one           |
| `X-Quota-Limit` | The account's `dailyAiLimit`                   |

| Status | `error`                          | When                                                                    |
| ------ | -------------------------------- | ----------------------------------------------------------------------- |
| `401`  | `authentication required`        | No access token, or one that is expired or revoked                       |
| `403`  | `ai-not-allowed`                 | `dailyAiLimit` is `0`. Refused before anything leaves the host           |
| `403`  | `account-suspended`              | The account is suspended (§5.9 uses the same code)                       |
| `400`  | `request body must be a JSON object` | The body is not an object. The input is never quoted back            |
| `429`  | a sentence naming the reset instant | The allowance is spent. `Retry-After` is seconds to the next UTC midnight |
| `429`  | a sentence naming the per-minute bound | More than `AI_RATE_LIMIT_PER_MINUTE` requests in any trailing 60 s   |

`403 ai-not-allowed` is a machine code because a client MUST branch on it — it
means "this account will never succeed here until an operator changes
something", which is a different message to show than "come back tomorrow". The
two `429`s are sentences because there is nothing to branch on: a person reads
them.

#### What is spent and what is given back

A unit is **reserved before** the upstream call, never counted after it.
Counting afterwards has a window in which N parallel requests all read the old
count and all go through, and a client that retries on error is precisely the
client that fires them together.

| Outcome                          | Unit     | Why                                                                                     |
| -------------------------------- | -------- | --------------------------------------------------------------------------------------- |
| Connection refused / DNS failure  | released | The request never left this host                                                        |
| Header timeout (no bytes yet)     | released | Nothing was served to us; our own bound gave up before the provider answered             |
| Upstream `4xx`                    | released | The provider REFUSED it. It reached no model, so nobody billed it — and charging the account for the operator's own misconfiguration would let a broken proxy eat an organization's whole allowance in a minute |
| Upstream `5xx`                    | spent    | The provider accepted it and failed while serving. Generation may have run. Releasing here is a free infinite retry loop against exactly the provider that is flaking |
| Body timeout / stream aborted     | spent    | Headers already arrived, so the provider ran it. That we failed to read the answer is our problem, not a refund |
| Upstream `2xx`                    | spent    | Obviously                                                                                |

The service records **one integer per account per UTC day** and nothing else:
no prompt, no response, no model name, no timestamp finer than the day (§9.2).

---

### 5.20 The admin API — `/v1/admin`

**Operator surface, not client surface.** An openplate client uses exactly one
of these endpoints, and only when the signed-in account is an admin: the
console the app renders at `/admin`. An alternative client may ignore this
section entirely.

Two credentials reach it, and both arrive as an ordinary `Authorization:
Bearer`:

1. **The static operator token** (`ADMIN_TOKEN`), which keeps working when
   every account is locked out.
2. **An account whose `role` is `admin`**, using its own access token. This is
   what puts the console in the app rather than in a shell.

With **neither** configured nor matching, the whole subtree answers the same
`404` any unknown path does — to everybody. An instance that never configured
an operator token is indistinguishable from one built before the feature
existed. A `401` there would announce that a credential exists and is merely
locked.

| Endpoint                                | Does                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------ |
| `GET /v1/admin/stats`                    | Aggregate counts: accounts, blobs, bytes, key records, `pendingInvites`, `admins`, `aiRequestsToday` |
| `GET /v1/admin/accounts`                 | A page of `AccountView`s, plus `total`                                    |
| `GET /v1/admin/accounts/:id`             | One `AccountView`                                                         |
| `PATCH /v1/admin/accounts/:id`           | `role`, `dailyAiLimit`, `suspended`, `displayName`. At least one required |
| `POST /v1/admin/accounts/:id/reset-mail` | Starts the reset of §5.12 on the operator's initiative                    |
| `DELETE /v1/admin/accounts/:id`          | Erases the account and everything attached to it                          |
| `GET /v1/admin/invites`                  | A page of pending invitations, plus `total`                               |
| `POST /v1/admin/invites`                 | Mints one (§5.8). The token is returned **once**                          |
| `POST /v1/admin/invites/:id/resend`      | A NEW token on the SAME row, and a new expiry                             |
| `DELETE /v1/admin/invites/:id`           | Withdraws a pending invitation                                            |

**`PATCH` is the one auth-adjacent write an operator has**, and it is bounded
deliberately. It cannot set a passphrase, and there is no endpoint that can:
the passphrase wraps the data key on the client, so a server-side credential
change would produce an account that logs in and decrypts nothing. It cannot
change an account's `email`, because the address is what the invitation
verified. It cannot print a recovery code.

**Suspending revokes every session in the same effect.** A `suspended_at` alone
would leave the phone in somebody's pocket syncing for another quarter of an
hour, which is not what an operator means by the word. Reactivating restores no
session; the person signs in again.

**An admin ACCOUNT cannot suspend, demote or delete itself** — `400`, with
`{"error": "self-change"}`. An organization with one administrator who does
that has locked everybody out of this tree, and the only remedy is a shell on
the container. The static token is exempt, because it has no self and is the
credential that exists for exactly that situation.

`AccountView` is the same shape the account's own `GET /v1/auth/account`
returns (§5.15) plus `aiUsedToday`, and it carries **no verifier, no KDF
descriptor, no escrow and no ciphertext**. A blob is reported as a byte count
and a timestamp. The reasoning is
`docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`, whose
prohibitions 1, 2, 3, 5 and 8 ADR-0005 supersedes and whose prohibition on
secrets in a response it does not.

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

**Pre-1.0 latitude.** Until the first public release, breaking changes may be taken without the migration path a released protocol would need. Two were taken WITHOUT a version bump: the move from cookie to bearer authentication, and the move of the sync routes from `/api/sync` to `/v1/sync`. A third, 0.5.0's removal of email, was taken without one too and should not have been — see below. This paragraph is deleted at public release, and from then on the rules above are followed literally.

**0.5.0 changed the auth contract and did NOT bump the version, and that was the mistake this section now records.** It replaced `email` with `handle`, removed `verify-email` and `request-reset`, and added `recover` and `recover-rotate` (§5.14). Because the number stayed at `1`, the §6 handshake did not catch it: a client older than 0.5.0 posting `email` got a `400` it could not repair, while the version numbers matched and told it everything was fine.

**0.6.0 bumps `PROTOCOL_VERSION` to 2, and does it for exactly that reason.** The changes are of the same class — the auth field is `email` again, signup requires an addressed invite and both key records, `signupMode` left the handshake, `AccountView` replaced the old account body, and two reset endpoints reuse §5.12 — but this time §6 catches them: a client speaking version 1 refuses to talk rather than half-working. Reasoning: [`docs/adr/0005-organization-accounts-and-escrowed-recovery.md`](./docs/adr/0005-organization-accounts-and-escrowed-recovery.md).

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
- **The account itself**: an **email address**, an optional display name, a role, a daily AI allowance, a suspension instant, an authentication verifier (a keyed hash of a keyed hash of the passphrase, see §5.8), a second verifier of the same construction over the recovery proof, and the account's KDF parameters. **The address names a person in the world**, which is a class of personal data 0.5.0 removed and 0.6.0 deliberately put back (ADR-0005): an organization's people are identified by the address their invitation arrived at, because that is the identifier they will still know in a month.
- **The account's RECOVERY CODE, sealed** (`accounts.recovery_code_escrow`, §3.1). This is the entry on this list that a reader should stop at. It is AES-256-GCM under a subkey of `SERVER_SECRET`, so a dumped database alone does not open it — and the operator of a managed instance has both. **The operator of a managed instance can open any account on it.** Not through an endpoint, and not through any code path in this service, but by reading that column with the secret in hand and running the client's own HKDF. A self-hosted instance is its own operator, so the older promise holds there. Deciding whether to trust a hosted instance is therefore a decision about its operator.
- **Pending invitations**: for each, an address, an optional name, a role and an allowance — belonging to somebody who has NO account yet and gave no consent. Minting one is an operator action, and `DELETE /v1/admin/invites/:id` withdraws the row.
- **AI usage**: one integer per account per UTC day. A count, never a log — no prompt, no response, no model, no timestamp beyond the day.
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

6. Serve a stable, real-shaped KDF descriptor for unknown addresses (§5.7), doing identical work on both branches, and rate-limit the endpoint by source address. A `404`, a lazily-derived dummy, or an unthrottled endpoint each re-opens the enumeration oracle the rest of the design closes, by response, by timing, or by volume.
7. Store both verifiers as keyed hashes of the submitted `authHash` and `recoveryAuthHash` under a secret held outside the database. Never the submitted value itself, and never in plaintext.
8. Apply §5.14's rotation submissions atomically, including the re-sealed escrow, and revoke every outstanding session on each of the triggers in §4.2.
9. Take the account's address from the INVITE at signup and never from the request body (§5.8), and throttle `recover`, `recover-rotate` and `reset/request` on one shared bucket per (IP, email) that is never cleared on success. A server that lets a signup body name its own address has removed the only thing that verifies it.
10. Answer `202` to every `reset/request` after identical work, and make `reset/open` write nothing to the account (§5.12). A reset that replaces a verifier is the account-takeover path this protocol deleted, whatever it is called.
11. Refuse a suspended account at login, at refresh and on every bearer route, with `403 {"error":"account-suspended"}` — that exact string.
12. Cascade account deletion to blobs, key records, reset tokens and usage rows.

A conforming server needs **none** of: the crypto in §3, JSON parsing of any payload, or knowledge of what a food log is.

## 11. Implementing an alternative client

Beyond §3 and the 409 loop of §5.1:

- Perform the §6 handshake before the first sync and refuse on mismatch.
- Never persist the passphrase, either KEK, or the DEK to any durable storage. Derive on unlock, hold in memory, discard.
- Run Argon2id off the main thread. At 64 MiB it visibly freezes low-end phones.
- Generate the recovery code at signup, wrap the DEK under it, and send it to the server in the signup body so it can be escrowed (§3.1). A client that skips it creates an account no reset can restore. Whether to SHOW it to the person is the client's call; on a managed instance the point of the escrow is that it need not.
- Say what kind of instance the person is signing in to, before they put a diary in it. On a managed instance the operator holds the escrowed code and can open the account; on a self-hosted one the operator is the person themselves. Both are honest; only one of them is what a stranger assumes.
- Read the address from `POST /v1/auth/invite-lookup` (§5.8.2) and show it, rather than asking the person to type their own. They cannot mistype it into an account nobody can reach if they never type it.
- Derive the recovery proof under `openplate-sync:recovery-auth:v1` and **never** send `KEK_r`. The two are siblings over the same code, and sending the KEK branch would hand the server an HMAC of the value that opens the diary (§3.1).
- After `POST /v1/auth/reset/open` hands back the recovery code, run the ORDINARY §5.14 `recover-rotate` with it: a new passphrase, a re-wrapped `passphrase` record, a new code, a re-wrapped `recovery` record and the new `recoveryCode` for the escrow. Stopping half way leaves an account whose escrow no longer matches its verifier.
- Treat `404` from `GET /blob` as "new account", not as an error.
- Send `authHash` — the `auth` HKDF branch of §3.1 — and never the passphrase, the Argon2id output, or `KEK_p`. Deriving the wrong branch is silent: it authenticates fine and produces a key that decrypts nothing.
- Fetch the KDF descriptor (§5.7) before deriving anything on a new device. Do not assume the defaults; an account created under raised parameters will not derive correctly from them.
- Keep the refresh token in the same storage tier as the access token and **never** reuse a spent one — a replay revokes the whole family and logs the user out (§4.2). Serialize refreshes; two tabs racing the same refresh token look exactly like a theft.
- On `401`, refresh once and retry once. On a second `401`, send the user to log in rather than looping.
