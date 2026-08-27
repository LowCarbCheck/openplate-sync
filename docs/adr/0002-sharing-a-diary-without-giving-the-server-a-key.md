# ADR-0002 — Sharing a diary without giving the server a key

- **Status:** accepted
- **Date:** 2026-08-27
- **Amends:** `PROTOCOL.md` §3 (a new wrap construction), §5 (a new endpoint
  family), §5.5 (shares are not a recovery path) and §9.2 (the server learns a
  new thing, and we say so).
- **Extends:** ADR-0001's prohibitions to a new surface.

## Context

Dieticians and researchers with patient groups want to see what their patients
logged. Today that is impossible, and impossible for the right reason: the diary
is encrypted under a key derived from the patient's passphrase, and the server
has never held it.

Two customers hide inside that one sentence, and they are not the same product.

| | Dietician | Researcher |
|---|---|---|
| Subject | One named patient | A pseudonymous cohort |
| Needs | The whole diary, ongoing | Usually daily totals |
| GDPR basis | Art 9(2)(h), care | Art 9(2)(j), research |
| Full-diary access is | proportionate | a data-minimisation failure |

**This ADR decides the dietician case only.** The researcher case is a reduced,
date-bounded, pseudonymous payload encrypted to the researcher and pushed as its
own small blob in a separate lane. It reuses the identity, authorisation and
read plumbing below, and it is deliberately not a flag on this mechanism.

Two designs were available and both are wrong. Giving the operator a decryption
key ends zero-knowledge for everybody. Reconstructing intake from the sibling
gateway's `ORG_MODE` audit trail (its ADR-0003) produces a confident, wrong
number: that trail holds what a vision model *proposed* for a photograph, not
what the person ate, and it never sees food logged by search.

## Decision

The account's DEK is already a wrap target twice over — once under the
passphrase KEK, once under the recovery KEK. The server holds both wrapped blobs
and can open neither.

**A share is a third wrap, addressed to the clinician's public key.** The
server's position does not change. It holds one more blob it has no key for.
§9.1's sentence — "decryption is not withheld by policy, it is unavailable" —
is still true after this feature, and that is the test this design had to pass.

### The wrap must be asymmetric, and that is the whole argument

The cheap version introduces no new primitive: a share code, HKDF, a KEK,
exactly mirroring the recovery path. It is rejected, and the reason decides the
rest of the document.

A symmetric share code is a **decryption secret in an email**. The gateway sends
that email. A gateway operator, a mail archive, or a mailbox breach would then
hold half of a decryption capability, and gateway-plus-sync collusion would be
total compromise by construction.

An asymmetric wrap puts only a **public** key in the mail. The strongest
mail-channel attack becomes *substitution* — an active attack, detectable by
fingerprint comparison, and never retroactive.

So the "no asymmetric primitive anywhere in this stack" property is spent here,
deliberately, and this ADR is where that is recorded.

### The construction, frozen

```
sender (patient, holding recipientPub):
  (ephPriv, ephPub) ← ECDH P-256, fresh per wrap, discarded after
  Z         ← ECDH(ephPriv, recipientPub)
  KEK_share ← HKDF-SHA-256(salt = empty, IKM = Z,
                           info = "openplate-sync:share-kek:p256:v1")
  AAD       ← UTF-8 of canonical fixed-key-order JSON:
              {"grantorAccountId":<int>,"recipientKeyFingerprint":"<base64>"}
  wrap      ← ephPub(65, uncompressed SEC1) ‖ iv(12) ‖ AES-256-GCM(KEK_share, DEK, aad=AAD)
              = 125 bytes
```

**P-256, not X25519.** Three reasons. It has been in every WebCrypto
implementation for a decade, including the older mobile WebViews that are
exactly this product's tail, whereas X25519 only went default-on in evergreen
browsers during 2025. WebCrypto performs point validation internally, which
removes the invalid-curve footgun that makes hand-rolled P-256 dangerous. And
§6's philosophy is fail-closed, not feature-detect-and-degrade — a curve
negotiation for one wrap format is complexity with no customer.

**The curve is named in the label**, not only the version. A future X25519
construction is therefore a new label rather than an ambiguity about what `:v1`
once meant.

**The empty HKDF salt is correct**, on the same RFC 5869 §3.1 grounds
`PROTOCOL.md` already argues for the recovery code: the input is a fresh,
high-entropy ECDH output, not a human secret needing a memory-hard stretch.

**This wrap carries AAD, unlike the key-record wraps.** A key-record wrap is
scoped by an owner-only row and needs no binding: an owner's KEK and an owner's
DEK cannot be confused with anyone else's. A share wrap sits in a
server-controlled association table, where they can — a malicious server could
splice one patient's wrap into a row pointing at another patient's blob, or swap
recipients. So the wrap is bound cryptographically, and a spliced row produces a
tag failure rather than a misattributed diary. Same argument §3.2 makes for the
blob.

**It binds the recipient's key fingerprint, not the grantee's account id.**
Substitution attacks the *key*, so the key is what the binding must name. It
also lets the clinician reconstruct the AAD from a fingerprint she computed
locally, instead of trusting an identifier the server handed her — no
server-supplied value enters the trust path.

The apparent cost, that a clinician rotating her key invalidates every existing
wrap, is illusory: the wrap is ECDH-bound to her old public key, so her new
private key could not decrypt it whatever the AAD said. The ceremony-per-new-key
is forced by the cryptography, and it is also the correct policy — a new key is
a new trust decision.

### Shares live in their own table

`sync_key_records` has an honest invariant: one row per (account, kind), CAS'd
on `updatedAt`, both kinds owner-held wraps participating in §5.14's atomic
rotation. A share breaks every clause. It is multi-valued, it is held by a
*different principal*, its lifecycle is grant and revoke rather than create and
rotate, its wrap is 125 bytes rather than 60, and it must never ride through
change-passphrase or reset — those rotate KEKs, and a share has no KEK to
rotate.

A nullable discriminator would turn the unique index partial, fork every
kind-validation branch, and grow §5.14's submission schema a share-awareness it
must not have.

```
sync_shares
  id                       serial PK
  accountId                int → accounts.id ON DELETE CASCADE   -- grantor (patient)
  granteeAccountId         int → accounts.id ON DELETE CASCADE   -- grantee (clinician)
  wrappedDek               bytea NOT NULL                        -- 125 bytes, see above
  recipientKeyFingerprint  text  NOT NULL                        -- pinning metadata only
  createdAt / updatedAt    -- updatedAt is the CAS token, as for key records
  UNIQUE (accountId, granteeAccountId)
  CHECK  (accountId <> granteeAccountId)
```

Both foreign keys cascade. A patient deleting their account kills every grant
they made; a clinician deleting theirs kills every wrap addressed to them. The
DSAR story stays "delete one row, the cascade does the rest" from both ends,
with no sweeper.

**Revocation is a hard delete, not a tombstone.** A tombstone would defend
nothing here. A whole-database restore predates the revoke, so the restored copy
lacks the tombstone too — it cannot prevent what it never contains. The
gateway's ADR-0002 resurrection was real because a *second live source of truth*
was merged back in at boot; this service has no second source. Re-creating a
deleted row needs the patient's own bearer token **and** a fresh wrap only the
patient's client can produce, which makes it a re-grant, a legitimate act.

Against that zero defensive value stands a real cost: a permanent server-side
assertion that a named patient was under a named clinician's care, surviving its
own revocation, on a service whose §9.2 this feature already widens. A patient
who wants a history of past grants can keep it in their own encrypted snapshot,
where it belongs.

**The grantee's public key is not stored here.** Storing it invites the key
directory this ADR rejects. The fingerprint is stored for pinning; the full
public key is pinned inside the *patient's own encrypted snapshot*, so a new
patient device can re-wrap after a rotation without re-running the invite.

### The endpoints, and the seam that must not be used

The singleton `PUT /key-records/:kind` is untouched. Shares get their own family
under the sync prefix, behind the existing bearer gate.

Grantor side: `PUT /v1/sync/shares/:granteeAccountId` (CAS on
`expectedUpdatedAt`, transplanting §5.4's discipline verbatim — a rotation
re-wrap can race a re-grant), `GET /v1/sync/shares` (never returns the wrap:
the grantor has no use for it, so it does not go where nobody needs it), and
`DELETE /v1/sync/shares/:granteeAccountId`.

Grantee side: `GET /v1/sync/shared`, `GET /v1/sync/shared/:grantorAccountId/blob`,
and `DELETE /v1/sync/shared/:grantorAccountId` so a grantee can drop a share
aimed at them — without it, anyone knowing an account id could park junk in a
clinician's list forever.

**Both sides address a share by the counterpart's account id, never by a
synthetic share id.** The stable identity of a share is the (grantor, grantee)
pair, and that is what has to survive a DEK rotation. A synthetic id would
change on every rotation and break the reference the clinician's client holds,
for no gain.

**The shared-blob response must carry `grantorAccountId`.** The blob's own AAD
binds it (§3.2), so a grantee who does not know it cannot decrypt at all.

A missing share and a grantor who never pushed return the **same** 404. So does
a share belonging to somebody else. Naming a counterpart in the URL is not an
enumeration oracle: access exists only through the live row lookup
`(grantor = param, grantee = caller)`, and the grantee learns no id the patient's
grant did not already hand her. Absence
of a share must not confirm that an account exists.

**`resolveEntitledUser` is not the door.** `create-app.ts` advertises it as "the
seam a future entitlement rule would use", and it is the wrong seam for this,
because its type answers *who are you* and every route then uses that one id as
the *target*:

```ts
interface SyncEntitledUser { userId: number }
const result = await handlePullBlob(user.userId, context.storage);
```

Resolving a clinician to the patient's id would not grant read access — it would
make the clinician *become* the patient, for the write path and key-record
rotation too. That is a confused deputy. Caller and target stay separate, and
the grantee read path is a parallel, read-only route that names the grantor
explicitly. The owner-only routes remain provably owner-only.

### Two tiers of revocation, and honest words for both

**Tier 1, access revocation** — delete the row. The server stops serving,
effective on the next request because the row is checked every time and never
cached. This is complete against the server-mediated path. It cannot un-know:
the clinician may hold the DEK and everything already pulled.

**Tier 2, cryptographic revocation** — `POST /v1/sync/rotate-dek`, one atomic
submission carrying the re-encrypted blob, both re-wrapped key records, and a
re-wrap for every share to keep. Shares not resubmitted are deleted in the same
transaction: silence is revocation, which is the safe default here, unlike
§5.14 where untouched-means-kept is safe because those are the owner's own
records. A partial application is the "logs in fine, decrypts nothing" brick
§5.14 already refuses to permit.

The DEK is immortal today because nothing ever needed to rotate it. The moment a
second human can hold it, rotation must exist. **Confirming the third wrap means
committing to rotation**; shipping one without the other is the corner.

The user-facing wording is binding: *"X can no longer access your diary through
openplate. Data they already viewed, they may have kept — as with anything you
have shared."* Rotation adds that future entries are sealed with a key X never
had.

*Revocation controls the future. It cannot repossess the past, and pretending
otherwise would be the only actual lie in this protocol.*

### Trust: the invite carries the key, the room verifies it

A server-hosted clinician directory is rejected outright. It would make this
service an identity provider — a trust role it does not have — converting "the
server *cannot* read your data" into "the server *promises* to hand your client
the right key". That is the class of promise this protocol exists to not need,
and it carries an identity-verification burden (who certifies that this account
is Dr. Meier?) the service cannot meet.

So the clinician's public key and fingerprint travel in the invite the gateway
already emails, and the client imports them as **unverified**. Verification is a
fingerprint comparison — and this is the rare setting where that is not theatre,
because a scheduled consultation puts both screens in one room. Design for that
room.

**Transport and trust are separated.** The key bytes may travel any convenient
way — the invite, a QR code, a directory. That is onboarding's problem. The
trust decision is a separate act, and it is this:

The clinician's app computes the fingerprint **locally, from her own key**, and
displays it. Never a server-rendered page — a server-rendered fingerprint is the
attacker reading you its own key. She reads it aloud. **The patient types it.**
The client refuses the grant unless the typed value matches the fingerprint of
the key it actually received.

**Typed, not compared.** A compare-and-confirm control is theatre: people tap
through it, and a design that relies on them not tapping through has no
security. A typed mismatch physically cannot proceed.

The display is 60 bits — the first 12 characters of the Crockford base32
fingerprint, in three groups of four. That puts a targeted collision, where a
server grinds keypairs until the visible prefix matches the real clinician's, at
about 2^60 hashes. Out of reach for this attacker. Forty bits would not be.

The verified key is pinned in the patient's encrypted snapshot, and every later
re-wrap uses the pinned key. A key change — rotation or attack, indistinguishable
and correctly so — voids the share until a new ceremony.

**The honest outer bound.** If the operator serves the client JavaScript, a
malicious operator ships malicious JavaScript and no in-protocol ceremony
survives it. That bound predates this feature and bounds the whole E2EE promise.
The fingerprint defends against a compromised or coerced *sync server*; it does
not defend against a compromised *client distribution*. This ADR does not imply
otherwise.

### The clinician is an ordinary account

No new principal type, no role column. Being a clinician is not a server-side
attribute; it is the fact that share rows point at you. This keeps the auth
surface unchanged and keeps the server from holding a labelled registry of
health professionals.

The share keypair is generated on the clinician's device and the private key is
stored inside their own encrypted snapshot — protected by their DEK, synced,
multi-device and recoverable by machinery that already exists.

**If they lose passphrase and recovery code, every share dies** and every
patient must re-share. That ships as-is. Any server-side softening is a
decryption capability parked on the server, which is ADR-0001's forbidden back
door wearing a support-tool label. What we owe instead is wording: clinician
onboarding must present the recovery code as protecting *their patients'*
access, not only their own.

**The concentration risk is real and has no cryptographic fix in v1.** One
clinician account is worth N patient diaries. Per-device hardware-backed
non-extractable keys with per-device wraps are the future hardening. Deferred,
recorded, not built.

## What the server learns, and why we accept it

§9.2 promises an honest statement of metadata, so this belongs there: the server
now stores and serves a **relationship graph** — patient X is read by clinician
Y, with timing and frequency. Given the product, an edge in that graph is itself
health-adjacent personal data: it says someone is under dietetic care.

This is a genuine expansion and it is acceptable because it is the minimum
needed to authorise the read, because both ends consented (the grantor created
the row, the grantee can delete their side), and because hard-delete plus the
double cascade means the edge dies with either party.

It is **not** acceptable for the graph to leak sideways, hence the prohibition
below.

## The snapshot is partitioned — amendment, 2026-08-27

The precondition below was taken, passed, and **went stale the same day**. That
is worth more than the fix.

A share is full-DEK, and the blob is the *whole* snapshot (§3.2). So "share the
DEK" silently meant "share the DEK's entire domain", and that domain had no
boundary. When the client slice put the owner's share private key and their
pinned peers into the snapshot — correctly, so they would survive a recovery
restore and reach a second device — it put them into the very thing a share
discloses.

**That is a cascade, not a leak.** A grantee holding the grantor's share private
key can decrypt every wrap addressed to that grantor. A clinician is an ordinary
account here, so a dietician who is also somebody's patient would hand their own
grantee the keys to *their* patients' shares — reaching a third party who never
made any trust decision about the recipient. The counterargument, that the
ciphertext is still gated because `/v1/sync/shared` authorises by bearer
identity, is exactly the argument this service does not accept: §9.1's whole
claim is that confidentiality does not rest on server policy. Material protected
only by an authorisation check is treated here as disclosed.

The pinned-peer list is the second half: it hands every grantee a subset of the
care graph that §9.2 only admits the *server* learns.

### The owner-private compartment

The snapshot is now formally two regions.

- **The shareable region** — diary and preferences. This is what a grant means.
- **The owner-private compartment** — key material and trust pins. This is what
  a grant must never mean.

The compartment is the service's own key architecture, relocated one level down:

```
CDK ← random 256-bit compartment data key
  wrapped under K_pp = HKDF(Argon2id hash, salt = account salt,
                            info = "openplate-sync:private-store-kek:v1")
  wrapped under K_pr = HKDF(recovery code, salt = empty,
                            info = "openplate-sync:private-store-recovery-kek:v1")
ciphertext ← iv ‖ AES-256-GCM(CDK, plaintext,
                aad = {"accountId":<int>,"purpose":"private-store","v":1})
```

The indirection exists for the same reason the DEK's does: two independent
unlock paths must open one ciphertext. Both slots use the same 60-byte wrap
format as a key record. Both labels are frozen here.

**This needs no protocol change.** §3.2 already declares everything inside
`snapshot` opaque to the protocol, so a nested ciphertext field violates
nothing. A second blob with its own key records would buy the same properties
with new endpoints, new key-record kinds and a two-repo change, to store what is
architecturally a mini key-record pair.

Lifecycle follows what the client already does, with three corrections found in
implementation and recorded here because the first draft of this section was
wrong about all three.

- **A passphrase change rewraps the `K_pp` slot** — but *not* "in the same
  moment", which is not achievable. The key records ride in one atomic auth
  request; the compartment lives in the blob and needs a second write. There is
  an unavoidable residual window. The ordering is chosen so the device that can
  repair it is the device that caused it, and a failure to rewrap is **not**
  reported as a failed passphrase change: the credential change already
  succeeded, and saying otherwise would invite the user to repeat it.
- **Regenerating the recovery code must rewrap slot 2**, which the first draft
  omitted entirely. Rotating the recovery key record without rewrapping the
  compartment would leave it openable only by the code the user has just been
  told to discard. This is also the upgrade path: an account predating the
  partition gets a compartment here.
- **A recovery-code reset** rewrites both slots while the code is still in the
  call frame. The **no-recovery-code** branch cannot — there is no session and
  no decryptable blob at that point — so such an account has no compartment
  until the next recovery-code regeneration. Degraded but safe: the key material
  stays on the device rather than being published in the clear.
- **A DEK rotation does not touch the CDK at all.**

**The compartment lives on the wire, not in the local store.** The device store
and the backup file keep `shareIdentity` and `sharePeers` in the clear, because
only a blob is ever handed to a second person. Stripping them from the backup
would leave a restored device unable to open any patient's wrap — solving a
disclosure problem by breaking recovery.

**The snapshot version is a safety interlock here, not a migration.** The local
shape does not change, so an older backup imports unchanged. The version is
bound into the envelope AAD, and that is the point: without a bump, a client
built before the partition would decrypt a partitioned blob, strip the
compartment as an unknown key, and push the result back — destroying the
account's share keys with nothing failing anywhere. With the bump it gets a tag
failure instead.

**Residual disclosure, stated:** a grantee still sees that a compartment exists
and roughly how large it is, which leaks an approximate peer count. Real, minor,
and disclosed rather than discovered.

### The rule this replaces the audit with

A point-in-time audit of a moving structure is stale the day the structure
moves, and this one proved it inside a single milestone, on the same team, in
one day.

**An invariant relied on across slices must be a test, not a review finding.**

Concretely: a frozen map classifies every snapshot key as `shared` or
`owner-private`. The test derives the actual key set from a fully populated
fixture built by the **real** snapshot builder — never a hand-copied list — and
fails on any key the map does not classify. Absent means fail, never means
shared. And it asserts the *positive* structure: owner-private material appears
only as the compartment's opaque ciphertext, and its known plaintext markers are
recoverable through the CDK path and provably not from the grantee's view. A
grep for absence passes on an empty snapshot.

## The Slice 0 precondition, and its finding

The blob is the client's whole local-store snapshot, and openplate is BYOK. If
that snapshot could carry the provider key or a gateway member token, a
full-DEK share would hand the clinician the patient's **credentials**. So no
share may be creatable until the snapshot contents are audited.

**Audited 2026-08-27. The gate passes, and by design rather than by luck.**

`readLocalSnapshot()` is `(await exportBackup()).data`, typed
`LocalStoreSnapshot`: `foods`, `foodLogs`, `weightEntries`, `profile`, `fasts`,
`savedMeals`. `profile` is goals, timezone and height. No credential appears in
any of them.

The BYOK configuration lives in a **separate IndexedDB database**, and
`local-store/ai-settings.ts` states the reason directly: a backup or export of a
user's tracker data must never carry their API key. The sync engine reaches the
primary store through a single bridge and never imports the AI store — verified
by search, not by reading the comment.

The property must be kept: anything added to the synced snapshot that is not
diary or preferences data re-opens this gate.

## Prohibitions

1. **The server never stores, generates, serves or endorses a share public key.**
   It stores a fingerprint as pinning metadata and an opaque wrap. A key
   directory is a rejected design, not a deferred one.
2. **No admin-surface exposure of the share graph.** Per-account counts at most,
   never the counterpart ids in either direction. Extends ADR-0001.
3. **A share is never a recovery path.** It is excluded from every "last
   remaining key record" calculation, and no mechanism may restore an owner's
   DEK through a grantee. §5.5's warning stands unchanged: deleting both key
   records still bricks the account.
4. **No grantee write path, no grantee key-record access, no grantee version
   history.** One read-only endpoint for the current blob, authorised by a share
   row checked on every request and never cached.
5. **No server-side escrow or admin-assisted recovery of a clinician's share
   key**, ever.
6. **A client never wraps the DEK to a key that has not passed the typed
   fingerprint ceremony**, and never to a key re-fetched from the server when a
   pinned key exists. The fingerprint a clinician reads out is computed locally
   from her own key, never displayed from server-rendered content. The client
   never auto-accepts a changed fingerprint. Any future change that replaces
   typing with tapping is a security regression, not a simplification, and must
   be reviewed as one.
7. **Revocation UI never claims retroactive effect.** No phrasing may say a
   revoked clinician can no longer read what they already downloaded.
8. **`rotate-dek` is atomic or it does not exist.** No sequence of individually
   committing endpoints may be documented or used as a rotation procedure.
9. **The shareable region of the snapshot may never contain credentials or
   trust pins.** Enforced by the classification test described in the
   partition amendment above, whose map fails closed: a snapshot key that
   nobody has classified is a red test, not a shared field.
10. **`SYNC_SHARING` unset means both route trees answer the ordinary
    unknown-route 404**, to everybody, credentialed or not, from the first
    commit that adds a route. The terminator is mounted **before**
    authentication — mounted after it, an unconfigured tree leaks a 401 and
    announces that a credential exists worth guessing.
11. **The researcher case must never be built as a share with a smaller UI.** A
    scope enforced by the viewing client is not data minimisation: the
    researcher would still hold a key to everything. It gets its own reduced,
    separately encrypted artifact, or it does not ship.
12. **No sharing GA without the §9.2 amendment and without DEK rotation.** An
    undisclosed sharing graph and an unrotatable DEK each turn an honest design
    into a quiet lie.

## The attacks that break this, ranked

1. **Clinician account takeover.** Phish one passphrase, get the vault, get the
   share private key, get every patient's wrap, get every diary including the
   past. No cryptography here prevents it. The posture is blast-radius honesty,
   Tier 1 revocation, and Tier 2 rotation as the incident response. This is the
   first risk, and it is written first deliberately.
2. **Grant-time key substitution with a skipped or theatrical ceremony.** If the
   fingerprint check ever degrades into compare-and-tap, or the clinician's
   fingerprint is rendered by anything the server controls, a coerced sync
   server substitutes its own key at grant time, reads every later blob, and
   every indicator stays green. The typed ceremony and snapshot pinning are the
   two load-bearing defences. This is the attack that breaks the design.
3. **Revocation misunderstanding.** Not a cryptographic attack; an attack we
   commit on ourselves with careless wording. Prohibition 7 is the defence.
4. **Wrap replay across rows** — defeated by the AAD binding, not by trusting
   the server's row integrity.

## Alternatives rejected

**A symmetric share code, mirroring the recovery path.** Rejected: it puts a
decryption secret in an email the gateway sends. See the decision section — this
is the argument the whole design turns on.

**A server-hosted clinician key directory.** Rejected: it makes this service an
identity provider and a standing MITM position.

**A `scope` or date-range column on `sync_shares` for the researcher case.**
Rejected as speculative. The researcher share references a different resource
entirely, and a dead column is how a schema rots.

**Reusing `resolveEntitledUser` for the grantee read.** Rejected: confused
deputy, as shown above.

**Extending `SyncEntitledUser` with a target field.** Rejected: it would make
every existing owner-only route depend on a field that must be null for them,
and the day someone forgets is the day a write lands in the wrong diary.
