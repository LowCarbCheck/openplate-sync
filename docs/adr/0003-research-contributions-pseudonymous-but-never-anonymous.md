# ADR-0003 — Research contributions: pseudonymous, but never anonymous

- **Status:** accepted
- **Date:** 2026-08-27
- **Extends:** ADR-0002's prohibitions to a second recipient class.
- **Amends:** `PROTOCOL.md` §9.2 again — the server learns a second graph.

## Context

ADR-0002 built clinician sharing and deliberately deferred the researcher, with
a prohibition written in advance to stop the obvious shortcut:

> The researcher case must never be built as a share with a smaller UI. A scope
> enforced by the viewing client is not data minimisation: the researcher would
> still hold a key to everything.

A dietician needs one named patient's whole diary under Art 9(2)(h). A
researcher needs a cohort under Art 9(2)(j), where full-diary access is not
merely excessive but a compliance failure. These are different artifacts.

## The honest limit, stated first

**Longitudinal daily nutrition totals are a behavioural fingerprint, and no
pseudonym changes that.**

A researcher holding a cohort plus any auxiliary dataset — a fitness-app export,
a workplace wellness programme, or simply knowing one participant personally —
can re-identify a series. The pattern of *which days were logged at all* is high
entropy by itself. The sparsity results for longitudinal traces apply squarely:
a handful of points identifies most individuals.

So this data is **pseudonymised personal data, never anonymous**, in every legal
document, every consent screen and every pixel of UI. Prohibition 5 makes that
binding.

Three responses were available and two are wrong. Server-side aggregation is
impossible — the server cannot read. Client-side differential-privacy noise on
small cohorts is statistics we are not qualified to calibrate per study, and
getting it wrong produces confident bad science. So per-contributor rows ship,
because within-subject longitudinal analysis is the scientific point, and the
residual risk is carried where it belongs: in the consent text and in each
study's own ethics approval. **If a study's design makes that residual
unacceptable, the ethics board is the right thing to fail — not our schema.**

## Decision

### The payload is a fixed tier, chosen by us

A study selects a **named tier** and a date window. It never supplies a field
list. v1 ships one tier:

`daily-intake:v1` — one row per calendar day in the window: `date` (day
granularity, no timestamps), `energyKcal`, `proteinG`, `carbsG`, `fatG`,
`fiberG`, `loggedEntryCount`.

`loggedEntryCount` is load-bearing rather than decorative: a researcher cannot
otherwise distinguish "ate nothing" from "did not log", so completeness is a
scientific necessity. It is a count, never the entries.

Nothing finer than a day, ever, in this tier. No food names, no free text, no
photos, no meal times. Weight trajectory is a plausible second tier, separately
consented, defined when a study actually needs it.

**The escape valve is a protocol revision, not a configuration.** A study-supplied
field list would turn the client into a remotely configurable exfiltration
engine and the consent screen into UI generated from researcher-controlled
input — prohibition 11 of ADR-0002 wearing a JSON schema. The window is the one
study-supplied parameter, and it is safe because a window can only narrow a
fixed schema: it cannot refine below the day floor or widen the field set.

The fixed schema is also the blast-radius control. A compromised study account
yields the reduced tier for N people, never N diaries.

### The pseudonym derives from a secret the server never holds

A per-account random 256-bit **pseudonym root**, generated at first enrolment and
stored in the owner-private compartment — which is what makes it survive a
recovery restore and reach a second device, so the pseudonym is stable.

```
pid = HMAC-SHA-256(root, "openplate-sync:study-pseudonym:v1" ‖ studyAccountId)
      truncated to 128 bits, Crockford base32
```

Stable across submissions and devices; unlinkable across studies, because HMAC
outputs under different messages are independent; and underivable by anyone
holding both the account table and a cohort, because the root is random and
never leaves the compartment.

**`H(accountId ‖ studyId)` is rejected on exactly that last point** — with public
inputs it reverses by enumeration over the account table.

**Be precise about whom this defends against: the researcher, not the server.**
The server authenticates the push by bearer token, so it knows which account
owns which row regardless. Once that is accepted, the pseudonym may travel in
the clear as a row attribute — the server learning it adds nothing to the
stronger fact it already holds.

### The envelope, and the identifier that must not appear

Ephemeral P-256 ECDH against the study's public key, HKDF under a **new frozen
label** `openplate-sync:research-kek:p256:v1`, AES-256-GCM. A new label rather
than a version bump of the share label: different purpose, same reasoning that
put the curve in the name.

There is no DEK in this lane. The wrap is over the payload directly.

```
AAD ← canonical fixed-key-order JSON
  {"studyAccountId":<int>,"pseudonym":"<string>","contributionVersion":<int>,
   "schemaTier":"daily-intake:v1","studyKeyFingerprint":"<base64>"}
```

Every field is reconstructible by the researcher before decryption: four ride in
the response, and the fingerprint is computed **locally from her own key**, which
keeps the substitution defence out of the server's hands.

**It contains no account id, and neither does any study-side response.** This is
the exact inversion of §5.16, where `grantorAccountId` is *required* because
§3.2's AAD binds it. Anyone reusing the shared-blob response shape here imports
the leak. The AAD above was designed so the identifier is never needed.

### Withdrawal: erase what we hold, instruct about what we do not

Three layers with different physics.

1. **The server's copy is genuinely erasable, and is erased.** Withdrawal
   hard-deletes the contribution row. Unlike the clinician case there is a real
   window where this is *full* erasure — a contribution not yet pulled reaches
   nobody.
2. **The researcher's pulled copy cannot be repossessed.** ADR-0002's sentence
   stands and no UI may contradict it.
3. **A withdrawal tombstone, keyed by pseudonym only.** ADR-0002 rejected
   tombstones; that argument does not transfer. There, a tombstone defended
   nothing. Here it carries exactly the payload the obligation needs — *which
   pseudonym to purge* — while the thing §9.2 wants gone, the account edge, dies
   with the row. **The live system forgets who; it remembers only that a
   pseudonym withdrew.** The study client must purge tombstoned pseudonyms
   before presenting or exporting anything: mechanical, on every pull, tested,
   never advisory.

Erasability is what forces the server to know cohort membership: deleting my row
requires finding my row. That trade is made deliberately and disclosed below.

**The binding words:** *"Your contributions have been removed from this study and
the study can no longer receive anything from you. Data the study team already
retrieved is governed by their ethics obligations — this system has instructed
them to delete it, and cannot force it."*

Backups predate the delete. The live system forgetting is the claim; immunity of
backups is not.

### A study is an ordinary sync account

Extending ADR-0002's D6. No new principal type, no role column, no server-side
study registry. Being a study is the fact that contribution rows point at you.

The keypair is generated on the researcher's device and its private key lives in
the study account's own owner-private compartment.

**The ceremony cannot be the consultation room, and must not pretend to be.** A
cohort has no room. The trust anchor moves to the study's **ethics-approved
consent materials**: the study key fingerprint is printed there, and the
contributor types it at enrolment. Typed, never tapped — the discipline is
unchanged, and it survives the move only in that form, because one substituted
study key harvests N people rather than one.

What matters is preserved: the fingerprint reaches the contributor over a
channel the sync server does not control.

**Key loss is attrition, not a brick, and that is the design working.** There is
no shared DEK and no rotation analogue. If a study loses its passphrase and
recovery code, existing ciphertexts are dead — but every contributor's client
still holds the source, so active contributors re-encrypt and re-push after a
new ceremony. The failure mode fails toward *less* data reaching the researcher,
which is the correct direction. No escrow: that is ADR-0001's back door
multiplied by N.

## What the server learns, and why we accept it

**The server learns which account contributes to which study, when, how often,
and how large the contribution is.** This is unavoidable, and withdrawal is the
proof: erasure requires locating the row, account deletion must cascade through
it, and CAS and abuse control key on the account. Any scheme that blinds the
server breaks one of those, and traffic analysis un-blinds it anyway.

So it goes into §9.2 in the same register as the care graph, in the first slice
rather than at GA. An edge here says "this person's health data is in study Y".

Do not build a half-measure that *pretends* to avoid it. A fake anonymity layer
that the withdrawal path contradicts is worse than the disclosure.

## Prohibitions

1. **The contribution schema is fixed by protocol revision, never by study
   configuration.** No server- or study-supplied field list reaches the reducer.
2. **No study-side endpoint, response or export ever carries a contributor's
   account id.** The mapping exists for CAS, withdrawal and cascade, and it
   stops at the server.
3. **The pseudonym derives only from the compartment root** — never from the
   account id, the email, or any server-known value. The server never computes
   it and cannot verify it.
4. **An account without an owner-private compartment cannot enrol.** The
   no-recovery-code branch leaves such an account; an unstable pseudonym after a
   recovery restore is not an acceptable degradation.
5. **No wording anywhere may call a contribution anonymous.** Pseudonymised,
   with the auxiliary-data caveat stated.
6. **Withdrawal is one transaction: hard-delete the row, insert the
   pseudonym-keyed tombstone.** No account id survives on any withdrawal record.
7. **Contributions are never wrapped under the DEK and never ride through
   `rotate-dek`.** Wiring them into that transaction would couple two unrelated
   key domains.
8. **The study client purges tombstoned pseudonyms before presenting or
   exporting** — enforced mechanically on every pull, and tested.
9. **`SYNC_RESEARCH` unset means the ordinary unknown-route 404**, to everybody,
   terminator mounted before authentication, from the first commit.
10. **No server-hosted study registry**, and the server never stores, serves or
    endorses a study public key. Extends ADR-0002 prohibition 1.
11. **The reduction map fails closed.** A payload field nobody classified is a
    red test, not a shipped field.
12. **No admin-surface exposure of the cohort graph** — per-account counts at
    most, never edges. Extends ADR-0002 prohibition 2.
13. **No GA without** the §9.2 study-graph amendment, per-study ethics-approval
    recording, and the Art 9(2)(j) sign-off.

## The attacks that break this, ranked

1. **The auxiliary join.** Re-identification of a pseudonymous longitudinal
   series by a researcher holding any other dataset. No pseudonym fixes it and
   this ADR does not claim one does. Carried by consent wording and the ethics
   gate.
2. **Enrolment-time study-key substitution.** The cohort version of ADR-0002's
   second attack, and worse by a factor of N. Defended by a fingerprint that
   travels in the consent materials, typed not tapped, pinned in the
   compartment.
3. **Study account takeover.** Phish one researcher, get every current
   contribution. No cryptography prevents it; the blast radius is the reduced
   tier, never a diary.
4. **Scope creep through the escape valve.** The pressure to "just add meal
   times for this one study" arrives with the first real study. Prohibition 1
   exists so that pressure meets a document rather than a judgement call at six
   in the evening.
5. **Splice and rollback across rows** — defeated by the AAD, not by trusting
   the server's rows.
