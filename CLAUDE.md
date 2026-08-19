# openplate-sync

See [`README.md`](./README.md) for what this service is and does, and
[`PROTOCOL.md`](./PROTOCOL.md) for the normative wire spec. This file is
agent-facing guidance for working in the repo — issue/PR triage, dev
workflow.

## Issue & PR triage

- **Every issue gets one `area:` label and one type label** (`bug`,
  `enhancement`, `documentation`, `question`, ...). Areas: `area: crypto`
  (envelope, KDF descriptors, verifier), `area: auth` (bearer tokens,
  registration, sessions), `area: storage` (blob store, key records,
  Postgres), `area: protocol` (wire contract, versioning), `area: ops`
  (docker, compose, migrations, config).
- **`needs info`** — apply when a report is missing what's needed to act on
  it (service version, deployment shape — compose vs. bare, logs). Ask for
  logs **without sensitive payloads**: ciphertext, tokens, `SERVER_SECRET`,
  or email addresses should never be pasted into a public issue. Remove the
  label once the missing info arrives.
- **`regression`** — only apply once the reporter (or triage) has confirmed
  a last-good version. Without one, it's an unconfirmed `bug`, not a
  regression.
- **Security reports are never triaged in a public issue.** If a report
  arrives as a public issue and it's plausibly a vulnerability, close/redirect
  it to [private vulnerability reporting](https://github.com/LowCarbCheck/openplate-sync/security/advisories/new)
  per [`SECURITY.md`](./SECURITY.md) — don't discuss specifics publicly first.
  **Any report that even might be a crypto/correlation flaw — anything that
  could let the server decrypt or correlate a blob it shouldn't, break token
  revocation, or open a new enumeration oracle beyond the signup-conflict `409`
  documented as an accepted tradeoff in [`SECURITY.md`](./SECURITY.md) — is
  treated as security until proven otherwise.** When in doubt, redirect
  privately first and downgrade only after confirming it isn't one.
- **PRs**: apply the relevant `area:` label(s) on open. Before requesting
  review, CI must be green end to end: lint → typecheck → unit →
  integration → build (see `pnpm` scripts below). Don't spend review effort
  on a red PR — ask the author to get it green first.

## Development

```bash
pnpm install
pnpm run typecheck
pnpm run test:unit          # node:test — handler cores, auth policy, protocol drift guard. No DB.
pnpm run test:integration   # boots the real app against a real Postgres (localhost:5433)
pnpm run lint               # oxlint, zero warnings
pnpm run build              # esbuild → dist/server.js
```

See the README's [Development](./README.md#development) and
[Layout](./README.md#layout) sections for the module map and the
`src/lib/json.ts` input-parsing invariant.
