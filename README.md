# openplate-sync

The account service for [openplate](https://github.com/LowCarbCheck/openplate). Its first feature is end-to-end-encrypted sync between your devices.

It holds two things: an email address, and opaque ciphertext. It cannot read what it stores — not as a policy, but as a consequence of never receiving a key. Your passphrase never leaves your device; what reaches the server is a derived value that authenticates you and decrypts nothing.

**Start with [`PROTOCOL.md`](./PROTOCOL.md).** It is the normative specification of the wire protocol, written so a third party can implement either side of it without reading this code — an alternative client against this service, or an alternative server that an openplate client can be pointed at with `SYNC_SERVER_URL`.

**This service is optional.** openplate is a complete, fully functional tracker without it: your diary lives in the browser, exports to JSON, and imports again on another device. Sync removes the manual step; it does not unlock anything.

> **Open source.** openplate-sync is licensed under the [MIT License](./LICENSE) (SPDX: `MIT`), the same license as the openplate app. Self-hosting is explicitly one of the things it supports. See [License](#license).

---

## Self-hosting

```bash
git clone https://github.com/LowCarbCheck/openplate-sync.git
cd openplate-sync
cp .env.example .env

# Generate the one secret you must not lose:
openssl rand -hex 32     # → paste into SERVER_SECRET in .env
# Set CLIENT_BASE_URL to wherever your openplate client is served.

docker compose up -d
curl http://localhost:3000/health
```

That is the whole install. Postgres comes up alongside the service, the schema migrates itself on boot, and there is nothing else to run.

Then point your openplate app at it by setting `SYNC_SERVER_URL` to this service's public URL — the one a **browser** can reach, since the sync client runs in the page. If you want both halves in one file, openplate ships a combined [`docker-compose.full.yml`](https://github.com/LowCarbCheck/openplate/blob/main/docker-compose.full.yml) that brings up the app, this service and a shared Postgres together.

### Mail is optional

With no mail configured, verification and reset links are printed to the service log:

```bash
docker compose logs -f sync
```

That is a supported way to run a personal or family instance, not a degraded one. Set `SMTP_HOST` and friends when you want real delivery. Every setting is documented in [`.env.example`](./.env.example).

### Two settings that matter more than the rest

- **`SERVER_SECRET`** — back it up _with your database_. Two subkeys are derived from it: the pepper mixed into every stored auth verifier, and the key behind the anti-enumeration KDF responses. A restored database with a lost secret is a database nobody can log into, and every account would need a passphrase reset.
- **`TRUST_PROXY`** — set it to the number of reverse proxies in front of the service (`1` behind a single nginx or Traefik). Left at `false` behind a proxy, every request appears to come from the proxy's address and the per-IP throttle becomes one global bucket a single attacker can lock for all your users. Set to `true` with nothing in front, anyone can spoof `X-Forwarded-For` and skip the throttle entirely.

Also worth knowing: **`SIGNUPS_OPEN=false`** closes registration on a family instance while leaving existing accounts working.

### What your users should understand

Losing the passphrase without the recovery code means losing the data. Permanently, and to you as the operator too. The email reset flow restores _login_ and cannot restore _data_ — the reset email says so in those words before anyone clicks. This is the direct cost of the server not being able to read anything, and it is not a bug you can fix from the server side.

---

## How it works

An openplate client serializes its whole local store, gzips it, encrypts it with AES-256-GCM under a key derived from the user's passphrase, and pushes the result as one opaque blob. The server versions those bytes and refuses writes that would clobber another device's. It also stores two small **key records** — the same data-encryption key wrapped under two different key-encryption keys, one from the passphrase and one from a recovery code — so a second device can bootstrap.

Accounts follow the Bitwarden model. The client derives two independent values from the passphrase via HKDF: one that unwraps the data key and never leaves the device, and one that it sends as its password. The server stores a keyed hash of the second under a secret held outside the database. Authentication therefore works without the server ever holding anything that could decrypt a blob.

Sessions are a short-lived access token plus a rotating refresh token, both stored only as digests. A passphrase change or a reset revokes every outstanding session immediately — which is precisely why they are database-backed opaque tokens rather than JWTs.

Full detail, including the exact HKDF labels, token lifetimes, and an honest account of what the server _does_ know: [`PROTOCOL.md`](./PROTOCOL.md).

### An account service, not a sync server

The name says sync because that is what it does today. The shape says account service, and that is deliberate: this is intended to become the shared identity for the wider [LowCarbCheck](https://lowcarbcheck.org) ecosystem, with community features (saved items, profiles, comments) hanging off the same account id later.

That future is already constrained rather than left open. [ADR 001](./docs/adr/001-community-auth-lane.md) fixes the rule now, while it is still cheap: community features get a **second authentication lane** that shares only the account id space. They will never touch the vault credential, because that credential is a sibling of the key that decrypts a user's data, and the surfaces that render other people's content are the last place it belongs. The `accounts` table stays minimal for the same reason.

---

## License

openplate-sync is **open source** under the [MIT License](./LICENSE) (SPDX: `MIT`), matching the [openplate](https://github.com/LowCarbCheck/openplate) app. MIT is one of the most permissive licenses available: run it, read it, change it, fork it, redistribute it, host it for others — commercially or not — with no restrictions beyond keeping the copyright and license notice attached to any copy you distribute. Self-hosting this service is a first-class use, and so is running it as a hosted product for others.

---

## Development

```bash
pnpm install
pnpm run typecheck
pnpm run test:unit          # node:test — handler cores, auth policy, protocol drift guard. No DB.
pnpm run test:integration   # boots the real app against a real Postgres
pnpm run lint               # oxlint, zero warnings
pnpm run build              # esbuild → dist/server.js
pnpm run dev                # tsx watch
```

Linting is [oxlint](https://oxc.rs) plus a vendored `anti-slop` plugin under
`tools/oxlint/anti-slop/` (MIT, © Dillon Mulroy — its own LICENSE ships beside
it). The gate is zero warnings, and `pnpm lint` runs first in the pre-push
hook. The rule that shapes this codebase most is the one against unparsed
input: request bodies enter as `JsonValue` and are decoded through
`src/lib/json.ts`, which is the only module that inspects a JSON primitive at
runtime.

The integration suite targets a local Postgres at `localhost:5433` and creates `openplate_sync_test` on first run. Override with `TEST_DATABASE_URL`. It deliberately does **not** use the compose database — that one is for self-hosters.

### Layout

| Path                  | What lives there                                                              |
| --------------------- | ----------------------------------------------------------------------------- |
| `src/protocol.ts`     | The wire contract: versions, limits, request/response types, handshake check. |
| `src/server/`         | Express glue, the sync handler cores, CORS, bearer auth, error handling.      |
| `src/accounts/`       | Account policy as pure handlers over an injected `AccountStore`.              |
| `src/db/`             | Drizzle schema and the two store implementations.                             |
| `src/lib/`            | Pure primitives: verifier, tokens, KDF descriptors, throttle.                 |
| `src/mail/`           | Console / SMTP / pigeon transports and the two messages this service sends.   |
| `drizzle/migrations/` | Generated migrations. Never hand-written — see `src/db/schema.ts`.            |

### Invariants

- **No `@sprqvntrs/*` or private-registry dependencies.** This repo must be buildable by anyone. The pigeon mail transport is a hand-written HTTP client for exactly that reason.
- **Handler cores stay pure and dependency-injected.** The shell owns Express, the database and the environment; the cores take a store, a clock and a token minter. That is why the auth suite tests rotation, reuse detection and revocation without a database.
- **`src/protocol.ts` is a hand-maintained duplicate** of `openplate/app/lib/sync/engine/protocol.ts`. There is no shared package and no shared CI, so both repos carry a unit test asserting the constants against _transcribed literals_. Changing the protocol means editing four places — two sources and two tests — starting with PROTOCOL.md.
- **Migrations are generated, never written.** And journal timestamps are never hand-edited: the migrator applies only migrations newer than the last applied one, so an out-of-order value causes a later migration to be silently skipped at boot.
