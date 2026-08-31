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

docker compose --project-directory . -f docker/compose.yml up -d
curl http://localhost:3000/health
```

That is the whole install. Postgres comes up alongside the service, the schema migrates itself on boot, and there is nothing else to run.

`--project-directory .` is what keeps the repository root as the project root, so `.env` is read from where you created it and the image builds from the checkout rather than from `docker/`. If you would rather run the published image than build from source, copy `docker/compose.yml` out on its own, uncomment the `image:` line, and plain `docker compose up -d` beside it works.

Then point your openplate app at it by setting `SYNC_SERVER_URL` to this service's public URL — the one a **browser** can reach, since the sync client runs in the page. If you want both halves in one file, openplate ships a combined [`docker/topologies/compose.sync.yml`](https://github.com/LowCarbCheck/openplate/blob/main/docker/topologies/compose.sync.yml) that brings up the app, this service and a shared Postgres together.

### Mail is optional

With no mail configured, verification and reset links are printed to the service log:

```bash
docker compose --project-directory . -f docker/compose.yml logs -f sync
```

That is a supported way to run a personal or family instance, not a degraded one. Set `SMTP_HOST` and friends when you want real delivery. Every setting is documented in [`.env.example`](./.env.example).

### Four settings that matter more than the rest

- **`SERVER_SECRET`** — back it up _with your database_. Two subkeys are derived from it: the pepper mixed into every stored auth verifier, and the key behind the anti-enumeration KDF responses. A restored database with a lost secret is a database nobody can log into, and every account would need a passphrase reset. The same is true of a deliberate rotation: changing this value invalidates every stored verifier at once, so it cannot be rotated after a suspected leak without resetting every account's passphrase.
- **`TRUST_PROXY`** — set it to the number of reverse proxies in front of the service (`1` behind a single nginx or Traefik). Left at `false` behind a proxy, every request appears to come from the proxy's address and the per-IP throttle becomes one global bucket a single attacker can lock for all your users. Set to `true` with nothing in front, anyone can spoof `X-Forwarded-For` and skip the throttle entirely.

- **`CLIENT_BASE_URL`** — the URL of the openplate **client**, not of this service. Verification and reset emails link to `/verify-email` and `/reset-passphrase`, which only the client serves; point this at the sync server by mistake and every link in every email answers `404`.

Your reverse proxy must also allow request bodies of about **2.75 MB**. Blobs are capped at 2 MB, base64 inflates them by a third, and nginx's default `client_max_body_size` is 1 MB — left at the default it rejects legitimate maximum-size syncs before this service ever sees or logs them. In nginx that is `client_max_body_size 3m;`.

- **`SYNC_RESEARCH`** — off by default. Turning it on opens the `/v1/sync/contributions` and
  `/v1/sync/study` endpoints, which is what brings the openplate client's `/study` console to
  life, and makes this server hold a study graph of health-adjacent personal data.
  Read [`.env.example`](./.env.example) before you set it; it is a different undertaking from
  holding ciphertext you cannot read.

Also worth knowing: **`SIGNUP_MODE`** decides who may register, and existing accounts keep
working whichever you pick.

| Value            | Who can create an account                            |
| ---------------- | ---------------------------------------------------- |
| `open` (default) | Anybody who can reach the service.                   |
| `invite`         | Only somebody holding a single-use token you minted. |
| `closed`         | Nobody.                                              |

Invite mode needs `ADMIN_TOKEN` set, because that is what mints the tokens:

```bash
pnpm sync-api invites create --note "who it is for" --client-url https://your-app.example
```

The token is printed **once** and is not stored — only its digest is. If you lose it, revoke
the invite and mint another. One invite creates one account, and a failed attempt (a taken
email address, say) does not spend it.

> The older **`SIGNUPS_OPEN`** variable was removed. The service now refuses to start if it is
> set, rather than ignoring it: it defaulted to _open_, so an instance that had it set to
> `false` would silently start accepting registrations again on the upgrade that ignored it.

### Backup and restore

Two things must survive together: the Postgres data and `SERVER_SECRET`. Either one alone
restores nothing usable.

```bash
# Back up
docker compose --project-directory . -f docker/compose.yml exec -T postgres \
  pg_dump -U openplate openplate_sync > sync-backup.sql

# Restore, into a stopped-then-started stack, before users reconnect
docker compose --project-directory . -f docker/compose.yml exec -T postgres \
  psql -U openplate openplate_sync < sync-backup.sql
```

The database lives in the `postgres-data` volume declared by `docker/compose.yml`. Keep
`SERVER_SECRET` with the dump, in whatever holds your other secrets — not in the dump itself.

### What your users should understand

Losing the passphrase without the recovery code means losing the data. Permanently, and to you as the operator too. The email reset flow restores _login_ and cannot restore _data_ — the reset email says so in those words before anyone clicks. This is the direct cost of the server not being able to read anything, and it is not a bug you can fix from the server side.

### The admin API is off unless you turn it on

There is an operator API at `/v1/admin` — list accounts, read one account's
metadata, aggregate storage counts, and **delete an account with everything
attached to it**. It exists mainly for that last one: an erasure request is an
obligation, and a service whose only erasure mechanism is a hand-written
`DELETE` in a SQL client is a service that will eventually get it wrong.

It is **unmounted unless `ADMIN_TOKEN` is set**. With the variable unset the
whole `/v1/admin` tree answers the same `404` any unknown path does, to
everybody — an instance that never configured it is indistinguishable from one
built before the feature existed. A `401` there would announce that a
credential exists and is merely locked.

Under Compose, put the value in `.env` — `docker/compose.yml` already forwards
`ADMIN_TOKEN` into the container. Compose passes only the variables that file's
`environment:` block names, so a variable you add to `.env` and nowhere else
never reaches the service. The same holds for `SYNC_SHARING`, `SYNC_RESEARCH`,
`PIGEON_API_KEY`, `PIGEON_BASE_URL` and `DATABASE_SSL`, all of which are
forwarded there too.

What it can never do, by design rather than by default:

- **Read a blob.** Ciphertext is not exported through the admin surface in any
  form. A blob is reported as a byte count and a timestamp.
- **Return a verifier or a KDF descriptor.** Neither has an operational use
  that justifies putting it where a screenshot or a paste can carry it.
- **Reset anyone's passphrase.** There cannot be a meaningful admin reset: the
  passphrase wraps the data key on the client, so a server-side credential
  change would produce an account that logs in and decrypts nothing.
- **Send email.**

The reasoning in full is in
[`docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md`](./docs/adr/0001-an-admin-api-for-a-zero-knowledge-service.md).

---

## How it works

The client encrypts your data before it ever leaves the device, using a key derived from your passphrase; the server only ever sees and stores opaque ciphertext blobs and wrapped key records, never a passphrase or a key that could decrypt them. This is a zero-knowledge design: authentication and sync both work without the server holding anything that unwraps your data.

Full detail, including the exact protocol, HKDF labels, and token lifetimes: [`PROTOCOL.md`](./PROTOCOL.md).

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

`pnpm sync-api` is a thin HTTP client over the admin API — it imports no
database code, so it runs from a machine with no Postgres:

```bash
ADMIN_TOKEN=... pnpm sync-api status
ADMIN_TOKEN=... pnpm sync-api accounts list --limit 20
ADMIN_TOKEN=... pnpm sync-api accounts get 42 --json
ADMIN_TOKEN=... pnpm sync-api accounts delete 42 --yes
```

The token comes from `ADMIN_TOKEN` and nowhere else — there is no `--token`
flag, because a credential in argv lands in shell history and is visible in
`ps`. The target is `--url`, then `SYNC_SERVER_URL`, then
`http://localhost:3000`. Deletion requires `--yes`. The CLI is not part of the
Docker image.

Two optional conveniences:

- `nix develop` gives you a shell with the expected Node 22 and pnpm, if you have Nix with flakes enabled.
- `docker compose -f docker/compose.dev.yml up -d` starts the contributor test database on port 5433, for the integration suite. Skip it if something already answers on that port.

Linting is [oxlint](https://oxc.rs) plus a vendored `anti-slop` plugin under
`tools/oxlint/anti-slop/` (MIT, © Dillon Mulroy — its own LICENSE ships beside
it). The gate is zero warnings, and `pnpm lint` runs first in the pre-push
hook. The rule that shapes this codebase most is the one against unparsed
input: request bodies enter as `JsonValue` and are decoded through
`src/lib/json.ts`, which is the only module that inspects a JSON primitive at
runtime.

The integration suite targets a local Postgres at `localhost:5433` (user `postgres`, password `postgres`) and creates `openplate_sync_test` on first run. Override with `TEST_DATABASE_URL`. It deliberately does **not** use the self-hosting database in `docker/compose.yml` — that one is for self-hosters. If you have no Postgres on 5433, `docker/compose.dev.yml` is a one-service file that provides exactly that and nothing else.

### Layout

| Path                  | What lives there                                                              |
| --------------------- | ----------------------------------------------------------------------------- |
| `src/protocol.ts`     | The wire contract: versions, limits, request/response types, handshake check. |
| `src/server/`         | Express glue, the sync handler cores, CORS, bearer auth, error handling.      |
| `src/accounts/`       | Account policy as pure handlers over an injected `AccountStore`.              |
| `src/db/`             | Drizzle schema and the two store implementations.                             |
| `src/admin/`          | The admin metadata read contract — deliberately not part of `AccountStore`.   |
| `src/lib/`            | Pure primitives: verifier, tokens, KDF descriptors, throttle.                 |
| `src/mail/`           | Console / SMTP / pigeon transports and the two messages this service sends.   |
| `scripts/sync-api/`   | The `pnpm sync-api` admin CLI. HTTP only — it imports no database code.       |
| `drizzle/migrations/` | Generated migrations. Never hand-written — see `src/db/schema.ts`.            |

### Invariants

- **No `@sprqvntrs/*` or private-registry dependencies.** This repo must be buildable by anyone. The pigeon mail transport is a hand-written HTTP client for exactly that reason.
- **Handler cores stay pure and dependency-injected.** The shell owns Express, the database and the environment; the cores take a store, a clock and a token minter. That is why the auth suite tests rotation, reuse detection and revocation without a database.
- **`src/protocol.ts` is a hand-maintained duplicate** of `openplate/app/lib/sync/engine/protocol.ts`. There is no shared package and no shared CI, so both repos carry a unit test asserting the constants against _transcribed literals_. Changing the protocol means editing four places — two sources and two tests — starting with PROTOCOL.md.
- **Migrations are generated, never written.** And journal timestamps are never hand-edited: the migrator applies only migrations newer than the last applied one, so an out-of-order value causes a later migration to be silently skipped at boot.
