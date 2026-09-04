# openplate-sync

The account service for [openplate](https://github.com/LowCarbCheck/openplate). Its first feature is end-to-end-encrypted sync between your devices.

**What this server holds, in one paragraph.** An email address, an opaque ciphertext blob per account, wrapped key records it cannot unwrap, and each account's recovery code sealed under a key in the environment. It cannot read the ciphertext, not as a policy, but as a consequence of never receiving a key: your passphrase never leaves your device, and what reaches the server is a derived value that authenticates you and decrypts nothing. The escrowed recovery code is the deliberate exception, and it is what makes "forgot password" restore the diary rather than only the login. **It also means the operator of a hosted instance can open any account on it** — not through an endpoint, there is none, but by reading that column with `SERVER_SECRET` in hand. A self-hosted instance is its own operator. The full argument, including what it costs and why it was taken, is [ADR-0005](./docs/adr/0005-organization-accounts-and-escrowed-recovery.md).

**And one thing that passes through without being held.** If the operator configures a provider key, this service proxies the app's food-photo requests to that provider at `POST /v1/chat/completions`, so the photograph and the model's answer cross this process. Neither is written, cached or logged — not the body, not a prefix, not a decoded buffer. What a log line carries is an account id, an upstream status, byte counts and a duration. This is also the one route where the zero-knowledge claim genuinely does not hold: the blob store cannot read what it holds, and the proxy can see everything that passes through it. Leave `UPSTREAM_API_KEY` unset and the route does not exist.

**Start with [`PROTOCOL.md`](./PROTOCOL.md).** It is the normative specification of the wire protocol, written so a third party can implement either side of it without reading this code — an alternative client against this service, or an alternative server that an openplate client can be pointed at with `SYNC_SERVER_URL`.

**This service is optional.** openplate is a complete, fully functional tracker without it: your diary lives in the browser, exports to JSON, and imports again on another device. Sync removes the manual step; it does not unlock anything.

> **Open source.** openplate-sync is licensed under the [MIT License](./LICENSE) (SPDX: `MIT`), the same license as the openplate app. Self-hosting is explicitly one of the things it supports. See [License](#license).

---

## Documentation

`docs/` holds only architecture decision records for now
([`docs/adr/`](./docs/adr/)); this README's Self-hosting, The AI proxy, Backup and restore,
and The admin API sections read like standalone guides and are candidates for splitting into
`docs/` files later.

### Reference

| Guide | What it covers |
| --- | --- |
| [**Protocol**](./PROTOCOL.md) | The wire and key protocol, version 2 |

---

## Self-hosting

```bash
git clone https://github.com/LowCarbCheck/openplate-sync.git
cd openplate-sync
cp .env.example .env

# Generate the one secret you must not lose:
openssl rand -hex 32     # → paste into SERVER_SECRET in .env
# That is the only value you must set.

docker compose --project-directory . -f docker/compose.yml up -d
curl http://localhost:3000/health
```

That is the whole install. Postgres comes up alongside the service, the schema migrates itself on boot, and there is nothing else to run.

`--project-directory .` is what keeps the repository root as the project root, so `.env` is read from where you created it and the image builds from the checkout rather than from `docker/`. If you would rather run the published image than build from source, copy `docker/compose.yml` out on its own, uncomment the `image:` line, and plain `docker compose up -d` beside it works.

Then point your openplate app at it by setting `SYNC_SERVER_URL` to this service's public URL — the one a **browser** can reach, since the sync client runs in the page. If you want both halves in one file, openplate ships a combined [`docker/topologies/compose.sync.yml`](https://github.com/LowCarbCheck/openplate/blob/main/docker/topologies/compose.sync.yml) that brings up the app, this service and a shared Postgres together.

### Signup is invite-only, and mail is optional

An account is an **email address plus a passphrase**, and it is created by redeeming an invite you addressed to somebody. There is no open registration and no closed mode: the invite is the only door.

```bash
pnpm sync-api invites create --email anna@example.org --name "Anna"
```

That prints a link (or, if you configured no `CLIENT_BASE_URL`, the raw token) **once**. It is not stored, only its digest is. One invite creates one account, at the address it names, and a failed attempt does not spend it.

**The invitation is the address verification.** `POST /v1/auth/signup` reads the address from the invite row, never from the request body, so the person who received the letter is the person who signs up. There is no confirmation link and nothing left to confirm afterwards.

**Mail is optional.** Set `MAIL_API_*` and this service sends the invitation and the password reset itself; leave it unset and both come back to you as links to paste. Nothing is silently dropped either way. `SMTP_*` and `PIGEON_*` are boot failures rather than no-ops: this service speaks pigeon's HTTP API and nothing else.

### The password reset, and what it costs

"Forgot password" works, and unlike the mailed reset this service used to have, it **restores the diary rather than only the login**.

It works this way: the client generates the recovery code at signup and sends it to the server, which seals it into `accounts.recovery_code_escrow` under a subkey of `SERVER_SECRET`. `POST /v1/auth/reset/request` mails a link; `POST /v1/auth/reset/open` spends it once and hands the code back; the client then runs the ordinary recovery ceremony with it — new passphrase, re-wrapped data key, new code, re-sealed escrow, one transaction. **The reset endpoint writes nothing to the account.** Without the key records, what it returns is a string.

**The cost, stated plainly: you, as the operator, hold what it takes to open any account on your instance.** Not through an endpoint — there is none, and no admin call ever prints a recovery code — but by reading that column with `SERVER_SECRET` in hand. If you run an instance for other people, they are trusting you and not only the cryptography, and they should be told so.

If you are your own operator, which is what self-hosting means, the older promise is intact: nobody but you can open your diary, and you already could.

### The AI proxy, and the allowance that bounds it

openplate can name a plate from a photograph. The model that does it is not in
this repository and not on your server: it is a provider you pay, and this
service is the thing that stands between your users and your bill.

```bash
UPSTREAM_BASE_URL=https://openrouter.ai/api/v1
UPSTREAM_API_KEY=sk-...            # both, or neither. One alone is a boot failure.
AI_ADVERTISED_MODEL=some/model     # optional, advertising copy for the app
AI_RATE_LIMIT_PER_MINUTE=20        # per account, default 20
UPSTREAM_TIMEOUT_MS=120000         # per request, default two minutes
```

With both set, a signed-in account posts an ordinary OpenAI-compatible request
to `POST /v1/chat/completions` **with its own access token**. This service
spends one unit of that account's daily allowance, replaces the token with your
provider key, forwards the body untouched, and streams the answer back. The
account never learns your key. The provider never learns the account's token.

**The allowance is per account, per UTC day, and it defaults to zero.** A new
invite hands out no AI at all unless you say otherwise, so an operator who
mints an ordinary invitation has not given away their provider key by accident:

```bash
pnpm sync-api invites create --email anna@example.org --name Anna --daily-limit 200
pnpm sync-api accounts set-limit 42 200      # or change it later
pnpm sync-api accounts set-limit 42 0        # or turn it off
```

Every proxied answer carries `X-Quota-Used` and `X-Quota-Limit`. An account at
its limit gets a `429` naming the UTC midnight it resets at, with `Retry-After`
in seconds. An account with an allowance of zero gets `403 ai-not-allowed`
before any request leaves your host.

**A unit is reserved before the call and given back only when the provider
cannot have billed you.** A connection that never opened, a provider that
refused the request outright, or a bound of yours that expired before any byte
arrived: released. A provider that accepted the request and then failed while
serving it: spent, because generation may have run and a released unit there is
a free retry loop against exactly the provider that is flaking.

There is also a per-account limiter of twenty requests a minute, which is a
different bound for a different failure: a stuck client that retries on every
error would otherwise spend a whole day's allowance in ten seconds, and the
first thing the person sees is that the feature stopped working.

Leave `UPSTREAM_API_KEY` unset and none of this exists. The route answers the
same `404` any unknown path does, and `/health` reports `instance.ai: null` so
the app knows not to offer a scan.

Setting any of the removed variables (`SIGNUP_MODE`, `SIGNUPS_OPEN`, `EMAIL_FROM`, `SMTP_*`, `PIGEON_*`, `REQUIRE_EMAIL_VERIFICATION`) is a **boot failure**, not a no-op. See [`.env.example`](./.env.example) for why refusing to start is the safer answer.

### The two letters are the whole of what it sends

An invitation and a password reset. Neither is a channel for anything else:
there is no breach notification, no "this instance is moving", no "your account
will be deleted on Friday". The bound is deliberate rather than unfinished. A
service that can send arbitrary mail grows a notification system, and a
notification system is a reason to keep reaching for the address column beside a
diary the operator cannot read.

**So if you need to reach your users about anything else, keep that list
yourself, outside this service.** You already know who they are: you addressed
their invitations. A household has a chat, a clinic has a patient record, an
employer has a directory.

The one thing the service does offer in between is a **notice on the
handshake**. Set
`SYNC_NOTICE` (and optionally `SYNC_NOTICE_URL`) and every client that connects
shows the message as a dismissible banner:

```bash
SYNC_NOTICE="This instance moves to sync.example.org on 1 March. Sign in there with the same address."
SYNC_NOTICE_URL="https://example.org/moving"
```

Know exactly what that is and is not. It is **pull, not push**: the client reads
it from `GET /health` when it connects, so it reaches only the people who open
the app, it does not reach anybody who has stopped using it, and the server never
learns who read it. Changing it is a redeploy. The
text is capped at 280 characters because `/health` is also the container's
healthcheck path and is polled continuously. For anything that must actually
arrive, use your own contact list.

### Three settings that matter more than the rest

- **`SERVER_SECRET`** — back it up _with your database_. Three subkeys are derived from it: the pepper mixed into every stored auth verifier, the key behind the anti-enumeration KDF responses, and the AES key that seals each account's escrowed recovery code. A restored database with a lost secret is a database nobody can log into, **no recovery code gets anybody back in** (the pepper keys both verifiers), and **no password reset works either** (the escrow cannot be opened). The same is true of a deliberate rotation. There is no path that repairs this from the server side, so treat the secret as part of the backup, not as a setting.
- **`TRUST_PROXY`** — set it to the number of reverse proxies in front of the service (`1` behind a single nginx or Traefik). Left at `false` behind a proxy, every request appears to come from the proxy's address and the per-IP throttle becomes one global bucket a single attacker can lock for all your users. Set to `true` with nothing in front, anyone can spoof `X-Forwarded-For` and skip the throttle entirely.

Your reverse proxy must also allow request bodies of about **2.75 MB**. Blobs are capped at 2 MB, base64 inflates them by a third, and nginx's default `client_max_body_size` is 1 MB — left at the default it rejects legitimate maximum-size syncs before this service ever sees or logs them. In nginx that is `client_max_body_size 3m;`.

- **`SYNC_RESEARCH`** — off by default. Turning it on opens the `/v1/sync/contributions` and
  `/v1/sync/study` endpoints, which is what brings the openplate client's `/study` console to
  life, and makes this server hold a study graph of health-adjacent personal data.
  Read [`.env.example`](./.env.example) before you set it; it is a different undertaking from
  holding ciphertext you cannot read.

Also worth knowing: **`ADMIN_TOKEN`** is the operator's break-glass credential, and it is optional. An account with `role: "admin"` reaches `/v1/admin` with its own access token, which is what puts the console in the app rather than in a shell. With neither configured nor existing, the whole `/v1/admin` tree answers the ordinary unknown-path 404 — not a 401, which would announce that a credential exists here worth guessing.

**`SERVER_PUBLIC_URL`** and **`CLIENT_BASE_URL`** are both optional and are needed together: they build the link in an invitation and in a reset mail. With neither, the admin API returns the raw token and you paste it yourself.

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

They sign in with the **address their invitation arrived at**, and a passphrase they choose. That is the whole of what they need to remember, which is the point: they will forget a username and they will forget a password, and they know their email.

If they forget the passphrase, "forgot password" mails them a link and their diary survives. Tell them the other half too: that works because **you** hold their recovery code in escrow, so they are trusting you as well as the mathematics. If that is not a trust you want to be given, do not run an instance for anybody but yourself.

### The admin API admits to nothing it is not asked with the right credential

There is an operator API at `/v1/admin` — list accounts and invitations, read
one account's metadata, aggregate storage counts, change what an account may do
(`role`, its AI allowance, its display name), suspend and reactivate it, send it
a password-reset letter, resend an invitation, and **delete an account with
everything attached to it**. That last one is why it exists at all: an erasure
request is an obligation, and a service whose only erasure mechanism is a
hand-written `DELETE` in a SQL client is a service that will eventually get it
wrong.

**Suspending revokes every session in the same act.** A `suspended_at` on its own
would leave the phone in somebody's pocket syncing for another quarter of an
hour, which is not what an operator means by the word. Reactivating restores no
session: the person signs in again.

**An administrator cannot suspend, demote or delete their own account.** An
organization with one administrator who does that has locked everybody out of
`/v1/admin`, and the remedy is a shell on the container. The static `ADMIN_TOKEN`
is exempt, because it has no self and it is the credential that exists for
exactly that situation.

Two credentials reach it: the static `ADMIN_TOKEN`, which is yours as the
operator and keeps working when every account is locked out, and an account
whose `role` is `admin`, using its own access token. The second is what puts the
console in the app at `/admin`, behind the same sign-in as everything else.

With **neither** — no `ADMIN_TOKEN`, and the caller not an admin account — the
whole `/v1/admin` tree answers the same `404` any unknown path does, to
everybody. An instance that never configured it is indistinguishable from one
built before the feature existed. A `401` there would announce that a
credential exists and is merely locked.

Under Compose, put the value in `.env` — `docker/compose.yml` already forwards
`ADMIN_TOKEN` into the container. Compose passes only the variables that file's
`environment:` block names, so a variable you add to `.env` and nowhere else
never reaches the service. `INSTANCE_NAME`, `INSTANCE_LANGUAGE`,
`SERVER_PUBLIC_URL`, `CLIENT_BASE_URL`, `TRUST_PROXY`, `LOG_LEVEL`,
`SYNC_SHARING`, `SYNC_RESEARCH`, `DATABASE_SSL`, `SYNC_NOTICE`,
`SYNC_NOTICE_URL`, `MAIL_API_*`, `UPSTREAM_BASE_URL`, `UPSTREAM_API_KEY`,
`UPSTREAM_TIMEOUT_MS`, `AI_ADVERTISED_MODEL` and `AI_RATE_LIMIT_PER_MINUTE` are
forwarded there too. If you run your own Compose file
rather than the one in `docker/`, name each variable you rely on in its
`environment:` block.

What it can never do, by design rather than by default:

- **Read a blob.** Ciphertext is not exported through the admin surface in any
  form. A blob is reported as a byte count and a timestamp.
- **Return a verifier or a KDF descriptor.** Neither has an operational use
  that justifies putting it where a screenshot or a paste can carry it.
- **Set anyone's passphrase.** It can send a reset *letter*, which starts the
  ceremony the client performs; it cannot choose the new passphrase. The
  passphrase wraps the data key on the client, so a server-side credential
  change would produce an account that logs in and decrypts nothing.
- **Print a recovery code.** The escrow is opened by the reset ceremony, at the
  request of the person holding the letter. No admin call returns one.
- **Read a request to the AI proxy.** No admin endpoint reports what was asked
  or answered. `aiUsedToday` is a count.

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
ADMIN_TOKEN=... pnpm sync-api accounts set-role 42 admin
ADMIN_TOKEN=... pnpm sync-api accounts set-limit 42 200
ADMIN_TOKEN=... pnpm sync-api accounts suspend 42
ADMIN_TOKEN=... pnpm sync-api accounts reset-mail 42
ADMIN_TOKEN=... pnpm sync-api accounts delete 42 --yes
ADMIN_TOKEN=... pnpm sync-api invites create --email anna@example.org --daily-limit 200
ADMIN_TOKEN=... pnpm sync-api invites resend 7
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
| `src/ai/`             | The completion proxy, its quota store, the minute limiter and the scrubber.  |
| `src/mail/`           | The two letters, their strings, and the HTTP mailer that sends them.          |
| `src/lib/`            | Pure primitives: verifier, tokens, KDF descriptors, throttle.                 |
| `scripts/sync-api/`   | The `pnpm sync-api` admin CLI. HTTP only — it imports no database code.       |
| `drizzle/migrations/` | Generated migrations. Never hand-written — see `src/db/schema.ts`.            |

### Invariants

- **No `@sprqvntrs/*` or private-registry dependencies.** This repo must be buildable by anyone.
- **Four runtime dependencies**: `express`, `pg`, `dotenv` and `undici`. The last is the AI
  proxy's, and it is not a preference: Node's global `fetch` applies a 300-second header
  timeout that an `AbortSignal` can only tighten, so an operator who set
  `UPSTREAM_TIMEOUT_MS=600000` would still be cut off at 300 with an error naming no knob.
- **Handler cores stay pure and dependency-injected.** The shell owns Express, the database and the environment; the cores take a store, a clock and a token minter. That is why the auth suite tests rotation, reuse detection and revocation without a database.
- **`src/protocol.ts` is a hand-maintained duplicate** of `openplate/app/lib/sync/engine/protocol.ts`. There is no shared package and no shared CI, so both repos carry a unit test asserting the constants against _transcribed literals_. Changing the protocol means editing four places — two sources and two tests — starting with PROTOCOL.md.
- **Migrations are generated, never written.** And journal timestamps are never hand-edited: the migrator applies only migrations newer than the last applied one, so an out-of-order value causes a later migration to be silently skipped at boot.
