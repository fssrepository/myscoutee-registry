# MyScoutee Registry

A small, reusable signed deployment registry. The implemented foundation
provides:

- proof-of-possession deployment registration with Ed25519;
- one accepted record kind: a zero-count `installation-test` MAU batch;
- a SQLite WAL append-only, hash-linked ledger;
- a directly maintained leaderboard query row for every ledger entry, written
  in the same SQLite transaction;
- signed registration and batch receipts plus completed-UTC-day checkpoints;
- signed, append-only operator claim/grouping actions with expiring client
  tokens;
- signed, snapshot-bound cursor leaderboard reads;
- a registry-signed, append-only operator announcement/update-manifest feed
  published only through a local CLI;
- fail-closed integrity verification on startup, health checks, writes, and
  checkpoint finalization.

It does not yet implement global user deduplication, production MAU
qualification, Firebase migration, or legal/buyer validation of operator
claims. With protocol-v1 accepting only zero-count installation tests, a real
registry's measured deployment weights remain zero until the production MAU
ruleset is introduced.

The registration/ledger wire and signature format is
[`docs/protocol-v1.md`](docs/protocol-v1.md). Signed claim, temporary
client-code grouping, audit, and leaderboard behavior is documented in
[`docs/operator-network-v1.md`](docs/operator-network-v1.md).
The local publication boundary, signed pull feed, and independently
package-signed update manifest are documented in
[`docs/announcements-v1.md`](docs/announcements-v1.md).

## Local development quick start

The local Compose setup creates a persistent volume, atomically creates the
central Ed25519 key only on the first pristine start, and runs as numeric
non-root UID/GID `65532`. A registry scope must be chosen explicitly:

```bash
cp .env.example .env
# Edit REGISTRY_SCOPE in .env for this independently governed instance.
docker compose up --build
curl http://127.0.0.1:8081/healthz
```

The container listens on port `8080`; Compose maps host port `8081` on
`127.0.0.1` by default. Set `REGISTRY_BIND_ADDRESS` only when an intentional
TLS/reverse-proxy topology requires another host bind.
The health endpoint is `GET /healthz`. Another Compose service should use
`http://registry:8080`; a host-side Java test should use
`http://127.0.0.1:8081`.

This loopback HTTP mapping is for local development. Production uses the
separate TLS edge described below.

An empty registry returns health JSON shaped like:

```json
{
  "status": "ok",
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "registry_key_id": "rkey_...",
  "ledger_index": 0,
  "entry_count": 0,
  "ledger_head_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
}
```

## Sovereign parent domains

`REGISTRY_SCOPE` is mandatory protocol domain separation and is signed into
requests, central receipts, ledger entries, and checkpoints. It is persisted
with the central identity, so changing it against an existing database fails
startup.

There are no hard-coded scope choices and no default parent. The infrastructure
owner chooses a value such as `example:region-a`. Independently governed scopes
run as independent deployments with different direct public endpoints,
databases, volumes, signing keys, and backups. A deployment selects exactly one
endpoint and scope. There is no forwarding, relay, replication, or fallback
across a scope boundary.

The generic scope format (`organization:domain` is a useful convention) keeps
the registry reusable beyond MyScoutee infrastructure.

An installed application begins fully uninitialized: no deployment key, no
pinned registry selection, and no automatic registry traffic. Before
initialization, only an explicitly operator-requested, read-only identity
preflight is permitted. A future authenticated Java operator API owns the
normal workflow:

1. the operator prepares a candidate registry URL and expected scope;
2. Java fetches and verifies that endpoint's self-signed
   `/v1/registry/identity`; the browser displays the scope while Java retains
   and pins the cryptographic identity;
3. the operator explicitly confirms that exact endpoint/scope/key identity;
4. Java invokes a narrow host-persistence boundary to generate and store the
   deployment key, returning only its public fingerprint to the browser;
5. Java submits the signed, idempotent registration and installation test
   directly to that one registry and durably stores the signed results.

This is not distributed two-phase commit. Before confirmation the preflight is
read-only and nothing is written centrally or initialized locally. After
confirmation each central request is one atomic, idempotent SQLite transaction,
and its signed result is persisted locally.
A packaged shell identity utility, where present in the application
distribution, is a development/recovery/E2E fallback—not the browser or normal
operator workflow.

## Production TLS deployment

Production runs the Go registry and its own Nginx reverse proxy on the
registry server using [`compose.production.yaml`](compose.production.yaml).
This is separate from any application-deployment Nginx. The registry container
is attached only to an internal Docker network, declares port `8080` for
service discovery, and has no host-published port. Nginx joins that backend
network and a separate edge bridge; Nginx alone publishes HTTP and HTTPS. HTTP
redirects to the configured HTTPS hostname and port.

No production certificate or TLS private key is generated, copied into the
image, or stored in this repository. The registry operator supplies a
certificate chain and matching private key as protected host files:

```bash
sudo install -d -m 0700 /opt/myscoutee-registry/tls
sudo install -o root -g root -m 0600 /secure/source/fullchain.pem \
  /opt/myscoutee-registry/tls/fullchain.pem
sudo install -o root -g root -m 0600 /secure/source/privkey.pem \
  /opt/myscoutee-registry/tls/privkey.pem

sudo install -m 0600 .env.production.example \
  /etc/myscoutee-registry.env
sudoedit /etc/myscoutee-registry.env
```

Set a real `REGISTRY_SCOPE`, DNS-only `REGISTRY_PUBLIC_HOSTNAME`, deliberate
public bind address, and absolute certificate/key paths. The hostname must be
covered by the certificate. Then validate the fully resolved Compose model
before starting it:

```bash
docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml config --quiet

docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml up --build -d

docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml ps

curl --fail --show-error \
  https://registry.example.invalid/v1/registry/identity
```

The TLS files must be owned by host UID/GID `0:0` and mode `0600`. Nginx's
capability-reduced root master can read such bind mounts and then drops worker
privileges; it intentionally cannot bypass discretionary access controls on a
mode-`0600` key owned by another host UID. `docker compose config` validates
interpolation and structure but cannot prove file readability or that the
certificate matches the key, so require both services to become healthy and
inspect `docker compose logs nginx` on first start or after renewal.

Allow the chosen HTTP/HTTPS ports through the host firewall only where
intended. `REGISTRY_PUBLIC_BIND_ADDRESS=0.0.0.0` publishes on all IPv4
interfaces; use a specific host address when the edge must be restricted.
Custom public ports are supported, and the HTTP redirect uses the configured
HTTPS port.

Nginx accepts TLS 1.2/1.3, applies HSTS, a bounded body size, per-address
request/connection limits, and bounded client/proxy timeouts. It overwrites
forwarded client headers at the public trust boundary. Its `proxy_pass` has no
URI component and performs no rewrite, so the original path and query reach
Go unchanged; Go remains responsible for rejecting queries and non-canonical
encoded aliases on signed endpoints. Keep `REGISTRY_EDGE_MAX_BODY_SIZE` no
larger than `REGISTRY_MAX_REQUEST_BODY_BYTES` unless both limits are changed
deliberately.

Both services are read-only apart from bounded tmpfs mounts and the registry's
persistent `/data` volume. The registry drops every capability and runs as UID
`65532`. Nginx listens on unprivileged container ports and drops every
capability except `CHOWN`, `SETGID`, and `SETUID`, which its root master needs
to initialize writable tmpfs paths and drop worker privileges. Both services
enable `no-new-privileges` and have health checks; Nginx starts only after the
registry reports healthy.

Certificate renewal is an operator-owned process. Replace the two protected
host files as a matching pair, then recreate or reload Nginx and verify its
health and public certificate. Never commit certificate material or production
environment files.

For a provisioned central signing key, use the existing overlay with the same
production environment file:

```bash
docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml \
  -f compose.provisioned-key.yaml \
  run --rm --build registry initialize

docker compose \
  --env-file /etc/myscoutee-registry.env \
  -f compose.production.yaml \
  -f compose.provisioned-key.yaml \
  up -d
```

Set `REGISTRY_PROVISIONED_KEY_PATH` in the protected environment file and
follow the signing-key lifecycle rules below.

## API

| Method | Path | Result |
| --- | --- | --- |
| `GET` | `/v1/registry/identity` | Read-only, self-signed registry identity preflight |
| `POST` | `/v1/deployments/register` | `201` new, `200` signed duplicate |
| `POST` | `/v1/mau/batches` | `201` appended, `200` idempotent duplicate |
| `GET` | `/v1/mau/batches/{batch_id}/receipt` | Stored signed receipt |
| `GET` | `/v1/ledger/checkpoints/{YYYY-MM-DD}` | Completed UTC day checkpoint |
| `POST` | `/v1/operator/actions` | Signed claim, client-token/group-link, or deployment-state action |
| `GET` | `/v1/leaderboard?view=founder\|claimed\|unclaimed` | Signed snapshot-bound cursor page |
| `GET` | `/v1/leaderboard/groups/{group_id}/deployments` | Cursor page of the deployments kept separate inside one virtual operator group |
| `GET` | `/v1/announcements` | Registry-signed, snapshot-bound cursor feed of active operator notices and update manifests |
| `GET` | `/healthz` | Storage and full integrity status |

Errors are JSON:

```json
{"error":{"code":"invalid_signature","message":"..."}}
```

Signed mutation endpoints reject query strings, and every endpoint rejects
percent-encoded path aliases. The unsigned leaderboard GET endpoints accept
only their documented, single-occurrence query parameters; the announcement GET
does the same for its documented filters. Both read models return
registry-signed snapshots and opaque cursors. JSON is size-bounded, valid
UTF-8, exactly one value, free of duplicate/unknown fields, and served only as
`application/json` (optional charset must be UTF-8). Protocol timestamps must
be RFC 3339 UTC values ending in `Z`.

The identity preflight is stable and creates no ledger entry. Clients verify
its Ed25519 self-signature and deterministic key ID before asking an operator
to pin the endpoint, scope, and key. It fails closed if full registry integrity
verification fails.

## Local announcement publication

There is no HTTP publish API and production starts with no fake announcement.
After reviewing a strict JSON file, a registry administrator can append it
while the server is running:

```bash
cd /home/raxim/workspace/myscoutee-backend/server
docker compose -f docker-compose-dev.yml exec -T registry \
  /registry publish-announcement --file - \
  < ../../myscoutee-registry/examples/announcement-general.json

curl --fail --show-error \
  'http://127.0.0.1:8081/v1/announcements?limit=20'
```

`/registry publish-announcement --help` documents file and stdin usage. The
command returns the complete signed entry and whether the caller-chosen
`publication_id` was an idempotent duplicate. Update the template's URLs,
timestamps, digests, deterministic `pkey_...` package key ID, and detached
package signature before use. Revocation and supersession are later append-only
announcements, never an edit of a published row. Production permissions/backup
guidance and exact application-development, restart-persistence, and optional
demo-volume reset commands are in
[`docs/announcements-v1.md`](docs/announcements-v1.md).

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `REGISTRY_LISTEN_ADDR` | `:8080` | HTTP bind address |
| `REGISTRY_SCOPE` | _required_ | Explicit immutable signed namespace |
| `REGISTRY_DATABASE_PATH` | `/data/registry.db` | SQLite database |
| `REGISTRY_SIGNING_KEY_PATH` | `/data/registry-signing-key.pem` | PKCS#8 Ed25519 PEM |
| `REGISTRY_GENERATE_SIGNING_KEY` | `true` | Allow key creation only for a pristine first start |
| `REGISTRY_TIMESTAMP_SKEW` | `5m` | Signed-request clock window |
| `REGISTRY_MAX_REQUEST_BODY_BYTES` | `65536` | JSON body limit, 1 KiB-1 MiB |
| `REGISTRY_CHECKPOINT_INTERVAL` | `1m` | Background completed-day finalization |
| `REGISTRY_SHUTDOWN_TIMEOUT` | `10s` | HTTP graceful shutdown timeout |
| `REGISTRY_HEALTHCHECK_URL` | `http://127.0.0.1:8080/healthz` | Binary healthcheck target |

Copy `.env.example` to `.env` and replace its example scope before starting
Compose; the service intentionally has no scope default.

## Central signing key lifecycle

The generated key is written as one mode-`0600` PKCS#8 PEM file, synced,
published without overwrite, and followed by a mandatory parent-directory
sync. The registry rejects symlinks, non-regular files, group/other-readable
keys, replacement during open, missing keys for non-pristine databases, and a
key whose public identity differs from SQLite.

The auto-generation mode also refuses an existing key with a pristine database.
That ambiguous state could indicate database loss under a still-trusted key.
Restore the database rather than silently starting a new ledger.

For a deliberately provisioned first-run key:

```bash
REGISTRY_KEY_DIR="$(mktemp -d)"
chmod 700 "$REGISTRY_KEY_DIR"
openssl genpkey -algorithm ED25519 \
  -out "$REGISTRY_KEY_DIR/registry-signing-key.pem"
chmod 600 "$REGISTRY_KEY_DIR/registry-signing-key.pem"
sudo chown 65532:65532 "$REGISTRY_KEY_DIR/registry-signing-key.pem"
export REGISTRY_PROVISIONED_KEY_PATH="$REGISTRY_KEY_DIR/registry-signing-key.pem"
docker compose -f compose.yaml -f compose.provisioned-key.yaml \
  run --rm --build registry initialize
docker compose -f compose.yaml -f compose.provisioned-key.yaml up
```

Private-key extensions are excluded from the Docker build context as a
defense-in-depth measure; still keep production keys outside this repository.
The temporary directory above is convenient for local integration. Use durable
access-controlled secret storage for production.

`REGISTRY_GENERATE_SIGNING_KEY=false` prevents generation but does not
authorize ordinary startup to pair an existing key with a pristine database.
Only the explicit one-shot `initialize` command may create that first identity
row. Subsequent `up` starts verify the persisted identity. If `/data` is lost
while the external key remains, ordinary startup fails instead of silently
resetting the ledger under the trusted key.

Back up the database and signing key as one recovery unit. Stop/quiesce the
service before a raw filesystem copy. For an online backup, use SQLite's online
backup API or a storage-level atomic snapshot; copying a changing database,
WAL, and SHM one after another is not a consistent backup. Restore the database
and matching key together. Never restore one sovereign scope's key or database
into the other scope.

## Integrity and operational boundary

SQLite uses WAL, foreign keys, `synchronous=FULL`, one serialized connection,
and append-only `UPDATE`/`DELETE` rejection triggers for identity,
deployments, nonces, idempotency records, ledger entries, batches,
leaderboard query rows, operator audit events, announcements, and checkpoints.

The accounting ledger is a linear SHA-256 hash chain, not a Merkle tree. Each
entry commits to its canonical contents and the previous entry hash. Signed,
hash-linked daily checkpoints commit to the completed-day ledger head. This
provides full replay/tamper verification; it does not claim Merkle inclusion
proofs.

`ledger_weight_rows` is not a projection and is never rebuilt asynchronously.
Accepting a batch performs two related inserts in one transaction: the
authoritative ledger entry and its exact query-friendly weight row. If either
insert fails, neither is committed. Integrity verification requires exactly
one matching query row per ledger entry and rejects missing, extra, or
mismatched rows.

On every restart and health check, the registry validates:

- the central key/scope identity;
- deployment public-key fingerprints, original request proofs, payload hashes,
  and central registration receipts;
- MAU request proofs, commitments, batch-to-ledger fields, ledger hashes,
  receipt signatures, idempotency links, and initial nonce links;
- ledger index/hash/timestamp monotonicity and the full checkpoint chain;
- exact ledger/query-row cardinality and field equality;
- the operator action hash chain, deployment signatures, replay/idempotency
  records, and registry-signed action receipts.
- the announcement hash chain, normalized nested-content hashes, publication
  idempotency hashes, registry signatures, and stored canonical JSON.

Registration, batch, operator-action, announcement-publication, and signed
read-model operations fail closed when this verification fails. New ledger
timestamps cannot precede registry creation, the current ledger head, or an
already finalized day.

Protocol v1 does not define recovery aliasing for a lost local installation
idempotency key: that key is included in the commitment and therefore in the
signed batch hash. A distinct valid key can create another zero-count test
record, but installation tests never contribute to accounting or weight.
Deploy the service behind TLS, request-rate limits, connection limits, and
per-source/per-deployment abuse controls; durable nonces intentionally grow to
preserve replay protection.

No raw email, Firebase UID, access token, profile, chat, location, payment
detail, or other direct user identifier is accepted.

## Development

The code targets Go 1.25 and uses the CGo-free `modernc.org/sqlite` driver.

```bash
go test ./...
go build ./cmd/registry
docker build -t myscoutee-registry:1.0.0-dev .
```

Tests use real temporary SQLite databases and real HTTP/Ed25519 flows. They
cover registration, duplicates, replay and idempotency conflicts, invalid
signatures, strict decoding, sovereign scope rejection, ledger/receipt
verification, clock rollback safeguards, completed-day checkpoints,
append-only triggers, key restart/loss/replacement guards, and fail-closed
integrity behavior. Announcement tests additionally cover strict manifest
validation, registry/package signature formats, expiry/filtering,
snapshot-bound cursor traversal and tampering, append-only publication,
live-volume CLI publication, and restart persistence.
