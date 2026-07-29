# MyScoutee Registry

A small, reusable signed deployment registry. The implemented foundation
provides:

- proof-of-possession deployment registration with Ed25519;
- zero-count `installation-test` MAU batches that never affect weight;
- signed `monthly-qmau` aggregate snapshots with linear immutable correction
  revisions, opaque evidence commitments, and six-complete-month leaderboard
  weighting;
- signed daily aggregate revenue snapshots and immutable correction revisions,
  separated by ISO-4217 settlement currency;
- registry-calculated, signed monthly technical settlement revisions with
  exact share-weighted 5% pool allocation, a bounded non-binding TTM
  valuation, and immutable pinned revenue/claim/eligibility source rows;
- a SQLite WAL append-only, hash-linked ledger;
- a compact RFC 9162 Certificate-Transparency-style Merkle Tree Hash index,
  signed tree heads, and inclusion/consistency proofs without duplicating
  ledger leaves;
- directly maintained leaderboard weight and revenue query rows, written in
  the same SQLite transaction as their authoritative ledger/source records;
- signed registration and batch receipts plus completed-UTC-day checkpoints;
- signed structured company-verification claims, append-only administrative
  review receipts, direct signed status, and short-lived single-use client
  codes for reviewed company-data reuse or virtual grouping;
- append-only, registry-signed claim eligibility suspension/reinstatement with
  a transactionally maintained current row and snapshot-pinned leaderboard
  exclusion that preserves visible measured weight;
- transactionally maintained, versioned operator-network rows used directly by
  leaderboard queries;
- signed, snapshot-bound cursor leaderboard reads;
- a registry-signed, append-only operator announcement/update-manifest feed
  published only through a local CLI;
- a registry-signed, hash-linked anomaly/case rail with same-transaction query
  rows and local flag/clear/list/show CLI commands that never mutate claim or
  accounting state;
- a registry-local signed exit-review rail that freezes completed checkpoint,
  Merkle, claim/group membership, eligibility, and settlement boundaries, with
  effective-dated buyer/auditor decisions and no payment or ownership transfer;
- fail-closed integrity verification on startup, health checks, writes, and
  checkpoint finalization.

It does not implement global-human deduplication, Firebase migration,
beneficial-owner due diligence, document upload/review, payment execution, or
a final legal payout. The QMAU protocol accepts a deployment-signed aggregate
and an opaque evidence commitment; the deployment remains responsible for
applying `qmau-v1` to its private activity evidence. Company claims have an
explicit local administrative approval boundary. The monthly technical
settlement deterministically allocates the calculated 5% pool and publishes a
clearly non-binding indicative value, but neither amount is a contractual
entitlement, invoice, transfer instruction, buyer decision, or final legal
allocation.

The registration/ledger wire and signature format is
[`docs/protocol-v1.md`](docs/protocol-v1.md). Signed claim, temporary
client-code grouping, audit, and leaderboard behavior is documented in
[`docs/operator-network-v1.md`](docs/operator-network-v1.md).
The registry-local anomaly/case audit rail is documented in
[`docs/registry-cases-v1.md`](docs/registry-cases-v1.md).
The registry-local record-date freeze and buyer/auditor decision rail is
documented in
[`docs/exit-reviews-v1.md`](docs/exit-reviews-v1.md).
The technical monthly allocation, bounded valuation, private signed history
query, and revision rules are documented in
[`docs/settlements-v1.md`](docs/settlements-v1.md).
The local publication boundary, signed pull feed, and independently
package-signed update manifest are documented in
[`docs/announcements-v1.md`](docs/announcements-v1.md).
Automated gates, the Explore production-package boundary, and the remaining
release drills are tracked in
[`docs/production-qualification.md`](docs/production-qualification.md).

## Isolated Explore/demo registry

The local Compose setup runs the real Go service with a dedicated demo
database, signing key, identity, and persistent volume. `start-demo` is
explicitly gated by `REGISTRY_DEMO_SEED=true`, a `demo:` scope, and database
and key filenames containing `demo`. It seeds through the normal signed
registration, QMAU, revenue, claim, review, client-code, and announcement
service paths. It then submits three deterministic signed revenue sources
covering the valuation windows and invokes the ordinary registry settlement
calculator. It does not insert domain fixtures with SQL.

```bash
cp .env.example .env
docker compose up --build
curl http://127.0.0.1:8081/healthz
```

The container listens on port `8080`; Compose maps host port `8081` on
`127.0.0.1` by default. Set `REGISTRY_BIND_ADDRESS` only when an intentional
TLS/reverse-proxy topology requires another host bind.
The health endpoint is `GET /healthz`. Another Compose service should use
`http://registry:8080`; a host-side Java test should use
`http://127.0.0.1:8081`.

The baseline has four genuine signed deployments, six complete QMAU months
for each deployment, a two-deployment approved operator group created through
a temporary client code, one pending claim, one unclaimed deployment, daily
revenue, a completed-day checkpoint, two signed announcements, and a matching
Merkle index. It also has an immutable June 2026 USD settlement with non-zero
earlier/prior/recent three-month averages, acceleration, a 5% allocation, and
the non-binding TTM value. Seeding is resumable and idempotent after
interruption. Once the baseline is marked complete, later interactive demo
writes are preserved on restart. On each guarded `start-demo`, the service
also appends only the missing QMAU snapshots needed to keep all four
deterministic deployments populated through the latest six complete UTC
months. An older completed demo volume receives the settlement once through
the same signed service/calculation paths. Existing snapshots, claims,
announcements, settlements, and interactive records are not re-created or
read back through a browser database.

A server-backed Explore workspace may run the same optimized image internally
with no host port, `command: ["start-demo"]`, and its own demo volume. Browser
local data is only an offline fallback. A real central registry is a separate
deployment using ordinary startup (no command and
`REGISTRY_DEMO_SEED=false`), a non-demo scope, and a different
database/key/volume. It is never seeded. The production package uses the same
stripped, non-root, scratch-based registry image for Explore, tagged
`myscoutee-registry:<version>-prod`; only its guarded command, demo identity,
and isolated volumes differ from an ordinary registry deployment.

An ordinary empty central registry returns health JSON shaped like:

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
| `POST` | `/v1/revenue/batches` | `201` appended daily aggregate, `200` idempotent duplicate |
| `GET` | `/v1/revenue/batches/{revbatch_id}/receipt` | Stored signed revenue receipt |
| `POST` | `/v1/settlements/query` | Deployment-signed private history for that deployment's exact historical beneficiary memberships |
| `GET` | `/v1/ledger/checkpoints/{YYYY-MM-DD}` | Completed UTC day checkpoint |
| `GET` | `/v1/ledger/merkle/inclusion/{tree_size}/{ledger_index}` | Registry-signed RFC 9162-style inclusion proof |
| `GET` | `/v1/ledger/merkle/consistency/{old_tree_size}/{new_tree_size}` | Registry-signed RFC 9162-style append-only consistency proof |
| `POST` | `/v1/operator/actions` | Signed claim, client-token/group-link, or deployment-state action |
| `GET` | `/v1/operator/claims/{deployment_id}` | Direct registry-signed company-verification status |
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

## Company-verification review CLI

Structured claims are accepted as `PENDING_REVIEW` and immediately retain or
create their operator group and provisional leaderboard membership. The
private registered address/contact is kept out of the public operator ledger,
status, and leaderboard. It is stored in an access-limited append-only table
linked to the public payload digest. Every company field, including the
absolute HTTPS website, is required. A deployment whose own current claim is
approved and remains in that claim's group may issue a short-lived, single-use
client code; redeeming it on an unclaimed deployment creates another
independently reviewable `PENDING_REVIEW` claim
without asking the operator to re-enter the approved company data.

The operational CLI requires the configured database, signing key, and
registry identity to already exist. A missing or mistyped Compose volume fails
without creating a directory, database, key, or identity.

```bash
docker compose exec -T registry \
  /registry list-operator-claims \
  --status PENDING_REVIEW \
  --limit 50

# WARNING: this prints the private address and verification contact.
docker compose exec -T registry \
  /registry show-operator-claim \
  --deployment-id dep_0123456789abcdef0123456789abcdef

docker compose exec -T registry \
  /registry approve-operator-claim \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --claim-action-id opa_0123456789abcdef0123456789abcdef \
  --group-id opg_0123456789abcdef0123456789abcdef \
  --legal-name 'Example Cooperative' \
  --reviewer-id network-review-team \
  --review-reference case:2026-0042 \
  --idempotency-key approve-example-2026-0042

docker compose exec -T registry \
  /registry suspend-operator-claim \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --claim-action-id opa_0123456789abcdef0123456789abcdef \
  --group-id opg_0123456789abcdef0123456789abcdef \
  --legal-name 'Example Cooperative' \
  --actor-id network-eligibility-team \
  --decision-reference case:2026-eligibility-0042 \
  --reason-code policy-hold \
  --idempotency-key suspend-example-2026-0042

docker compose exec -T registry \
  /registry leaderboard --view claimed --limit 20

docker compose exec -T registry \
  /registry revenue --period 2026-07-27 --currency EUR

docker compose exec -T registry \
  /registry revenue --period 2026-07-27 --currency EUR \
  --deployment-id dep_0123456789abcdef0123456789abcdef

docker compose exec -T registry \
  /registry revenue --period 2026-07-27 --currency EUR \
  --group-id opg_0123456789abcdef0123456789abcdef

docker compose exec -T registry \
  /registry calculate-settlement --period 2026-06 --currency EUR

docker compose exec -T registry \
  /registry settlements --period 2026-06 --currency EUR --limit 20

docker compose exec -T registry \
  /registry settlements \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --currency EUR --limit 20

docker compose exec -T registry \
  /registry merkle-proof --ledger-index 1

docker compose exec -T registry \
  /registry merkle-consistency --old-tree-size 32 --new-tree-size 64
```

Commands emit JSON. An exact approval retry exits `0` with `duplicate: true`;
an idempotency conflict or a withdrawn/superseded claim target exits `1`.
`reviewer-id` and `review-reference` are required registry audit fields. Local
CLI access is the review authority; the registry signature binds what it
recorded but is not a separate human signature. Cursors and
`next_deployment_id` values are opaque and must be copied unchanged.

The raw revenue command reads the already-initialized local registry database
and has no HTTP query endpoint. It reports one settlement currency at a time,
performs no foreign-exchange conversion, and keeps
`network_commission_pool_minor` equal to the global day/currency pool even
when the other totals are filtered to one deployment or current claimed
group. `reported_estimated_commission_minor` remains the sum of the selected
rows' individually rounded estimates. The global pool is
`floor(SUM(active commission_basis_minor) * 500 / 10000)`; it is not the sum
of per-deployment rounded estimates and is not a payout instruction.

`calculate-settlement` accepts only a completed UTC month and one currency. It
appends a new immutable signed revision only when the pinned source boundary
or exact source fingerprint changed. `settlements` is a local administrative
query and can expose every beneficiary amount. The HTTP settlement-history
endpoint is different: it requires a current registered deployment signature
and returns only allocations whose immutable historical membership table
contains that deployment. It is not linked from the public leaderboard and
does not expose raw revenue rows.

The complete list/show/approve flow, JSON examples, signed status receipt,
cursor examples, exit codes, privacy/backup handling, and stale-target
behavior are in
[`docs/operator-network-v1.md`](docs/operator-network-v1.md).

## Registry anomaly/case CLI

Registry administrators can attach an auditable anomaly case to an existing
deployment, claim action, operator group, QMAU batch, revenue batch, or ledger
index. A case stores bounded references and SHA-256 evidence digests only; it
does not store evidence bodies, personal review data, or remote credentials.
Flagging or clearing a case never changes claim approval, measured MAU,
revenue, leaderboard share, or legal eligibility.

The CLI opens only the configured existing SQLite database and signing key. It
appends a registry-signed hash-chain event and updates the directly queried
case row in one transaction:

```bash
docker compose exec -T registry \
  /registry flag-registry-case \
  --subject-type deployment \
  --subject-id dep_0123456789abcdef0123456789abcdef \
  --category qmau-anomaly \
  --severity warning \
  --evidence-hash sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --reference review:2026-0042 \
  --actor-id network-review-team \
  --idempotency-key flag-review-2026-0042

docker compose exec -T registry \
  /registry list-registry-cases --status OPEN --limit 50

docker compose exec -T registry \
  /registry show-registry-case \
  --case-id case_0123456789abcdef0123456789abcdef

docker compose exec -T registry \
  /registry clear-registry-case \
  --case-id case_0123456789abcdef0123456789abcdef \
  --reference resolution:2026-0042 \
  --actor-id network-review-team \
  --idempotency-key clear-review-2026-0042
```

Omit `--evidence-hash` only when no governed evidence artifact exists; the
signed event then commits to the protocol zero hash. Never put names, e-mail
addresses, document contents, or secrets in `reference`, `actor-id`, or any
identifier field. The full signed format and pagination semantics are in
[`docs/registry-cases-v1.md`](docs/registry-cases-v1.md).

## Exit-review CLI

An exit record freezes one exact approved claim generation at a completed UTC
checkpoint. It commits to the ledger/Merkle prefix, operator audit/review/
eligibility heads, every eligible deployment in the exact group, and the
latest settlement revision for each period/currency at that boundary.
Subsequent `verify`, `reject`, `dispute`, and `withdraw` decisions are
effective-dated, registry-signed immutable events.

```bash
docker compose exec -T registry \
  /registry freeze-exit-review \
  --record-date 2026-07-28 \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --claim-action-id opa_0123456789abcdef0123456789abcdef \
  --group-id opg_0123456789abcdef0123456789abcdef \
  --actor-role auditor \
  --actor-id exit-audit-team \
  --reference exit:2026-0042 \
  --idempotency-key freeze-exit-2026-0042

docker compose exec -T registry \
  /registry list-exit-reviews --status review-pending --limit 50

docker compose exec -T registry \
  /registry decide-exit-review \
  --review-id exr_0123456789abcdef0123456789abcdef \
  --decision verify \
  --effective-date 2026-07-29 \
  --actor-role buyer \
  --actor-id acquisition-audit \
  --reference acquisition:2026-0042 \
  --idempotency-key verify-exit-2026-0042
```

This rail neither transfers ownership nor executes or authorizes a payment.
Only bounded non-personal actor/reference fields and SHA-256 evidence
commitments are stored. Full command, transition, pagination, privacy, and
verification rules are in
[`docs/exit-reviews-v1.md`](docs/exit-reviews-v1.md).

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `REGISTRY_LISTEN_ADDR` | `:8080` | HTTP bind address |
| `REGISTRY_SCOPE` | _required_ | Explicit immutable signed namespace |
| `REGISTRY_DATABASE_PATH` | `/data/registry.db` | SQLite database |
| `REGISTRY_SIGNING_KEY_PATH` | `/data/registry-signing-key.pem` | PKCS#8 Ed25519 PEM |
| `REGISTRY_GENERATE_SIGNING_KEY` | `true` | Allow key creation only for a pristine first start |
| `REGISTRY_DEMO_SEED` | `false` | Guard accepted only with the explicit `start-demo` command |
| `REGISTRY_TIMESTAMP_SKEW` | `5m` | Signed-request clock window |
| `REGISTRY_MAX_REQUEST_BODY_BYTES` | `65536` | JSON body limit, 1 KiB-1 MiB |
| `REGISTRY_VALUATION_MULTIPLIER_BASIS_POINTS` | `30000` | Technical TTM valuation base multiplier (30000 = 3x), bounded to 1000-100000 |
| `REGISTRY_CHECKPOINT_INTERVAL` | `1m` | Background completed-day finalization |
| `REGISTRY_SHUTDOWN_TIMEOUT` | `10s` | HTTP graceful shutdown timeout |
| `REGISTRY_HEALTHCHECK_URL` | `http://127.0.0.1:8080/healthz` | Binary healthcheck target |

`compose.yaml` supplies the isolated demo scope and paths. An ordinary central
registry intentionally has no scope default and must never set the demo guard.

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
leaderboard query rows, operator audit events, private claim submissions,
claim reviews, claim eligibility decisions, versioned operator-network rows,
announcements, registry case
events, and checkpoints.

The authoritative accounting ledger remains a linear SHA-256 hash chain: each
entry commits to its canonical contents and the previous entry hash. In the
same append transaction, the registry stores only the newly completed internal
nodes of an RFC 9162 Certificate-Transparency-style Merkle Tree Hash index.
Ledger hashes are the leaves and are not duplicated in the Merkle table. For
`n` ledger entries it stores exactly `n - popcount(n)` internal nodes (fewer
than one stored node per entry), performs one leaf hash plus an amortized one
parent hash per append, and produces `O(log n)` inclusion and consistency
proofs. Registry-signed tree heads bind the scope, registry key, tree size,
root, and generation time. The existing linear chain and signed daily
checkpoints remain authoritative and independently verified.

The complete operational state and Merkle index are audited at bootstrap,
health checks, checkpoint finalization, and explicit verification commands.
That successful audit establishes the immutable trusted prefix. Ordinary reads
and writes compare SQLite's connection-local `data_version`, an `O(1)`
operation. While it is unchanged, all commits came through the serialized,
transactionally checked Store methods. When another connection (normally the
local CLI) commits, the next request verifies the configured identity,
required append-only triggers, cryptographic chain heads and predecessors,
source/query boundary rows, signatures, and only the newly completed Merkle
frontier before trusting the new revision. That boundary work is constant
except for the `O(log n)` Merkle frontier. A failed complete audit latches the
service fail-closed until a later complete audit succeeds.

Generated inclusion and consistency proofs are also verified in-process before
they are returned. Ordinary append and read paths therefore do not rebuild the
ledger, receipt, operator, announcement, or Merkle history.

`ledger_weight_rows`, `revenue_query_rows`, and the settlement source/allocation
tables are not asynchronous projections and are never repaired from the
ledger. An installation-test acceptance writes
its authoritative ledger entry and exact weight row in one transaction. A
revenue acceptance writes its ledger entry, immutable source batch, and one
exact query row per reported currency in one transaction; an explicit
zero-revenue snapshot deliberately has no currency row. If any required insert
fails, none is committed. Integrity verification rejects missing, extra, or
mismatched source/query rows. A settlement calculation likewise appends its
registry-owned ledger/Merkle event and every pinned revenue, TTM, weight,
historical membership, and exact allocation row in one transaction.

On every restart and health check, the registry validates:

- the central key/scope identity;
- deployment public-key fingerprints, original request proofs, payload hashes,
  and central registration receipts;
- installation/QMAU request proofs, commitments, immutable linear QMAU
  revision links, batch-to-ledger fields, direct weight rows, ledger hashes,
  receipt signatures, idempotency links, and initial nonce links;
- revenue request proofs, canonical currency aggregates, immutable revision
  links, direct query rows, ledger entries, receipts, nonces, idempotency
  links, and bounded active aggregates;
- settlement revision links, registry receipt signatures, all four pinned
  source-chain boundaries, exact revenue/TTM/weight/historical-membership
  inputs, valuation arithmetic, largest-remainder conservation, allocation
  hashes, direct rows, and the registry-owned ledger/Merkle append;
- ledger index/hash/timestamp monotonicity, every compact Merkle internal node,
  and the full checkpoint chain;
- exact ledger/query-row cardinality and field equality;
- the operator action hash chain, deployment signatures, replay/idempotency
  records, registry-signed action receipts, private claim-record hashes,
  signed review and eligibility chains, direct claim status/current
  eligibility, and versioned operator-network query rows;
- the announcement hash chain, normalized nested-content hashes, publication
  idempotency hashes, registry signatures, and stored canonical JSON.
- frozen exit-review checkpoint/Merkle/operator/settlement boundaries, exact
  historical group membership, global and per-review signed event chains,
  transition rules, and one same-transaction query row per event.

Registration, MAU/revenue batch, operator-action, announcement-publication,
and signed read-model operations fail closed when their operational integrity
verification fails. Full Merkle failures additionally fail startup, health,
checkpoint finalization, proof verification, and explicit audit commands.
New ledger timestamps cannot precede registry creation, the current ledger
head, or an already finalized day.

Protocol v1 does not define recovery aliasing for a lost local installation
idempotency key: that key is included in the commitment and therefore in the
signed batch hash. A distinct valid key can create another zero-count test
record, but installation tests never contribute to accounting or weight.
Deploy the service behind TLS, request-rate limits, connection limits, and
per-source/per-deployment abuse controls; durable nonces intentionally grow to
preserve replay protection.

No raw verification-contact email/address is placed in the public operator
ledger or leaderboard. Those claim fields are accepted only into the protected
private append-only submission table. Firebase UID, access token, chat,
payment detail, and unrelated direct user identifiers are not accepted by the
registry protocol.

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
integrity behavior. Operator tests additionally cover structured validation,
private/public separation, review idempotency and stale targets, direct
status, CLI preflight, and review/status tampering. Announcement tests
additionally cover strict manifest validation, registry/package signature
formats, expiry/filtering,
snapshot-bound cursor traversal and tampering, append-only publication,
live-volume CLI publication, and restart persistence.
Revenue tests additionally cover real deployment signatures, immutable
receipts, exact idempotent retries, correction chains, stale-correction
rejection, explicit zero-revenue days, deterministic currency validation, and
aggregate-level commission rounding.
