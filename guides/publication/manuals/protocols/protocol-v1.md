# MyScoutee Registry Protocol v1

This document fixes the wire and signature format for deployment registration,
the non-accounting installation test, production aggregate qualified-monthly-
active-user (QMAU) snapshots/corrections, aggregate daily revenue
snapshots/corrections, signed receipts, daily checkpoints, and RFC 9162-style
Merkle proofs. The registry-owned monthly allocation and private signed
deployment-history extension is specified in
[`settlements-v1.md`](settlements-v1.md). Privacy-preserving optional
cross-deployment identity linking and globally deduplicated QMAU are specified
in [`global-identity-v1.md`](global-identity-v1.md).

## Encoding rules

- HTTP JSON is UTF-8 with `Content-Type: application/json`.
- Protocol version is the JSON string `"1"`.
- Timestamps are RFC 3339 UTC timestamps ending in the literal `Z`.
- Installation-test and QMAU periods use `YYYY-MM`.
- Revenue periods use an original payment UTC day in `YYYY-MM-DD`.
- Checkpoint dates use `YYYY-MM-DD` in UTC.
- Binary values use standard padded RFC 4648 base64.
- SHA-256 values use `sha256:` followed by 64 lowercase hexadecimal digits.
- Deployment IDs are `dep_` followed by exactly 32 lowercase hexadecimal
  characters.
- Batch IDs are `batch_` followed by exactly 32 lowercase hexadecimal
  characters.
- Revenue batch IDs are `revbatch_` followed by exactly 32 lowercase
  hexadecimal characters.
- Canonical values must not contain CR or LF.
- Every canonical message is its listed fields joined with LF (`\n`) and has
  one final LF.
- Signatures are Ed25519 signatures over the canonical message bytes, not over
  incidental JSON serialization.
- Public keys are X.509 SubjectPublicKeyInfo DER values containing an Ed25519
  public key.

The fingerprint of a public key is:

```text
sha256:<lowercase SHA-256 hex of the complete SPKI DER value>
```

A registry signing key ID is deterministic:

```text
rkey_<first 32 hexadecimal characters of the public-key fingerprint digest>
```

The all-zero chain hash is:

```text
sha256:0000000000000000000000000000000000000000000000000000000000000000
```

## Sovereign registry scope

Every registry instance has one mandatory, immutable `registry_scope`. There
are no built-in product, geography, or parent modes and there is no default.
The infrastructure owner chooses an explicit deployment-specific value, for
example:

```text
example:region-a
```

Different scope values are separate sovereign namespaces. Deployments choose
one registry and communicate with it directly. Registry servers do not
forward, relay, or synchronize signed requests across a scope boundary.
Operators use separate databases, signing keys, volumes, backups, and public
endpoints for independently governed scopes.

Scope values are 3-128 characters, begin with a lowercase ASCII letter or
digit, and otherwise contain only lowercase ASCII letters, digits, `.`, `:`,
`_`, or `-`. The scope is persisted with the registry identity and cannot be
changed for an existing database. It is included in every signature and hash
listed below, preventing a request, receipt, ledger entry, or checkpoint for
one parent domain from being accepted as belonging to another.

## Registry identity preflight

Before an operator confirms enrollment, a deployment can inspect the
registry's immutable public identity without creating any central state:

```text
GET /v1/registry/identity
```

The response is:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "signature": "<base64 Ed25519 signature>"
}
```

The registry identity signature input is:

```text
myscoutee-registry-identity-v1
<protocol_version>
<registry_scope>
<registry_key_id>
<registry_public_key>
```

The response is self-signed by `registry_public_key`. A client must verify that
the public key parses as Ed25519, that `registry_key_id` is derived from its
complete SPKI DER value as specified above, and that `signature` verifies over
the canonical message before displaying or pinning the identity. This proves
the endpoint controls the advertised key; the operator must still compare and
explicitly approve the intended endpoint, scope, and key ID.

The endpoint is read-only, rejects query strings and percent-encoded path
aliases, and appends no ledger record. It fails closed when full registry
integrity verification fails.

## Generic signed request

The request signature input is:

```text
myscoutee-registry-request-v1
<uppercase HTTP method>
<request path>
<protocol_version>
<registry_scope>
<signer>
<timestamp>
<nonce>
<idempotency_key>
<payload_hash>
```

For registration, `signer` is the submitted public-key fingerprint. For a batch,
it is the assigned deployment ID.

The default accepted timestamp skew is five minutes. Nonces and idempotency keys
are printable ASCII tokens between 8 and 128 characters.

Idempotency behavior is:

1. The signature and timestamp are always validated first.
2. Repeating the same signer/idempotency key with the same payload hash returns
   the original stored result and does not append another ledger entry.
3. Repeating that idempotency key with a different payload hash is a conflict.
4. Reusing an accepted nonce for a different request is a replay conflict.
5. A retry may use a fresh timestamp, nonce, and signature while preserving the
   original idempotency key and payload.

## Deployment registration

Endpoint:

```text
POST /v1/deployments/register
```

Registration payload hash input:

```text
myscoutee-registry-registration-payload-v1
<key_algorithm>
<public_key>
<software_version>
```

`key_algorithm` must be `Ed25519`. The request is:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "timestamp": "2026-07-28T00:00:00Z",
  "nonce": "nonce_...",
  "idempotency_key": "registration_...",
  "key_algorithm": "Ed25519",
  "public_key": "<base64 SPKI DER>",
  "software_version": "1.0.0",
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

The request signature uses the generic request format with the registration
path and public-key fingerprint as signer. This proves possession of the
submitted private key. Registration is additionally idempotent by public-key
fingerprint, so the same key can never create two deployments.

The central registration receipt signature input is:

```text
myscoutee-registry-registration-receipt-v1
<protocol_version>
<registry_scope>
<deployment_id>
<public_key_fingerprint>
<registered_at>
<registry_key_id>
```

Response:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "registered_at": "2026-07-28T00:00:01Z",
  "public_key_fingerprint": "sha256:...",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "receipt_signature": "<base64 Ed25519 signature>",
  "duplicate": false
}
```

`deployment_id` is the public installation/deployment code in milestone 1. It
is not an operator login secret or a future claim bearer token. Possession of
the deployment private key is the proof of deployment control.

## Installation-test MAU batch

Endpoint:

```text
POST /v1/mau/batches
```

The installation-test variant is non-accounting:

```text
kind                = installation-test
ruleset_version     = installation-test-v1
qualified_mau_count = 0
```

The test commitment hash input is:

```text
myscoutee-registry-installation-test-v1
<deployment_id>
<idempotency_key>
```

The batch payload hash input is:

```text
myscoutee-registry-mau-batch-payload-v1
<kind>
<period>
<ruleset_version>
<qualified_mau_count as base-10 integer>
<commitment_hash>
```

Request:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-28T00:00:02Z",
  "nonce": "nonce_...",
  "idempotency_key": "installation_...",
  "kind": "installation-test",
  "period": "2026-07",
  "ruleset_version": "installation-test-v1",
  "qualified_mau_count": 0,
  "commitment_hash": "sha256:...",
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

Accepted installation tests use ledger entry type:

```text
INSTALLATION_TEST_BATCH_ACCEPTED
```

They must never contribute to MAU weight or a leaderboard.

The immutable ledger-entry hash input is:

```text
myscoutee-registry-ledger-entry-v1
<protocol_version>
<registry_scope>
<ledger_index>
<entry_type>
<deployment_id>
<batch_id>
<kind>
<period>
<ruleset_version>
<qualified_mau_count>
<batch_hash>
<previous_entry_hash>
<accepted_at>
```

`batch_hash` is the verified request `payload_hash`. The entry hash is the
SHA-256 hash of this canonical message.

The central MAU receipt signature input is:

```text
myscoutee-registry-mau-receipt-v1
<protocol_version>
<registry_scope>
<batch_id>
<deployment_id>
<ledger_index>
<entry_hash>
<previous_entry_hash>
<batch_hash>
<kind>
<period>
<ruleset_version>
<qualified_mau_count>
<accepted_at>
<checkpoint_date>
<registry_key_id>
```

Response:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "batch_id": "batch_...",
  "deployment_id": "dep_...",
  "idempotency_key": "installation_...",
  "duplicate": false,
  "receipt": {
    "ledger_index": 1,
    "entry_hash": "sha256:...",
    "previous_entry_hash": "sha256:...",
    "batch_hash": "sha256:...",
    "kind": "installation-test",
    "period": "2026-07",
    "ruleset_version": "installation-test-v1",
    "qualified_mau_count": 0,
    "accepted_at": "2026-07-28T00:00:03Z",
    "checkpoint_date": "2026-07-28",
    "registry_scope": "example:region-a",
    "registry_key_id": "rkey_...",
    "registry_public_key": "<base64 SPKI DER>",
    "signature": "<base64 Ed25519 signature>"
  }
}
```

Receipt lookup:

```text
GET /v1/mau/batches/{batch_id}/receipt
```

The immediate receipt names the UTC checkpoint date that will cover the entry.
That daily checkpoint is immutable and is finalized only after the UTC date has
closed.

## Qualified monthly active-user snapshots

Production QMAU snapshots use the same signed endpoint:

```text
POST /v1/mau/batches
```

The fixed v1 metadata is:

```text
kind            = monthly-qmau
ruleset_version = qmau-v1
```

For `qmau-v1`, one qualified user is a distinct local human account that is not
an administrator, demo account, or test account and that records at least two
substantive actions on at least two separate days in the applicable rolling
30-day activity window. Substantive actions are rating, joining, messaging,
hosting, booking, or verified attendance. The submitting deployment applies
this rule to its private evidence. The registry receives only the aggregate
non-negative count and an opaque SHA-256 evidence commitment; it does not
receive user identifiers or activity records and cannot independently prove
that the local evidence is truthful.

The initial snapshot for one deployment and period has `revision = 1` and an
empty `supersedes_batch_id`. A correction is a complete immutable replacement,
increments `revision` by exactly one, and names the currently active prior
batch. Stale or branching corrections are rejected. Historical revisions stay
in the ledger and source table; direct leaderboard rows select the latest
revision at their signed ledger boundary.

The QMAU payload-hash input is:

```text
myscoutee-registry-qmau-batch-payload-v1
monthly-qmau
<period>
qmau-v1
<qualified_mau_count as base-10 integer>
<commitment_hash>
<revision as base-10 integer>
<supersedes_batch_id, empty for revision 1>
```

Example request:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-28T00:00:02Z",
  "nonce": "nonce_...",
  "idempotency_key": "qmau_2026_06_revision_1",
  "kind": "monthly-qmau",
  "period": "2026-06",
  "ruleset_version": "qmau-v1",
  "qualified_mau_count": 1250,
  "commitment_hash": "sha256:...",
  "revision": 1,
  "supersedes_batch_id": "",
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

The generic request signature uses `/v1/mau/batches` and the deployment ID as
signer. An accepted snapshot appends the entry type:

```text
QMAU_BATCH_ACCEPTED
```

The existing ledger-entry canonical message is unchanged. In the same SQLite
transaction, the registry writes one immutable `ledger_weight_rows` row with
the accepted count. This row is a directly queryable representation, not an
asynchronous projection, and is never rebuilt or repaired from the ledger.

The QMAU receipt-signature input is:

```text
myscoutee-registry-qmau-receipt-v1
<protocol_version>
<registry_scope>
<batch_id>
<deployment_id>
<ledger_index>
<entry_hash>
<previous_entry_hash>
<batch_hash>
monthly-qmau
<period>
<ruleset_version>
<qualified_mau_count>
<commitment_hash>
<revision>
<supersedes_batch_id>
<accepted_at>
<checkpoint_date>
<registry_key_id>
```

The response uses the normal batch envelope. Its `receipt` includes
`commitment_hash`, `revision`, registry identity, and signature;
`supersedes_batch_id` is present when non-empty. The empty revision-1 value is
still one line in the canonical receipt-signature message. Receipt lookup
remains:

```text
GET /v1/mau/batches/{batch_id}/receipt
```

Leaderboard measured weight is the arithmetic mean of each deployment's active
QMAU snapshots across the six most recent complete UTC months. Missing months
contribute zero to that fixed six-month denominator. The leaderboard
explicitly reports deployment-level QMAU; it must not be described as globally
deduplicated human users.

## Daily aggregate revenue batches

Revenue ingestion is a distinct signed endpoint:

```text
POST /v1/revenue/batches
```

It accepts privacy-safe per-currency totals only. It never accepts payment,
customer, user, booking, or provider identifiers. The fixed v1 accounting
metadata is:

```text
kind                         = daily-revenue
ruleset_version              = net-captured-revenue-v1
commission_rate_basis_points = 500
```

`period` is the original payment UTC day. Revision 1 has an empty
`supersedes_batch_id`. A correction is a complete immutable replacement
snapshot for the same deployment/day, increments `revision` by exactly one,
and names the currently active prior batch in `supersedes_batch_id`. A stale or
branching correction is rejected. Old revisions remain in the ledger and
direct query tables; reads select only the latest revision.

The request is:

```json
{
  "protocol_version": "1",
  "registry_scope": "example:region-a",
  "deployment_id": "dep_...",
  "timestamp": "2026-07-28T00:00:02Z",
  "nonce": "nonce_...",
  "idempotency_key": "revenue_2026_07_27_revision_1",
  "kind": "daily-revenue",
  "period": "2026-07-27",
  "revision": 1,
  "supersedes_batch_id": "",
  "ruleset_version": "net-captured-revenue-v1",
  "commission_rate_basis_points": 500,
  "currencies": [
    {
      "currency_code": "EUR",
      "fraction_digits": 2,
      "captured_minor": 12345,
      "refunded_minor": 345,
      "net_minor": 12000,
      "commission_basis_minor": 12000,
      "estimated_commission_minor": 600,
      "payment_count": 4
    }
  ],
  "payload_hash": "sha256:...",
  "signature": "<base64 Ed25519 signature>"
}
```

Currencies must be strictly sorted and unique by `currency_code`. The registry
uses a deterministic supported ISO-4217 code/exponent table and rejects unknown
codes or mismatched `fraction_digits`. It never converts or aggregates between
currencies. `currencies` must be a JSON array; an empty array is valid and
records an explicit zero-revenue day, while an omitted or `null` field is
rejected.
At most 32 currencies are accepted. Every minor-unit value is bounded at
`9000000000000000` and `payment_count` at `1000000000000`; the registry also
rejects a write that would overflow the active per-day/currency aggregate.

For each row:

```text
captured_minor >= 0
0 <= refunded_minor <= captured_minor
net_minor = captured_minor - refunded_minor
commission_basis_minor = net_minor
estimated_commission_minor = floor(commission_basis_minor * 500 / 10000)
payment_count >= 0
```

The `currencies` field contains accounting totals, not a transaction list. The
canonical revenue payload is:

```text
myscoutee-registry-revenue-batch-payload-v1
<kind>
<period>
<revision>
<supersedes_batch_id>
<ruleset_version>
<commission_rate_basis_points>
<currency row count>
<first currency_code>
<first fraction_digits>
<first captured_minor>
<first refunded_minor>
<first net_minor>
<first commission_basis_minor>
<first estimated_commission_minor>
<first payment_count>
... eight lines for each remaining sorted currency row
```

The request `payload_hash` is the SHA-256 digest of that message. The generic
request signature uses `/v1/revenue/batches` and the deployment ID as signer.

An accepted batch appends `REVENUE_BATCH_ACCEPTED` to the same hash-linked
ledger as installation-test entries. Its existing ledger message format is
unchanged: revenue uses `qualified_mau_count = 0`, and `batch_hash` is the
verified revenue payload hash. Therefore introducing revenue does not change
or invalidate any historical ledger hash or completed-day checkpoint.

In the same SQLite transaction, the registry also writes immutable
`revenue_batches` and one `revenue_query_rows` row per currency. These rows are
the directly queryable representation; they are not an asynchronous projection
and are never repaired from the ledger. Integrity verification independently
compares every source batch, signed request, receipt, ledger entry, revision
link, and query row.

The registry receipt signature input is:

```text
myscoutee-registry-revenue-receipt-v1
<protocol_version>
<registry_scope>
<batch_id>
<deployment_id>
<ledger_index>
<entry_hash>
<previous_entry_hash>
<batch_hash>
<kind>
<period>
<revision>
<supersedes_batch_id>
<ruleset_version>
<commission_rate_basis_points>
<currency_count>
<accepted_at>
<checkpoint_date>
<registry_key_id>
```

The response has the same top-level identity/idempotency fields as an MAU
batch response and a receipt containing every canonical field above plus
`registry_public_key` and `signature`. Receipt lookup is:

```text
GET /v1/revenue/batches/{revbatch_id}/receipt
```

The local registry-administrator CLI can query one currency at a time:

```text
/registry revenue --period 2026-07-27 --currency EUR
/registry revenue --period 2026-07-27 --currency EUR --deployment-id dep_...
/registry revenue --period 2026-07-27 --currency EUR --group-id opg_...
```

There is intentionally no unauthenticated public revenue query endpoint.
`network_commission_pool_minor` is calculated once from the registry-wide
active aggregate for the requested UTC day and currency:

```text
floor(SUM(active commission_basis_minor) * 500 / 10000)
```

It is not the sum of already-rounded deployment estimates. The CLI reports the
currency and minor-unit exponent with the total; the registry does not perform
foreign-exchange conversion. With `--deployment-id` or `--group-id`, captured,
refunded, net, basis, payment-count, batch-count, and
`reported_estimated_commission_minor` fields describe only the selected
breakdown, while `network_commission_pool_minor` deliberately remains the
registry-wide active pool for that UTC day and currency. The separately
versioned [`settlements-v1.md`](settlements-v1.md) extension can apply the
auditable QMAU weight boundary to a completed month's aggregated technical
pool. That extension is deliberately non-binding and does not turn either the
daily revenue receipt or monthly allocation into a legal settlement, payment,
or payout decision.

## Compact Merkle proofs

The linear SHA-256 ledger hash chain remains authoritative. In the same
transaction as each ledger append, the registry additionally maintains an
RFC 9162 Certificate-Transparency-style Merkle Tree Hash index over the
immutable ledger entry hashes.

The leaf and internal-node hashes are:

```text
leaf_hash = SHA-256(0x00 || raw_32_byte_ledger_entry_hash)
node_hash = SHA-256(0x01 || raw_32_byte_left_hash || raw_32_byte_right_hash)
empty_root = SHA-256(empty byte string)
```

Ledger entries are the leaves and are not copied into a second table. Only
completed internal subtrees are stored. A tree with `n` entries therefore
stores exactly `n - popcount(n)` internal rows. A normal append computes one
leaf and at most `floor(log2(n))` parent hashes (amortized one parent hash);
proof generation and proof verification are `O(log n)`. Full-tree validation
is deliberately reserved for startup, health checks, checkpoint finalization,
and explicit verification commands rather than performed as an additional
Merkle scan on every ordinary request.

Inclusion proof:

```text
GET /v1/ledger/merkle/inclusion/{tree_size}/{ledger_index}
```

Consistency proof:

```text
GET /v1/ledger/merkle/consistency/{old_tree_size}/{new_tree_size}
```

`tree_size = 0` on the inclusion endpoint means the current size.
`new_tree_size = 0` on the consistency endpoint means the current size.
Indices are one-based. Both responses include an audit path and a
registry-signed tree head. The tree-head signature input is:

```text
myscoutee-registry-merkle-tree-head-v1
<protocol_version>
<registry_scope>
<tree_size>
<root_hash>
<generated_at>
<registry_key_id>
```

The signed head also returns the registry public key. A verifier must validate
the registry key ID/public-key relationship, the Ed25519 tree-head signature,
and the complete inclusion or consistency path. These proofs establish that
an entry belongs to a signed ledger prefix or that one prefix only grew by
appending. They do not replace the daily checkpoint chain or prove that a
deployment's aggregate claim is truthful.

## Daily checkpoint

Endpoint:

```text
GET /v1/ledger/checkpoints/{YYYY-MM-DD}
```

A checkpoint commits to the ledger head at the end of a completed UTC day. Its
`entry_count` is the total number of ledger entries through that point.

Checkpoint signature/hash input:

```text
myscoutee-registry-checkpoint-v1
<registry_scope>
<checkpoint_date>
<through_ledger_index>
<entry_count>
<ledger_head_hash>
<previous_checkpoint_hash>
<generated_at>
<registry_key_id>
```

`checkpoint_hash` is the SHA-256 hash of that canonical message. `signature` is
the registry Ed25519 signature over the same canonical message.

```json
{
  "registry_scope": "example:region-a",
  "checkpoint_date": "2026-07-28",
  "through_ledger_index": 123,
  "entry_count": 123,
  "ledger_head_hash": "sha256:...",
  "previous_checkpoint_hash": "sha256:...",
  "checkpoint_hash": "sha256:...",
  "generated_at": "2026-07-29T00:00:05Z",
  "registry_key_id": "rkey_...",
  "registry_public_key": "<base64 SPKI DER>",
  "signature": "<base64 Ed25519 signature>"
}
```

## Trust boundary

This protocol begins only after a deployment has been explicitly initialized
and its Ed25519 key exists. It does not authorize automatic installer-time key
creation, registry selection, discovery, or outbound enrollment. A browser may
display the deployment public-key fingerprint but must never receive the
private key.

Registration proves possession of a deployment key. Batch signatures prove
which registered deployment made an unchanged claim. Central signatures, the
linear hash chain, signed checkpoints, and Merkle proofs make accepted history
tamper-evident. None of these prove that the operator reported truthful
activity or that a local account is one human.

No raw email, Firebase UID, access token, profile, chat, location, payment
detail, or other direct user identifier is accepted by protocol v1.

The later registry-signed, read-only operator announcement and update-manifest
extension is specified separately in
[`announcements-v1.md`](announcements-v1.md). It adds no public mutation or
remote-install endpoint and does not change deployment-registration or
accounting signatures.
