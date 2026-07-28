# MyScoutee Operator Network Protocol v1

This document defines the signed operator actions and read-only leaderboard
added on top of the deployment-registration protocol. Claiming a deployment
and grouping claimed deployments are deliberately separate operations.

## Trust and identity

- The installer performs no outbound registry communication.
- An operator explicitly selects and approves a registry before the Java
  deployment creates its local Ed25519 identity and registers.
- Every operator mutation is signed by the registered deployment key.
- The registry verifies the signature, timestamp, nonce, idempotency key, and
  payload hash before accepting the action.
- A deployment can be claimed only through its own signed request.
- A client code never claims a deployment and never changes deployment
  identity, MAU history, or ledger ownership.

## Signed operator actions

Endpoint:

```text
POST /v1/operator/actions
```

The request uses the generic signed-request envelope from
`protocol-v1.md`, with the registered `deployment_id` as signer. Its canonical
payload is:

```text
myscoutee-registry-operator-action-payload-v1
<action>
<operator_name>
<operator_avatar_url>
<client_token_hash>
<token_ttl_seconds>
<token_id>
<link_id>
```

Only fields belonging to the selected action may be populated. Supported
actions are:

- `claim`: claims the caller and creates its operator group. Repeating it
  updates the public operator name/avatar without changing the group.
- `withdraw-claim`: withdraws the caller's claim.
- `issue-client-token`: issues a temporary client code after the caller is
  already claimed. The plaintext code is returned once; only its SHA-256 hash
  is stored.
- `revoke-client-token`: revokes an issued client code.
- `redeem-client-token`: links the caller to the issuing deployment's operator
  group. Both deployments must already be independently claimed.
- `revoke-group-link`: removes an accepted virtual group link.
- `deactivate-deployment` and `reactivate-deployment`: change whether a
  deployment participates in current leaderboard views.

Client codes are valid for 60–3600 seconds. They are virtual grouping
credentials only. Redeeming one does not combine ledger rows: each
deployment's accounting history remains separately auditable while the
leaderboard can present their share as one operator group.

Every accepted action appends:

1. one immutable, deployment-signed nonce record; and
2. one immutable, hash-linked operator audit event with a registry-signed
   receipt.

The action and nonce inserts commit in one SQLite transaction. Replays,
idempotency conflicts, expired/revoked codes, invalid signatures, and invalid
claim/group state fail without appending an audit event.

## Accounting ledger and query rows

The MAU ledger is the accounting source of truth. It is a linear SHA-256 hash
chain, anchored by registry-signed daily checkpoints; it is not a binary
Merkle tree.

For every accepted ledger entry, the same SQLite transaction performs exactly
two accounting writes:

1. the immutable `ledger_entries` row; and
2. the exact immutable `ledger_weight_rows` query row used by leaderboard
   SQL.

There is no projection worker, repair job, or eventual-consistency window.
Startup/read integrity verification rejects missing, extra, or field-mismatched
query rows.

## Leaderboard reads

Top-level pages:

```text
GET /v1/leaderboard?view=founder|claimed|unclaimed&through_period=YYYY-MM&limit=20&cursor=...
```

Deployments inside one claimed operator group:

```text
GET /v1/leaderboard/groups/{group_id}/deployments?through_period=YYYY-MM&limit=20&cursor=...
```

The registry:

- reads weights directly from `ledger_weight_rows`;
- freezes the ledger and operator-audit boundaries for the first page;
- signs the snapshot containing both boundary hashes;
- returns registry-signed opaque cursors bound to the view, period, group, and
  frozen boundaries; and
- orders rows by weight descending with a stable ID tie-breaker.

The formula uses the six most recent complete UTC months. Founder contribution
is fixed at 100,000 units and founder share is:

```text
max(10%, 100000 / (100000 + measured_network_weight))
```

The remaining pool is divided among claimed operator groups by their
aggregated measured weight. Unclaimed deployments remain visible with their
measured weight but receive zero share.

Protocol v1 currently accepts only zero-count installation-test MAU batches,
so production weight remains zero until the separately specified qualified-MAU
protocol is enabled. Explore/demo data is seeded locally and does not enter a
real registry.

