# Registry-local ownership transfer v1

Ownership transfer is a registry-local legal/audit rail for changing one
deployment's effective operator-group membership after an exit review. It is
not a sale contract, beneficial-owner check, invoice, tax record, payment
instruction, or payment execution.

## Prepared boundary

`prepare-ownership-transfer` accepts:

- one exact deployment and its exact current `APPROVED` claim generation;
- that claim's current source operator group;
- a different, existing target operator group;
- the exact current `verified-eligible` exit review and verification-event
  hash for the same deployment, claim generation, and source group; and
- governed request and evidence commitments.

The source claim must still be active and eligible. The target group must
currently contain at least one active, approved, eligible claim; an arbitrary
empty, stale, or invented group ID is rejected. Both conditions are checked
again when completion is attempted.

The immutable transfer record pins the exit record hash, verification event
index/hash, and that event's evidence commitment. Its `legal_name` is only the
source deployment's historical claim-generation audit name. It is never used
as the target group's public label. The target group's leaderboard name and
avatar continue to come from the target group's own active, approved,
registry-verified claim profile.

Preparation writes no membership row and changes no leaderboard, claim,
eligibility, revenue, settlement, or payment state.

## Manager state machine

Every action is an immutable registry-signed event in both a global chain and
a per-transfer chain:

| Action | From | Result |
| --- | --- | --- |
| `prepare` | no transfer | `prepared` |
| `approve` | `prepared` | `approved` |
| `reject` | `prepared` | `rejected` |
| `cancel` | `prepared`, `approved` | `cancelled` |
| `complete` | `approved` | `completed` |

`rejected`, `cancelled`, and `completed` are terminal. Reject and cancel
require a bounded lowercase reason token. Manager actions use the
`registry-manager` actor role and a bounded non-personal manager identifier.
The registry signing key is the v1 command authority; evidence bodies,
personal data, credentials, and remote-system secrets remain outside the
database.

The event idempotency key is globally unique. An exact retry returns the
original event with `duplicate: true`; reuse for different content fails
closed.

## Completion and historical membership

Completion is deliberately separate from approval. It succeeds only while:

- the exact source claim generation is still current, approved, active, and
  eligible in the source group;
- the pinned exit review is still at the exact verified event; and
- the target group still has an active, approved, eligible claim.

The explicit completion `effective_date` must be today's UTC date. This
prevents a later command from backdating a membership into an already frozen
exit day or an already signed settlement boundary.

In one SQLite transaction, completion appends:

1. the signed `complete` event;
2. its directly maintained immutable query-state row; and
3. one immutable membership boundary containing the source/target group,
   effective date, exact claim generation, completion event hash, and pinned
   operator-audit index/hash.

It does not update or delete the old claim, eligibility decision, claim
submission, operator-audit state, or historical group membership. A
leaderboard snapshot applies the membership only when both its pinned transfer
event index and effective date include completion. Old signed cursors and
snapshots therefore retain the old group. A later claim, withdrawal,
deactivation, or group-link action has a later operator-audit boundary and
supersedes the transfer overlay without editing either history.

Current group-filtered revenue reads and later technical settlement
calculations use the effective membership. Historical settlements retain
their immutable beneficiary-deployment rows and are never reassigned.

Only one `prepared` or `approved` transfer may exist for an exact deployment
and claim generation. If the claim, eligibility, exit decision, or target
group becomes stale, completion fails closed; a manager can record
`cancelled`, and a later request is a new immutable transfer.

## CLI flow

Prepare using identifiers copied from the claim and verified exit review:

```bash
docker compose exec -T registry \
  /registry prepare-ownership-transfer \
  --exit-review-id exr_0123456789abcdef0123456789abcdef \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --claim-action-id opa_0123456789abcdef0123456789abcdef \
  --source-group-id opg_0123456789abcdef0123456789abcdef \
  --target-group-id opg_fedcba9876543210fedcba9876543210 \
  --exit-verification-event-hash sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --requester-id acquisition-request-system \
  --reference transfer:2026-0042 \
  --evidence-hash sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --idempotency-key prepare-transfer-2026-0042
```

Approve, inspect, and complete:

```bash
docker compose exec -T registry \
  /registry decide-ownership-transfer \
  --transfer-id otf_0123456789abcdef0123456789abcdef \
  --decision approve \
  --effective-date 2026-07-29 \
  --manager-id registry-transfer-manager \
  --reference approval:2026-0042 \
  --idempotency-key approve-transfer-2026-0042

docker compose exec -T registry \
  /registry show-ownership-transfer \
  --transfer-id otf_0123456789abcdef0123456789abcdef

docker compose exec -T registry \
  /registry complete-ownership-transfer \
  --transfer-id otf_0123456789abcdef0123456789abcdef \
  --effective-date 2026-07-29 \
  --manager-id registry-transfer-manager \
  --reference completion:2026-0042 \
  --idempotency-key complete-transfer-2026-0042
```

Reject uses `decide-ownership-transfer --decision reject --reason-code TOKEN`.
Cancellation uses `cancel-ownership-transfer` and also requires
`--reason-code`. Paginate direct state with:

```bash
/registry list-ownership-transfers \
  --status prepared --limit 50
```

## Verification and backup

Startup, health, explicit verification, and the first request after another
SQLite connection commits verify:

- append-only triggers and exact record hashes;
- claim submission and verified exit-review/event commitments;
- target-group approved/eligible existence at prepare;
- global and per-transfer event links, transitions, timestamps, payload/event
  hashes, registry signatures, actors, reasons, and idempotency;
- one exact state row per event and no conflicting active transfers; and
- exactly one correctly hashed membership boundary per completed transfer,
  including its pinned operator-audit head.

Back up the SQLite database, registry signing key, and registry identity
together.

## Deliberate final-allocation boundary

This v1 finishes auditable membership ownership transfer. It does not create a
final contractual exit allocation. A separately versioned allocation rail
still needs to pin one verified exit review and one completed transfer (or an
explicit no-transfer beneficiary), select exact latest settlement revisions
only inside that exit's frozen settlement boundary, record contractual input
commitments, store allocated minor units separately for every ISO-4217
currency, enforce non-negative JavaScript-safe integers and exact per-currency
conservation, and append signed decision/query rows in one transaction.

That future record must remain non-payment: no bank details, payout
instructions, invoice state, or money movement may be inferred or executed by
the registry.
