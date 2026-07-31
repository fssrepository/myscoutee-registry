# Registry-local exit review v1

Exit review is a registry-local legal/audit rail. It freezes an exact,
historically verifiable technical boundary for one approved claim generation
and records subsequent buyer/auditor decisions. It does not transfer claim
ownership, calculate a contractual entitlement, create an invoice, or execute
a payment.

## Frozen record

`freeze-exit-review` accepts an exact deployment, claim action, operator group,
and completed UTC `record_date`. The date must already have a signed registry
checkpoint. One immutable record pins:

- the checkpoint hash, ledger index/head, entry count, and RFC 9162 Merkle
  root for that ledger prefix;
- the last operator-audit, claim-review, and eligibility event before the end
  of the record date;
- every active claimed deployment in the exact group at those boundaries,
  including each claim generation, its active/suspended eligibility state, and
  source hashes (the target claim itself must be active and eligible);
- the newest settlement revision for every period/currency whose ledger event
  is within the frozen checkpoint.

Membership and settlement rows are sorted canonically and committed by
separate SHA-256 hashes. The complete record is committed by `record_hash`.
The first signed event commits to that hash and begins in `review-pending`.
There is at most one frozen review for an exact target deployment/claim
generation.

The source ledgers remain authoritative. The exit tables do not copy private
verification contacts, documents, addresses, payment instructions, or
credentials.

## Effective-dated states

The registry accepts these immutable transitions:

| Action | From | Result |
| --- | --- | --- |
| `freeze` | no review | `review-pending` |
| `verify` | `review-pending`, `disputed` | `verified-eligible` |
| `reject` | `review-pending`, `disputed` | `rejected` |
| `dispute` | `verified-eligible`, `rejected` | `disputed` |
| `withdraw` | any non-withdrawn state | `withdrawn` |

`withdrawn` is terminal. Effective dates cannot precede the frozen record date
or the preceding event for that review, and cannot be in the future. Reject,
dispute, and withdraw require a bounded lowercase reason token.

Events form both one global registry-signed hash chain and a per-review hash
chain. Each event and its direct query row are appended in one SQLite
transaction. Query rows are never repaired or regenerated from either the
ledger or the event chain.

## Evidence and actor boundary

The database stores only:

- `actor_role`: `buyer` or `auditor`;
- a bounded, non-personal actor identifier;
- a bounded, non-personal external reference;
- a canonical SHA-256 commitment to governed evidence.

Evidence bodies, names, e-mail addresses, documents, secrets, and remote
credentials must remain in the separately governed buyer/auditor system.
Omitting `--evidence-hash` records the protocol zero hash. Local filesystem and
container access to the registry signing key is the v1 command authority; the
registry signature proves what the registry recorded, not who a human is.

## CLI flow

Copy the exact identifiers from the approved claim and choose a completed
checkpoint day:

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
  --evidence-hash sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --idempotency-key freeze-exit-2026-0042
```

Inspect or paginate directly maintained state:

```bash
docker compose exec -T registry \
  /registry list-exit-reviews --status review-pending --limit 50

docker compose exec -T registry \
  /registry show-exit-review \
  --review-id exr_0123456789abcdef0123456789abcdef
```

Record a decision:

```bash
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

`--decision reject` additionally requires `--reason-code`. The
`dispute-exit-review` and `withdraw-exit-review` commands use the same
review/date/actor/reference/evidence/idempotency arguments and always require
`--reason-code`. Exact retries return `duplicate: true`; reuse of an
idempotency key for different content fails closed.

## Verification and backup

Startup, health, explicit verification, and the first request after another
SQLite connection commits verify:

- all required append-only triggers;
- the exact frozen checkpoint, Merkle root, chain heads, group membership, and
  latest settlement revision set;
- record, membership, and settlement-boundary hashes;
- global and per-review event links, payload/event hashes, registry
  signatures, timestamps, actors, evidence commitments, and transitions;
- one exact direct query row for every immutable event.

Any mismatch fails closed. Back up the SQLite database, signing key, and
registry identity together. Restoring only the exit tables or editing a query
row is not supported.
