# Final exit allocation v1

Final exit allocation is a registry-local, append-only contractual/audit rail.
It turns one verified exit review's already frozen technical settlement
boundary into a currency-separated beneficiary allocation record. It does not
execute or authorize a payment and contains no bank account, payout
instruction, tax, invoice, or payment-provider field.

## Exact source and beneficiary boundary

`create-exit-allocation` accepts the exact current `verified-eligible` exit
review and verification-event hash. The immutable record pins:

- the exit record and verification event index/hash/evidence commitment;
- the exact deployment, approved claim generation, and source operator group
  already frozen by that exit review;
- either one exact completed ownership transfer or an explicit `no-transfer`
  beneficiary decision;
- the global ownership-transfer event index/hash visible when the decision was
  recorded;
- a bounded non-personal contract reference plus SHA-256 commitments to the
  complete contractual terms and supporting evidence; and
- every settlement revision selected by the exit review's frozen settlement
  boundary.

For `completed-transfer`, the beneficiary is derived from the completed
transfer's target operator group. The supplied transfer must match the same
exit review, deployment, claim generation, and source group, and its exact
terminal completion event is pinned. A separate `--beneficiary-id` is rejected.

For `no-transfer`, the command requires an opaque bounded non-personal
`--beneficiary-id`. No transfer may be `prepared`, `approved`, or `completed`
for that exact claim at the pinned ownership boundary. Once either kind of
final allocation exists, a new ownership-transfer preparation for that exit is
rejected. Rejected and cancelled transfer history remains visible and does not
prevent an explicit no-transfer decision.

Only one final allocation record may exist per exit review.

## Frozen settlement revisions and conservation

The command does not select a new or current settlement. It copies the exact
ordered rows from `exit_review_settlement_boundaries`. Those rows were already
selected as the latest revision for each period/currency at the exit's frozen
ledger boundary.

For each copied settlement revision, the allocation source is exactly that
settlement's immutable `OPERATOR_GROUP` network-pool allocation for the exit
source group. A missing source-group row contributes zero. Indicative
valuation is deliberately excluded: it is non-binding technical metadata, not
distributable value.

For each ISO-4217 currency `C`, v1 enforces:

```text
distributable_minor(C)
  = sum(source_group_network_pool_allocation_minor for frozen rows in C)

allocated_minor(C)
  = distributable_minor(C)
```

Currencies are never converted or combined. `fraction_digits` is copied from
the settlement source and must be consistent within a currency. Every source,
sum, and allocated amount is a non-negative integer no greater than
`9007199254740991`, so JSON/JavaScript consumers can represent it exactly.
SQLite checks equality and range; the full verifier independently reconstructs
the rows and sums. Zero-valued currencies are retained. An exit with no frozen
settlement rows has zero currency rows and commits to the canonical empty
source/allocation hashes.

The settlement-source hash and currency-allocation hash commit row order,
currency, fraction digits, exact revision identifiers and hashes, and all
minor-unit amounts. The record hash commits those two hashes and every exit,
ownership, beneficiary, contract, evidence, and registry identity field.

## Signed two-event lifecycle

Creation and final verification are separate:

| Command/action | From | Result |
| --- | --- | --- |
| `create-exit-allocation` / `create` | no record | `recorded` |
| `verify-exit-allocation` / `verify` | `recorded` | `verified-final` |

Each action appends one registry-signed event to both a global event hash chain
and the per-allocation hash chain. The same SQLite transaction writes the
authoritative record/source/currency rows, event, and immutable direct query
row. Verification rechecks the still-current exact verified-exit event,
beneficiary decision, copied settlement sources, and currency conservation
before appending the terminal event.

Event idempotency keys are globally unique within this rail. An exact retry
returns the original event with `duplicate: true`; different content under the
same key fails closed. `verified-final` is terminal.

## CLI

Transfer-backed creation:

```bash
docker compose exec -T registry \
  /registry create-exit-allocation \
  --exit-review-id exr_0123456789abcdef0123456789abcdef \
  --exit-verification-event-hash sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --decision-mode completed-transfer \
  --ownership-transfer-id otf_0123456789abcdef0123456789abcdef \
  --ownership-transfer-completion-event-hash sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789 \
  --contract-reference exit-contract:2026-0042 \
  --contract-terms-hash sha256:1111111111111111111111111111111111111111111111111111111111111111 \
  --evidence-hash sha256:2222222222222222222222222222222222222222222222222222222222222222 \
  --allocator-id registry-contract-manager \
  --idempotency-key create-exit-allocation-2026-0042
```

Explicit no-transfer creation replaces the two ownership-transfer flags with:

```bash
--decision-mode no-transfer \
--beneficiary-id contract-beneficiary:2026-0042
```

Inspect, verify-final, and paginate:

```bash
/registry show-exit-allocation \
  --allocation-id xal_0123456789abcdef0123456789abcdef

/registry verify-exit-allocation \
  --allocation-id xal_0123456789abcdef0123456789abcdef \
  --verifier-id registry-allocation-verifier \
  --reference allocation-verification:2026-0042 \
  --evidence-hash sha256:3333333333333333333333333333333333333333333333333333333333333333 \
  --idempotency-key verify-exit-allocation-2026-0042

/registry list-exit-allocations \
  --status verified-final \
  --decision-mode completed-transfer \
  --limit 50
```

Copy `next_event_index` into `--before-event-index` for the next page.

## Verification, evidence, and backups

Startup, health, explicit full verification, and the first operation after
another SQLite connection commits verify:

- append-only triggers and registry identity;
- exit record and exact eligible verification-event pins;
- historical ownership head, completed-transfer membership, or no-transfer
  absence at the recorded boundary;
- exact frozen settlement revisions, source-group technical allocations,
  source/currency hashes, JavaScript-safe ranges, and per-currency
  conservation;
- record, payload, event, global-chain, and per-record-chain hashes;
- registry signatures, transitions, timestamps, audit fields, and
  idempotency; and
- exactly one direct state row per event.

Evidence and contractual bodies stay in the governed external evidence store.
The registry holds only opaque non-personal references and SHA-256
commitments. Back up the SQLite database, registry signing key, registry
identity, and governed evidence store under the same retention policy.

This rail is proof of what was contractually allocated from immutable
technical sources. Payment approval, sanctions/tax checks, invoicing, bank
details, payout execution, reconciliation, and legal sufficiency remain
outside the registry.
