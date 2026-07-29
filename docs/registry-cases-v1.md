# Registry administrator case rail v1

This rail records operational anomaly observations without silently converting
them into claim, suspension, payout, or legal-exit decisions. It is local to
one registry identity and has no public HTTP mutation endpoint.

## Scope and privacy

A case may reference exactly one existing:

- deployment ID;
- operator claim action ID;
- operator group ID;
- monthly QMAU batch ID;
- revenue batch ID; or
- one-based accounting-ledger index.

The registry verifies that the typed subject already exists before accepting a
flag. The event stores only a bounded category, severity, actor identifier,
external reference, and optional canonical SHA-256 evidence digest. Evidence
bodies, personal names, e-mail addresses, documents, credentials, and free-form
investigation notes do not belong in this database or CLI output.

`OPEN` and `CLEARED` are audit-case states only. Neither state changes company
claim approval, operator grouping, measured MAU/revenue, leaderboard
eligibility/share, or legal entitlement.

## Append and query model

`registry_case_events` is immutable and hash-linked in `event_index` order.
Every event is signed by the registry identity. `registry_cases` is the directly
queried current row, written in the same SQLite transaction. Startup, health,
and external-CLI revision checks derive the expected current rows from the
signed events and fail closed on any mismatch; they never repair state.

A `flag` creates one case. A `clear` may follow it once. Reopening and ownership
transfer remain later versioned actions rather than overloaded v1 case states.
Suspension/reinstatement and exit disputes already use their own signed rails.

The caller-intent digest for `flag` excludes the registry-generated case ID, so
an exact idempotent retry returns the original signed flag event. Its adjacent
`case` field always reports current query state: after a later `clear`, retrying
the original `flag` therefore returns the original event together with the
current `CLEARED` case row, never a misleading stale `OPEN` row. A `clear`
digest includes the existing target case ID. Reusing an idempotency key with
different content fails.

Claim suspension and reinstatement now exist as a separate signed eligibility
rail, and exit disputes exist in the separate exit-review rail. They never
overload or rewrite a registry case. Case reopening, ownership transfer, and
final contractual allocation are not v1 case actions.

The event payload digest uses:

```text
myscoutee-registry-case-payload-v1
<action>
<empty for flag; target case_id for clear>
<subject_type>
<subject_id>
<category>
<severity>
<evidence_hash>
<reference>
<actor_id>
```

The immutable event hash uses:

```text
myscoutee-registry-case-event-v1
<event_index>
<event_id>
<case_id>
<action>
<subject_type>
<subject_id>
<category>
<severity>
<evidence_hash>
<reference>
<actor_id>
<idempotency_key>
<payload_hash>
<accepted_at>
<previous_event_hash>
<registry_scope>
<registry_key_id>
```

The Ed25519 registry receipt signs:

```text
myscoutee-registry-case-event-receipt-v1
<event_hash>
<registry_key_id>
```

## Operational commands

All commands require an existing, matching database, registry scope, and
signing key. They never initialize a missing registry.

```bash
/registry flag-registry-case \
  --subject-type deployment \
  --subject-id dep_0123456789abcdef0123456789abcdef \
  --category qmau-anomaly \
  --severity warning \
  --evidence-hash sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --reference review:2026-0042 \
  --actor-id network-review-team \
  --idempotency-key flag-review-2026-0042

/registry list-registry-cases \
  --status OPEN \
  --limit 50

/registry list-registry-cases \
  --status OPEN \
  --limit 50 \
  --before-event-index 123

/registry show-registry-case \
  --case-id case_0123456789abcdef0123456789abcdef

/registry clear-registry-case \
  --case-id case_0123456789abcdef0123456789abcdef \
  --reference resolution:2026-0042 \
  --actor-id network-review-team \
  --idempotency-key clear-review-2026-0042
```

The descending `next_event_index` cursor is the last returned case's immutable
flag-event index and is copied unchanged into `--before-event-index`. Clearing
a case while another caller is paging does not reorder or skip its remaining
case rows. Omitting `--evidence-hash` commits the protocol zero hash; it does
not authorize storing raw evidence elsewhere in the command.
