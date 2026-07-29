# Technical monthly settlement and valuation v1

This document defines the registry-calculated
`share-weighted-settlement-v1` technical allocation and the
`three-month-acceleration-valuation-v1` indicative valuation. Both are
deterministic accounting records. They are not payment execution, a legal
entitlement, an invoice, a tax statement, a buyer/auditor decision, or a final
contractual allocation.

## Calculation boundary

An administrator explicitly runs the calculation for one completed UTC month
`M` and one supported ISO-4217 currency. The registry pins:

- the latest non-settlement ledger index and hash;
- the operator audit index and hash;
- the company-review index and hash;
- the claim-eligibility index and hash;
- every selected revenue batch/ledger entry;
- all 12 monthly TTM basis rows;
- every eligible operator-group weight; and
- every active, eligible deployment that belonged to each beneficiary group
  at that boundary, including a zero-weight member of a group whose aggregate
  weight is positive.

The ledger source boundary deliberately excludes earlier settlement events.
Re-running an unchanged calculation therefore returns the existing immutable
revision rather than making its own ledger append a new source. A changed
source boundary or source fingerprint appends the next revision and records
the exact superseded settlement ID. Old revisions are never edited.

The registry writes the settlement event, Merkle append, receipt signature,
source rows, historical beneficiary memberships, and allocations in one
SQLite transaction. These direct query tables are not an asynchronous
projection and are never repaired from the ledger.

## Monthly 5% pool

For each deployment/day in the trailing 12-month range, the calculation selects
the latest revenue revision at or before the pinned ledger boundary. It sums
`commission_basis_minor` by month without currency conversion.

For settlement month `M`:

```text
monthly_basis = SUM(active commission_basis_minor in M)
monthly_pool  = floor(monthly_basis * 500 / 10000)
```

The 5% is calculated once after aggregation. It is not the sum of rounded
per-deployment estimates.

The informational trailing-twelve-month pool follows the same aggregate rule:
`floor(TTM_commission_basis_minor * 500 / 10000)`. The per-month TTM source
rows retain their own independently rounded month values for audit, but those
rows are not summed to derive the TTM aggregate pool.

## Share ratios

The weight window is `M-5` through `M`, the same six-complete-month window and
latest-QMAU-revision semantics used by the leaderboard.

```text
founder_scaled = 100000 * 6
founder_share  = max(1/10, founder_scaled /
                           (founder_scaled + all_measured_weight))
operator_pool  = 1 - founder_share
```

`all_measured_weight` includes measured deployment weight regardless of claim
status, matching the leaderboard founder formula. The operator pool is divided
pro rata only among operator groups whose claim is legacy `claimed` or
administratively `approved`, whose deployment is active, and whose claim is
not suspended at the pinned eligibility boundary.

If no operator group is eligible, the entire operator pool is assigned to the
explicit `UNALLOCATED_RESERVE` beneficiary. The founder allocation is always
present. Pending, rejected, withdrawn, inactive, and suspended claims receive
no allocation.

All shares are stored as exact numerator/denominator strings. Integer minor
units use the largest-remainder method. Equal remainders are resolved by
ascending stable beneficiary ID. The allocation verifier recalculates every
ratio and requires both the monthly pool and indicative-value allocations to
conserve their respective totals exactly.

## Non-binding indicative value

The valuation uses accepted commission-basis revenue, not the 5% pool.
Trailing-twelve-month basis is the sum for `M-11` through `M`.

Three consecutive three-month averages are calculated with integer division:

```text
earlier = floor(SUM(M-8 .. M-6) / 3)
prior   = floor(SUM(M-5 .. M-3) / 3)
recent  = floor(SUM(M-2 .. M  ) / 3)
```

Growth in basis points has explicit zero-window behavior:

```text
growth(0, 0)        = 0
growth(0, positive) = 20000
growth(previous>0, current) =
    clamp(trunc((current-previous) * 10000 / previous), -10000, 20000)
```

Then:

```text
prior_growth  = growth(earlier, prior)
recent_growth = growth(prior, recent)
acceleration  = clamp(recent_growth - prior_growth, -10000, 10000)

adjustment = clamp(
    trunc(recent_growth / 4) + trunc(acceleration / 4),
    -2500,
    2500
)

effective_multiplier_bps =
    floor(base_multiplier_bps * (10000 + adjustment) / 10000)

indicative_network_value_minor =
    floor(TTM_commission_basis_minor * effective_multiplier_bps / 10000)
```

The default base multiplier is `30000` basis points (3x), configurable with
`REGISTRY_VALUATION_MULTIPLIER_BASIS_POINTS`. For the default, the bounded
adjustment limits the effective multiplier to 2.25x-3.75x. A single new spike
cannot bypass that bound. Every operation uses signed integers or exact
rationals; no floating point is used.

The value is allocated across the same exact beneficiary shares for
transparency, but every receipt and history item marks it non-binding.

## Exact JSON money boundary

The v1 wire format carries minor-unit money fields as JSON numbers. Therefore
every settlement monetary input, aggregate, three-month average, pool,
indicative value, and allocation exposed by a receipt or history item must be
an integer in:

```text
0 .. 9007199254740991
```

The upper bound is JavaScript's `Number.MAX_SAFE_INTEGER`; Go and Java enforce
the same value as `SettlementMaximumSafeMinor` and
`SETTLEMENT_MAXIMUM_SAFE_MINOR`. A calculation that would exceed the bound
fails before any settlement, ledger, Merkle, or direct-query row is written.
Startup verification also rejects an out-of-range persisted settlement. This
keeps every signed decimal integer exact in browser, Java, and Go consumers
without changing the v1 numeric wire format. A future protocol that needs
larger amounts must version those fields as canonical decimal strings rather
than silently emitting imprecise JSON numbers.

## Ledger and receipt

Each non-duplicate calculation appends a registry-owned ledger event:

```text
entry_type      = SETTLEMENT_CALCULATED
deployment_id   = <empty canonical registry-owned value>
kind            = monthly-settlement
period          = YYYY-MM
ruleset_version = share-weighted-settlement-v1
```

The settlement hash commits to its revision, currency, rulesets, valuation
inputs/results, all four source boundaries, source fingerprint, allocation
hash, acceptance time, scope, and registry key ID. The ledger entry commits to
that settlement hash. The registry receipt signature additionally binds the
ledger index, entry hash, and previous entry hash. The normal compact Merkle
index includes this ledger entry.

Startup verification recalculates the exact revenue selection, TTM rows,
three-window valuation, eligibility/membership/weight inputs, shares,
largest-remainder allocations, hashes, revision chain, ledger linkage, and
registry receipt signature. The bounded operational verifier also recognizes
and verifies a settlement when it is the externally appended ledger head.

## Private deployment history endpoint

There is no public settlement or raw-revenue leaderboard field. A registered
deployment signs:

```text
POST /v1/settlements/query
```

The ordinary canonical request signer is the deployment ID; `query_id` occupies
the canonical idempotency-key position. `payload_hash` commits to currency,
period filters, superseded-revision choice, page size, and opaque cursor.

The registry verifies the deployment Ed25519 signature and timestamp before
querying. It returns only `OPERATOR_GROUP` allocation rows for which the
immutable `settlement_beneficiary_deployments` source table contains that
deployment. Joining a group later does not reveal earlier group settlements,
and leaving later does not alter an already signed historical record.

The response is registry-signed and binds the request hash, item hash, cursor,
generation time, scope, deployment, and registry key ID. Founder, reserve, and
other groups are available only through the local administrative CLI.

## Administrative CLI

The commands require an existing database, matching scope, and existing
registry signing key:

```bash
/registry calculate-settlement --period 2026-06 --currency EUR

/registry settlements --period 2026-06 --currency EUR --limit 20

/registry settlements \
  --deployment-id dep_0123456789abcdef0123456789abcdef \
  --currency EUR --limit 20
```

`calculate-settlement` prints the complete signed receipt and `duplicate`.
`settlements` can expose private beneficiary amounts and must remain a
registry-administrator command. Pagination cursors are the returned
`next_after_period` and `next_after_settlement_id` pair and must be copied
unchanged.

## Deliberate legal boundary

This v1 record makes a technical formula reproducible and auditable. Actual
payment, tax treatment, beneficial-owner checks, dispute/transfer handling,
exit record-date freeze, buyer/auditor approval, contractual rounding, and
final legal allocation remain governed outside this protocol until separately
versioned rules are approved.
