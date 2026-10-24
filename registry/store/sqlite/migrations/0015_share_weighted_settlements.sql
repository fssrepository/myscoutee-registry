-- Registry-calculated monthly settlements are authoritative append-only ledger
-- events. Their immutable source, weight, beneficiary-membership, TTM, and
-- allocation rows are written in the same transaction as the ledger/Merkle
-- append; they are query tables, never a repaired or asynchronous projection.
--
-- A settlement is registry-owned rather than deployment-submitted, so its
-- ledger deployment_id is the canonical empty string. Existing deployment
-- entries retain a non-empty deployment ID and are still verified against the
-- immutable deployments table by startup integrity verification.
DROP TRIGGER revenue_query_rows_no_update;
DROP TRIGGER revenue_query_rows_no_delete;
DROP TRIGGER revenue_batches_no_update;
DROP TRIGGER revenue_batches_no_delete;
DROP TRIGGER ledger_weight_rows_no_update;
DROP TRIGGER ledger_weight_rows_no_delete;
DROP TRIGGER mau_batches_no_update;
DROP TRIGGER mau_batches_no_delete;
DROP TRIGGER ledger_entries_no_update;
DROP TRIGGER ledger_entries_no_delete;

ALTER TABLE revenue_query_rows RENAME TO revenue_query_rows_pre_settlement;
ALTER TABLE revenue_batches RENAME TO revenue_batches_pre_settlement;
ALTER TABLE ledger_weight_rows RENAME TO ledger_weight_rows_pre_settlement;
ALTER TABLE mau_batches RENAME TO mau_batches_pre_settlement;
ALTER TABLE ledger_entries RENAME TO ledger_entries_pre_settlement;

CREATE TABLE ledger_entries (
    ledger_index         INTEGER PRIMARY KEY CHECK (ledger_index > 0),
    protocol_version     TEXT NOT NULL CHECK (protocol_version = '1'),
    registry_scope       TEXT NOT NULL,
    entry_type           TEXT NOT NULL CHECK (entry_type IN (
        'INSTALLATION_TEST_BATCH_ACCEPTED',
        'QMAU_BATCH_ACCEPTED',
        'REVENUE_BATCH_ACCEPTED',
        'SETTLEMENT_CALCULATED'
    )),
    deployment_id        TEXT NOT NULL,
    batch_id             TEXT NOT NULL UNIQUE,
    kind                 TEXT NOT NULL CHECK (kind IN (
        'installation-test',
        'monthly-qmau',
        'daily-revenue',
        'monthly-settlement'
    )),
    period               TEXT NOT NULL,
    ruleset_version      TEXT NOT NULL CHECK (ruleset_version IN (
        'installation-test-v1',
        'qmau-v1',
        'net-captured-revenue-v1',
        'share-weighted-settlement-v1'
    )),
    qualified_mau_count  INTEGER NOT NULL CHECK (qualified_mau_count >= 0),
    batch_hash           TEXT NOT NULL,
    previous_entry_hash  TEXT NOT NULL,
    entry_hash           TEXT NOT NULL UNIQUE,
    accepted_at          TEXT NOT NULL,
    CHECK (
        (
            entry_type = 'INSTALLATION_TEST_BATCH_ACCEPTED'
            AND deployment_id <> ''
            AND kind = 'installation-test'
            AND ruleset_version = 'installation-test-v1'
            AND qualified_mau_count = 0
        )
        OR
        (
            entry_type = 'QMAU_BATCH_ACCEPTED'
            AND deployment_id <> ''
            AND kind = 'monthly-qmau'
            AND ruleset_version = 'qmau-v1'
        )
        OR
        (
            entry_type = 'REVENUE_BATCH_ACCEPTED'
            AND deployment_id <> ''
            AND kind = 'daily-revenue'
            AND ruleset_version = 'net-captured-revenue-v1'
            AND qualified_mau_count = 0
        )
        OR
        (
            entry_type = 'SETTLEMENT_CALCULATED'
            AND deployment_id = ''
            AND kind = 'monthly-settlement'
            AND ruleset_version = 'share-weighted-settlement-v1'
            AND qualified_mau_count = 0
        )
    )
);

CREATE TABLE mau_batches (
    batch_id                    TEXT PRIMARY KEY,
    deployment_id               TEXT NOT NULL REFERENCES deployments(deployment_id),
    idempotency_key             TEXT NOT NULL,
    request_timestamp           TEXT NOT NULL,
    request_nonce               TEXT NOT NULL,
    deployment_signature        BLOB NOT NULL CHECK (length(deployment_signature) = 64),
    kind                        TEXT NOT NULL CHECK (kind IN ('installation-test', 'monthly-qmau')),
    period                      TEXT NOT NULL,
    ruleset_version             TEXT NOT NULL CHECK (ruleset_version IN ('installation-test-v1', 'qmau-v1')),
    qualified_mau_count         INTEGER NOT NULL CHECK (qualified_mau_count >= 0),
    commitment_hash             TEXT NOT NULL,
    revision                    INTEGER NOT NULL CHECK (revision >= 0),
    supersedes_batch_id         TEXT NOT NULL DEFAULT '',
    payload_hash                TEXT NOT NULL,
    accepted_at                 TEXT NOT NULL,
    ledger_index                INTEGER NOT NULL UNIQUE REFERENCES ledger_entries(ledger_index),
    receipt_signature           BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (deployment_id, idempotency_key),
    CHECK (
        (
            kind = 'installation-test'
            AND ruleset_version = 'installation-test-v1'
            AND qualified_mau_count = 0
            AND revision = 0
            AND supersedes_batch_id = ''
        )
        OR
        (
            kind = 'monthly-qmau'
            AND ruleset_version = 'qmau-v1'
            AND revision >= 1
            AND (
                (revision = 1 AND supersedes_batch_id = '')
                OR (revision > 1 AND supersedes_batch_id <> '')
            )
        )
    )
);

CREATE TABLE ledger_weight_rows (
    ledger_index          INTEGER PRIMARY KEY REFERENCES ledger_entries(ledger_index),
    deployment_id         TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                TEXT NOT NULL,
    revision              INTEGER NOT NULL DEFAULT 0 CHECK (revision >= 0),
    ruleset_version       TEXT NOT NULL,
    qualified_mau_count   INTEGER NOT NULL CHECK (qualified_mau_count >= 0),
    weight_numerator      INTEGER NOT NULL CHECK (weight_numerator >= 0),
    weight_denominator    INTEGER NOT NULL CHECK (weight_denominator > 0),
    accepted_at           TEXT NOT NULL,
    source_entry_hash     TEXT NOT NULL UNIQUE
);

CREATE TABLE revenue_batches (
    batch_id                       TEXT PRIMARY KEY,
    deployment_id                  TEXT NOT NULL REFERENCES deployments(deployment_id),
    idempotency_key                TEXT NOT NULL,
    request_timestamp              TEXT NOT NULL,
    request_nonce                  TEXT NOT NULL,
    deployment_signature           BLOB NOT NULL CHECK (length(deployment_signature) = 64),
    kind                           TEXT NOT NULL CHECK (kind = 'daily-revenue'),
    period                         TEXT NOT NULL,
    revision                       INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_batch_id            TEXT REFERENCES revenue_batches(batch_id),
    ruleset_version                TEXT NOT NULL CHECK (ruleset_version = 'net-captured-revenue-v1'),
    commission_rate_basis_points   INTEGER NOT NULL CHECK (commission_rate_basis_points = 500),
    currency_count                 INTEGER NOT NULL CHECK (currency_count >= 0),
    payload_hash                   TEXT NOT NULL,
    accepted_at                    TEXT NOT NULL,
    ledger_index                   INTEGER NOT NULL UNIQUE REFERENCES ledger_entries(ledger_index),
    receipt_signature              BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (deployment_id, idempotency_key),
    UNIQUE (deployment_id, period, revision),
    CHECK (
        (revision = 1 AND supersedes_batch_id IS NULL)
        OR (revision > 1 AND supersedes_batch_id IS NOT NULL)
    )
);

CREATE TABLE revenue_query_rows (
    batch_id                       TEXT NOT NULL REFERENCES revenue_batches(batch_id),
    currency_index                 INTEGER NOT NULL CHECK (currency_index >= 0),
    ledger_index                   INTEGER NOT NULL REFERENCES ledger_entries(ledger_index),
    deployment_id                  TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                         TEXT NOT NULL,
    revision                       INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_batch_id            TEXT NOT NULL DEFAULT '',
    currency_code                  TEXT NOT NULL CHECK (length(currency_code) = 3 AND currency_code = upper(currency_code)),
    fraction_digits                INTEGER NOT NULL CHECK (fraction_digits BETWEEN 0 AND 4),
    captured_minor                 INTEGER NOT NULL CHECK (captured_minor >= 0),
    refunded_minor                 INTEGER NOT NULL CHECK (refunded_minor >= 0 AND refunded_minor <= captured_minor),
    net_minor                      INTEGER NOT NULL CHECK (net_minor >= 0),
    commission_basis_minor         INTEGER NOT NULL CHECK (commission_basis_minor >= 0),
    estimated_commission_minor     INTEGER NOT NULL CHECK (estimated_commission_minor >= 0),
    payment_count                  INTEGER NOT NULL CHECK (payment_count >= 0),
    accepted_at                    TEXT NOT NULL,
    source_entry_hash              TEXT NOT NULL,
    PRIMARY KEY (batch_id, currency_index),
    UNIQUE (batch_id, currency_code),
    CHECK (net_minor = captured_minor - refunded_minor),
    CHECK (commission_basis_minor = net_minor)
);

INSERT INTO ledger_entries SELECT * FROM ledger_entries_pre_settlement ORDER BY ledger_index;
INSERT INTO mau_batches SELECT * FROM mau_batches_pre_settlement;
INSERT INTO ledger_weight_rows SELECT * FROM ledger_weight_rows_pre_settlement;
INSERT INTO revenue_batches SELECT * FROM revenue_batches_pre_settlement;
INSERT INTO revenue_query_rows SELECT * FROM revenue_query_rows_pre_settlement;

DROP TABLE revenue_query_rows_pre_settlement;
DROP TABLE revenue_batches_pre_settlement;
DROP TABLE ledger_weight_rows_pre_settlement;
DROP TABLE mau_batches_pre_settlement;
DROP TABLE ledger_entries_pre_settlement;

CREATE UNIQUE INDEX mau_batches_qmau_revision_idx
    ON mau_batches (deployment_id, period, revision)
    WHERE kind = 'monthly-qmau';
CREATE INDEX mau_batches_qmau_supersedes_idx
    ON mau_batches (supersedes_batch_id)
    WHERE supersedes_batch_id <> '';
CREATE INDEX ledger_entries_accepted_at_idx
    ON ledger_entries (accepted_at, ledger_index);
CREATE INDEX ledger_weight_rows_period_deployment_idx
    ON ledger_weight_rows (period, deployment_id, ledger_index);
CREATE INDEX ledger_weight_rows_deployment_period_idx
    ON ledger_weight_rows (deployment_id, period, ledger_index);
CREATE INDEX revenue_batches_period_deployment_revision_idx
    ON revenue_batches (period, deployment_id, revision DESC);
CREATE INDEX revenue_batches_supersedes_idx
    ON revenue_batches (supersedes_batch_id);
CREATE INDEX revenue_query_period_currency_deployment_idx
    ON revenue_query_rows (period, currency_code, deployment_id, revision DESC);
CREATE INDEX revenue_query_deployment_period_currency_idx
    ON revenue_query_rows (deployment_id, period, currency_code, revision DESC);
CREATE INDEX revenue_query_ledger_idx
    ON revenue_query_rows (ledger_index);

CREATE TABLE settlements (
    settlement_id                       TEXT PRIMARY KEY,
    period                              TEXT NOT NULL,
    currency_code                       TEXT NOT NULL CHECK (length(currency_code) = 3 AND currency_code = upper(currency_code)),
    fraction_digits                     INTEGER NOT NULL CHECK (fraction_digits BETWEEN 0 AND 4),
    revision                            INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_settlement_id            TEXT REFERENCES settlements(settlement_id),
    ruleset_version                     TEXT NOT NULL CHECK (ruleset_version = 'share-weighted-settlement-v1'),
    valuation_ruleset_version           TEXT NOT NULL CHECK (valuation_ruleset_version = 'three-month-acceleration-valuation-v1'),
    commission_rate_basis_points        INTEGER NOT NULL CHECK (commission_rate_basis_points = 500),
    base_valuation_multiplier_basis_points INTEGER NOT NULL CHECK (base_valuation_multiplier_basis_points BETWEEN 1000 AND 100000),
    recent_three_month_average_minor    INTEGER NOT NULL CHECK (recent_three_month_average_minor >= 0),
    prior_three_month_average_minor     INTEGER NOT NULL CHECK (prior_three_month_average_minor >= 0),
    earlier_three_month_average_minor   INTEGER NOT NULL CHECK (earlier_three_month_average_minor >= 0),
    recent_growth_basis_points          INTEGER NOT NULL CHECK (recent_growth_basis_points BETWEEN -10000 AND 20000),
    prior_growth_basis_points           INTEGER NOT NULL CHECK (prior_growth_basis_points BETWEEN -10000 AND 20000),
    acceleration_basis_points           INTEGER NOT NULL CHECK (acceleration_basis_points BETWEEN -10000 AND 10000),
    valuation_adjustment_basis_points   INTEGER NOT NULL CHECK (valuation_adjustment_basis_points BETWEEN -2500 AND 2500),
    effective_valuation_multiplier_basis_points INTEGER NOT NULL CHECK (effective_valuation_multiplier_basis_points > 0),
    commission_basis_minor              INTEGER NOT NULL CHECK (commission_basis_minor >= 0),
    network_commission_pool_minor       INTEGER NOT NULL CHECK (network_commission_pool_minor >= 0),
    ttm_commission_basis_minor          INTEGER NOT NULL CHECK (ttm_commission_basis_minor >= 0),
    ttm_network_commission_pool_minor   INTEGER NOT NULL CHECK (ttm_network_commission_pool_minor >= 0),
    indicative_network_value_minor      INTEGER NOT NULL CHECK (indicative_network_value_minor >= 0),
    through_ledger_index                INTEGER NOT NULL CHECK (through_ledger_index >= 0),
    through_audit_index                 INTEGER NOT NULL CHECK (through_audit_index >= 0),
    through_review_index                INTEGER NOT NULL CHECK (through_review_index >= 0),
    through_eligibility_index           INTEGER NOT NULL CHECK (through_eligibility_index >= 0),
    ledger_head_hash                    TEXT NOT NULL,
    audit_head_hash                     TEXT NOT NULL,
    review_head_hash                    TEXT NOT NULL,
    eligibility_head_hash               TEXT NOT NULL,
    source_fingerprint                  TEXT NOT NULL,
    allocation_hash                     TEXT NOT NULL,
    settlement_hash                     TEXT NOT NULL UNIQUE,
    accepted_at                         TEXT NOT NULL,
    ledger_index                        INTEGER NOT NULL UNIQUE REFERENCES ledger_entries(ledger_index),
    registry_key_id                     TEXT NOT NULL,
    receipt_signature                   BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (period, currency_code, revision),
    UNIQUE (period, currency_code, source_fingerprint),
    CHECK (
        (revision = 1 AND supersedes_settlement_id IS NULL)
        OR (revision > 1 AND supersedes_settlement_id IS NOT NULL)
    )
);

CREATE TABLE settlement_revenue_sources (
    settlement_id             TEXT NOT NULL REFERENCES settlements(settlement_id),
    source_order              INTEGER NOT NULL CHECK (source_order >= 0),
    revenue_period            TEXT NOT NULL,
    deployment_id             TEXT NOT NULL REFERENCES deployments(deployment_id),
    batch_id                  TEXT NOT NULL REFERENCES revenue_batches(batch_id),
    ledger_index              INTEGER NOT NULL REFERENCES ledger_entries(ledger_index),
    source_entry_hash         TEXT NOT NULL,
    commission_basis_minor    INTEGER NOT NULL CHECK (commission_basis_minor >= 0),
    PRIMARY KEY (settlement_id, source_order),
    UNIQUE (settlement_id, batch_id)
);

CREATE TABLE settlement_ttm_months (
    settlement_id                       TEXT NOT NULL REFERENCES settlements(settlement_id),
    period                              TEXT NOT NULL,
    commission_basis_minor              INTEGER NOT NULL CHECK (commission_basis_minor >= 0),
    network_commission_pool_minor       INTEGER NOT NULL CHECK (network_commission_pool_minor >= 0),
    PRIMARY KEY (settlement_id, period)
);

CREATE TABLE settlement_weight_sources (
    settlement_id    TEXT NOT NULL REFERENCES settlements(settlement_id),
    beneficiary_id   TEXT NOT NULL,
    label            TEXT NOT NULL,
    weight           INTEGER NOT NULL CHECK (weight >= 0),
    PRIMARY KEY (settlement_id, beneficiary_id)
);

CREATE TABLE settlement_beneficiary_deployments (
    settlement_id    TEXT NOT NULL REFERENCES settlements(settlement_id),
    beneficiary_id   TEXT NOT NULL,
    deployment_id    TEXT NOT NULL REFERENCES deployments(deployment_id),
    PRIMARY KEY (settlement_id, deployment_id)
);

CREATE TABLE settlement_allocations (
    settlement_id                       TEXT NOT NULL REFERENCES settlements(settlement_id),
    allocation_order                    INTEGER NOT NULL CHECK (allocation_order >= 0),
    beneficiary_type                    TEXT NOT NULL CHECK (beneficiary_type IN ('FOUNDER', 'OPERATOR_GROUP', 'UNALLOCATED_RESERVE')),
    beneficiary_id                      TEXT NOT NULL,
    label                               TEXT NOT NULL,
    share_numerator                     TEXT NOT NULL,
    share_denominator                   TEXT NOT NULL,
    network_pool_allocation_minor       INTEGER NOT NULL CHECK (network_pool_allocation_minor >= 0),
    indicative_value_allocation_minor   INTEGER NOT NULL CHECK (indicative_value_allocation_minor >= 0),
    PRIMARY KEY (settlement_id, allocation_order),
    UNIQUE (settlement_id, beneficiary_id)
);

CREATE INDEX settlements_period_currency_revision_idx
    ON settlements (period DESC, currency_code, revision DESC);
CREATE INDEX settlements_ledger_idx
    ON settlements (ledger_index);
CREATE INDEX settlement_revenue_sources_period_idx
    ON settlement_revenue_sources (revenue_period, settlement_id);
CREATE INDEX settlement_beneficiary_deployment_idx
    ON settlement_beneficiary_deployments (deployment_id, settlement_id);

CREATE TRIGGER ledger_entries_no_update BEFORE UPDATE ON ledger_entries BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only');
END;
CREATE TRIGGER ledger_entries_no_delete BEFORE DELETE ON ledger_entries BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only');
END;
CREATE TRIGGER mau_batches_no_update BEFORE UPDATE ON mau_batches BEGIN
    SELECT RAISE(ABORT, 'MAU batches are append-only');
END;
CREATE TRIGGER mau_batches_no_delete BEFORE DELETE ON mau_batches BEGIN
    SELECT RAISE(ABORT, 'MAU batches are append-only');
END;
CREATE TRIGGER ledger_weight_rows_no_update BEFORE UPDATE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;
CREATE TRIGGER ledger_weight_rows_no_delete BEFORE DELETE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;
CREATE TRIGGER revenue_batches_no_update BEFORE UPDATE ON revenue_batches BEGIN
    SELECT RAISE(ABORT, 'revenue batches are append-only');
END;
CREATE TRIGGER revenue_batches_no_delete BEFORE DELETE ON revenue_batches BEGIN
    SELECT RAISE(ABORT, 'revenue batches are append-only');
END;
CREATE TRIGGER revenue_query_rows_no_update BEFORE UPDATE ON revenue_query_rows BEGIN
    SELECT RAISE(ABORT, 'revenue query rows are append-only');
END;
CREATE TRIGGER revenue_query_rows_no_delete BEFORE DELETE ON revenue_query_rows BEGIN
    SELECT RAISE(ABORT, 'revenue query rows are append-only');
END;
CREATE TRIGGER settlements_no_update BEFORE UPDATE ON settlements BEGIN
    SELECT RAISE(ABORT, 'settlements are append-only');
END;
CREATE TRIGGER settlements_no_delete BEFORE DELETE ON settlements BEGIN
    SELECT RAISE(ABORT, 'settlements are append-only');
END;
CREATE TRIGGER settlement_revenue_sources_no_update BEFORE UPDATE ON settlement_revenue_sources BEGIN
    SELECT RAISE(ABORT, 'settlement revenue sources are append-only');
END;
CREATE TRIGGER settlement_revenue_sources_no_delete BEFORE DELETE ON settlement_revenue_sources BEGIN
    SELECT RAISE(ABORT, 'settlement revenue sources are append-only');
END;
CREATE TRIGGER settlement_ttm_months_no_update BEFORE UPDATE ON settlement_ttm_months BEGIN
    SELECT RAISE(ABORT, 'settlement TTM months are append-only');
END;
CREATE TRIGGER settlement_ttm_months_no_delete BEFORE DELETE ON settlement_ttm_months BEGIN
    SELECT RAISE(ABORT, 'settlement TTM months are append-only');
END;
CREATE TRIGGER settlement_weight_sources_no_update BEFORE UPDATE ON settlement_weight_sources BEGIN
    SELECT RAISE(ABORT, 'settlement weight sources are append-only');
END;
CREATE TRIGGER settlement_weight_sources_no_delete BEFORE DELETE ON settlement_weight_sources BEGIN
    SELECT RAISE(ABORT, 'settlement weight sources are append-only');
END;
CREATE TRIGGER settlement_beneficiary_deployments_no_update BEFORE UPDATE ON settlement_beneficiary_deployments BEGIN
    SELECT RAISE(ABORT, 'settlement beneficiary deployments are append-only');
END;
CREATE TRIGGER settlement_beneficiary_deployments_no_delete BEFORE DELETE ON settlement_beneficiary_deployments BEGIN
    SELECT RAISE(ABORT, 'settlement beneficiary deployments are append-only');
END;
CREATE TRIGGER settlement_allocations_no_update BEFORE UPDATE ON settlement_allocations BEGIN
    SELECT RAISE(ABORT, 'settlement allocations are append-only');
END;
CREATE TRIGGER settlement_allocations_no_delete BEFORE DELETE ON settlement_allocations BEGIN
    SELECT RAISE(ABORT, 'settlement allocations are append-only');
END;
