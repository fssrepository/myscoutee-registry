-- Revenue batches share the authoritative registry ledger with installation
-- batches. Rebuild the three ledger-related tables so existing v1 hashes and
-- rows remain byte-for-byte unchanged while the constraints admit the new
-- append-only revenue entry type.
DROP TRIGGER ledger_weight_rows_no_update;
DROP TRIGGER ledger_weight_rows_no_delete;
DROP TRIGGER mau_batches_no_update;
DROP TRIGGER mau_batches_no_delete;
DROP TRIGGER ledger_entries_no_update;
DROP TRIGGER ledger_entries_no_delete;

ALTER TABLE ledger_weight_rows RENAME TO ledger_weight_rows_v1;
ALTER TABLE mau_batches RENAME TO mau_batches_v1;
ALTER TABLE ledger_entries RENAME TO ledger_entries_v1;

CREATE TABLE ledger_entries (
    ledger_index         INTEGER PRIMARY KEY CHECK (ledger_index > 0),
    protocol_version     TEXT NOT NULL CHECK (protocol_version = '1'),
    registry_scope       TEXT NOT NULL,
    entry_type           TEXT NOT NULL CHECK (entry_type IN (
        'INSTALLATION_TEST_BATCH_ACCEPTED',
        'REVENUE_BATCH_ACCEPTED'
    )),
    deployment_id        TEXT NOT NULL REFERENCES deployments(deployment_id),
    batch_id             TEXT NOT NULL UNIQUE,
    kind                 TEXT NOT NULL CHECK (kind IN (
        'installation-test',
        'daily-revenue'
    )),
    period               TEXT NOT NULL,
    ruleset_version      TEXT NOT NULL CHECK (ruleset_version IN (
        'installation-test-v1',
        'net-captured-revenue-v1'
    )),
    qualified_mau_count  INTEGER NOT NULL CHECK (qualified_mau_count = 0),
    batch_hash           TEXT NOT NULL,
    previous_entry_hash  TEXT NOT NULL,
    entry_hash           TEXT NOT NULL UNIQUE,
    accepted_at          TEXT NOT NULL,
    CHECK (
        (
            entry_type = 'INSTALLATION_TEST_BATCH_ACCEPTED'
            AND kind = 'installation-test'
            AND ruleset_version = 'installation-test-v1'
        )
        OR
        (
            entry_type = 'REVENUE_BATCH_ACCEPTED'
            AND kind = 'daily-revenue'
            AND ruleset_version = 'net-captured-revenue-v1'
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
    kind                        TEXT NOT NULL CHECK (kind = 'installation-test'),
    period                      TEXT NOT NULL,
    ruleset_version             TEXT NOT NULL CHECK (ruleset_version = 'installation-test-v1'),
    qualified_mau_count         INTEGER NOT NULL CHECK (qualified_mau_count = 0),
    commitment_hash             TEXT NOT NULL,
    payload_hash                TEXT NOT NULL,
    accepted_at                 TEXT NOT NULL,
    ledger_index                INTEGER NOT NULL UNIQUE REFERENCES ledger_entries(ledger_index),
    receipt_signature           BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (deployment_id, idempotency_key)
);

CREATE TABLE ledger_weight_rows (
    ledger_index          INTEGER PRIMARY KEY REFERENCES ledger_entries(ledger_index),
    deployment_id         TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                TEXT NOT NULL,
    ruleset_version       TEXT NOT NULL,
    qualified_mau_count   INTEGER NOT NULL CHECK (qualified_mau_count >= 0),
    weight_numerator      INTEGER NOT NULL CHECK (weight_numerator >= 0),
    weight_denominator    INTEGER NOT NULL CHECK (weight_denominator > 0),
    accepted_at           TEXT NOT NULL,
    source_entry_hash     TEXT NOT NULL UNIQUE
);

INSERT INTO ledger_entries
SELECT * FROM ledger_entries_v1 ORDER BY ledger_index;

INSERT INTO mau_batches
SELECT * FROM mau_batches_v1;

INSERT INTO ledger_weight_rows
SELECT * FROM ledger_weight_rows_v1;

DROP TABLE ledger_weight_rows_v1;
DROP TABLE mau_batches_v1;
DROP TABLE ledger_entries_v1;

CREATE INDEX ledger_entries_accepted_at_idx
    ON ledger_entries (accepted_at, ledger_index);
CREATE INDEX ledger_weight_rows_period_deployment_idx
    ON ledger_weight_rows (period, deployment_id, ledger_index);
CREATE INDEX ledger_weight_rows_deployment_period_idx
    ON ledger_weight_rows (deployment_id, period, ledger_index);

CREATE TRIGGER ledger_entries_no_update
BEFORE UPDATE ON ledger_entries BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only');
END;
CREATE TRIGGER ledger_entries_no_delete
BEFORE DELETE ON ledger_entries BEGIN
    SELECT RAISE(ABORT, 'ledger entries are append-only');
END;

CREATE TRIGGER mau_batches_no_update
BEFORE UPDATE ON mau_batches BEGIN
    SELECT RAISE(ABORT, 'MAU batches are append-only');
END;
CREATE TRIGGER mau_batches_no_delete
BEFORE DELETE ON mau_batches BEGIN
    SELECT RAISE(ABORT, 'MAU batches are append-only');
END;

CREATE TRIGGER ledger_weight_rows_no_update
BEFORE UPDATE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;
CREATE TRIGGER ledger_weight_rows_no_delete
BEFORE DELETE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;

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
        OR
        (revision > 1 AND supersedes_batch_id IS NOT NULL)
    )
);

CREATE INDEX revenue_batches_period_deployment_revision_idx
    ON revenue_batches (period, deployment_id, revision DESC);
CREATE INDEX revenue_batches_supersedes_idx
    ON revenue_batches (supersedes_batch_id);

-- These are directly written in the same transaction as the ledger entry and
-- source batch. They are immutable query rows, not an asynchronously rebuilt
-- projection.
CREATE TABLE revenue_query_rows (
    batch_id                       TEXT NOT NULL REFERENCES revenue_batches(batch_id),
    currency_index                 INTEGER NOT NULL CHECK (currency_index >= 0),
    ledger_index                   INTEGER NOT NULL REFERENCES ledger_entries(ledger_index),
    deployment_id                  TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                         TEXT NOT NULL,
    revision                       INTEGER NOT NULL CHECK (revision >= 1),
    supersedes_batch_id            TEXT NOT NULL DEFAULT '',
    currency_code                  TEXT NOT NULL CHECK (
        length(currency_code) = 3
        AND currency_code = upper(currency_code)
    ),
    fraction_digits                INTEGER NOT NULL CHECK (fraction_digits BETWEEN 0 AND 4),
    captured_minor                 INTEGER NOT NULL CHECK (captured_minor >= 0),
    refunded_minor                 INTEGER NOT NULL CHECK (
        refunded_minor >= 0 AND refunded_minor <= captured_minor
    ),
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

CREATE INDEX revenue_query_period_currency_deployment_idx
    ON revenue_query_rows (period, currency_code, deployment_id, revision DESC);
CREATE INDEX revenue_query_deployment_period_currency_idx
    ON revenue_query_rows (deployment_id, period, currency_code, revision DESC);
CREATE INDEX revenue_query_ledger_idx
    ON revenue_query_rows (ledger_index);

CREATE TRIGGER revenue_batches_no_update
BEFORE UPDATE ON revenue_batches BEGIN
    SELECT RAISE(ABORT, 'revenue batches are append-only');
END;
CREATE TRIGGER revenue_batches_no_delete
BEFORE DELETE ON revenue_batches BEGIN
    SELECT RAISE(ABORT, 'revenue batches are append-only');
END;

CREATE TRIGGER revenue_query_rows_no_update
BEFORE UPDATE ON revenue_query_rows BEGIN
    SELECT RAISE(ABORT, 'revenue query rows are append-only');
END;
CREATE TRIGGER revenue_query_rows_no_delete
BEFORE DELETE ON revenue_query_rows BEGIN
    SELECT RAISE(ABORT, 'revenue query rows are append-only');
END;
