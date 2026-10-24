-- Every accepted ledger entry receives a directly-written accounting row.
-- This is part of the ledger write transaction, not an asynchronously rebuilt
-- projection. Existing protocol-v1 installation rows are backfilled once.
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

INSERT INTO ledger_weight_rows (
    ledger_index,
    deployment_id,
    period,
    ruleset_version,
    qualified_mau_count,
    weight_numerator,
    weight_denominator,
    accepted_at,
    source_entry_hash
)
SELECT
    ledger_index,
    deployment_id,
    period,
    ruleset_version,
    qualified_mau_count,
    qualified_mau_count,
    1,
    accepted_at,
    entry_hash
FROM ledger_entries;

CREATE INDEX ledger_weight_rows_period_deployment_idx
    ON ledger_weight_rows (period, deployment_id, ledger_index);
CREATE INDEX ledger_weight_rows_deployment_period_idx
    ON ledger_weight_rows (deployment_id, period, ledger_index);

CREATE TABLE operator_audit_events (
    audit_index             INTEGER PRIMARY KEY CHECK (audit_index > 0),
    action_id               TEXT NOT NULL UNIQUE,
    deployment_id           TEXT NOT NULL REFERENCES deployments(deployment_id),
    subject_deployment_id   TEXT NOT NULL REFERENCES deployments(deployment_id),
    related_deployment_id   TEXT NOT NULL DEFAULT '',
    action_type             TEXT NOT NULL CHECK (action_type IN (
        'claim',
        'withdraw-claim',
        'issue-client-token',
        'revoke-client-token',
        'redeem-client-token',
        'revoke-group-link',
        'deactivate-deployment',
        'reactivate-deployment'
    )),
    request_timestamp       TEXT NOT NULL,
    request_nonce           TEXT NOT NULL,
    idempotency_key         TEXT NOT NULL,
    payload_hash            TEXT NOT NULL,
    request_hash            TEXT NOT NULL,
    deployment_signature    BLOB NOT NULL CHECK (length(deployment_signature) = 64),
    operator_name           TEXT NOT NULL DEFAULT '',
    operator_avatar_url     TEXT NOT NULL DEFAULT '',
    claim_state             TEXT NOT NULL DEFAULT '',
    group_id                TEXT NOT NULL DEFAULT '',
    link_id                 TEXT NOT NULL DEFAULT '',
    token_id                TEXT NOT NULL DEFAULT '',
    client_token_hash       TEXT NOT NULL DEFAULT '',
    token_ttl_seconds       INTEGER NOT NULL DEFAULT 0 CHECK (token_ttl_seconds >= 0),
    token_expires_at        TEXT NOT NULL DEFAULT '',
    accepted_at             TEXT NOT NULL,
    previous_audit_hash     TEXT NOT NULL,
    audit_hash              TEXT NOT NULL UNIQUE,
    registry_key_id         TEXT NOT NULL,
    receipt_signature       BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (deployment_id, request_nonce),
    UNIQUE (deployment_id, idempotency_key)
);

CREATE INDEX operator_audit_events_action_idx
    ON operator_audit_events (action_type, audit_index);
CREATE INDEX operator_audit_events_deployment_idx
    ON operator_audit_events (deployment_id, audit_index);
CREATE INDEX operator_audit_events_group_idx
    ON operator_audit_events (group_id, audit_index);
CREATE INDEX operator_audit_events_token_hash_idx
    ON operator_audit_events (client_token_hash, action_type, audit_index);
CREATE INDEX operator_audit_events_token_id_idx
    ON operator_audit_events (token_id, audit_index);

-- A repeated idempotent request may use a fresh nonce while returning the
-- original action receipt. Keep every accepted nonce so it cannot later be
-- replayed for a different request.
CREATE TABLE operator_action_nonces (
    deployment_id   TEXT NOT NULL REFERENCES deployments(deployment_id),
    request_nonce   TEXT NOT NULL,
    request_hash    TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    request_timestamp TEXT NOT NULL,
    deployment_signature BLOB NOT NULL CHECK (length(deployment_signature) = 64),
    action_id       TEXT NOT NULL REFERENCES operator_audit_events(action_id),
    accepted_at     TEXT NOT NULL,
    PRIMARY KEY (deployment_id, request_nonce)
);

CREATE INDEX operator_action_nonces_action_idx
    ON operator_action_nonces (action_id);

CREATE TRIGGER ledger_weight_rows_no_update
BEFORE UPDATE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;
CREATE TRIGGER ledger_weight_rows_no_delete
BEFORE DELETE ON ledger_weight_rows BEGIN
    SELECT RAISE(ABORT, 'ledger weight rows are append-only');
END;

CREATE TRIGGER operator_audit_events_no_update
BEFORE UPDATE ON operator_audit_events BEGIN
    SELECT RAISE(ABORT, 'operator audit events are append-only');
END;
CREATE TRIGGER operator_audit_events_no_delete
BEFORE DELETE ON operator_audit_events BEGIN
    SELECT RAISE(ABORT, 'operator audit events are append-only');
END;

CREATE TRIGGER operator_action_nonces_no_update
BEFORE UPDATE ON operator_action_nonces BEGIN
    SELECT RAISE(ABORT, 'operator action nonces are append-only');
END;
CREATE TRIGGER operator_action_nonces_no_delete
BEFORE DELETE ON operator_action_nonces BEGIN
    SELECT RAISE(ABORT, 'operator action nonces are append-only');
END;
