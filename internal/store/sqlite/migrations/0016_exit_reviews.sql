-- Exit review is a registry-local, non-payment audit rail. A freeze commits to
-- one completed UTC checkpoint plus exact operator/claim/eligibility,
-- deployment-membership, Merkle, and settlement boundaries. Buyer/auditor
-- decisions extend a separately signed global event chain. Query state is
-- appended in the same transaction as each event; it is never projected or
-- repaired while serving reads.
CREATE TABLE exit_reviews (
    review_id                         TEXT PRIMARY KEY,
    ruleset_version                   TEXT NOT NULL CHECK (ruleset_version = 'exit-review-v1'),
    record_date                       TEXT NOT NULL,
    target_deployment_id              TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id                   TEXT NOT NULL
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    group_id                          TEXT NOT NULL,
    legal_name                        TEXT NOT NULL,
    checkpoint_hash                   TEXT NOT NULL,
    through_ledger_index              INTEGER NOT NULL CHECK (through_ledger_index >= 0),
    ledger_head_hash                  TEXT NOT NULL,
    merkle_tree_size                  INTEGER NOT NULL CHECK (merkle_tree_size >= 0),
    merkle_root_hash                  TEXT NOT NULL,
    through_audit_index               INTEGER NOT NULL CHECK (through_audit_index >= 0),
    audit_head_hash                   TEXT NOT NULL,
    through_review_index              INTEGER NOT NULL CHECK (through_review_index >= 0),
    claim_review_head_hash            TEXT NOT NULL,
    through_eligibility_index         INTEGER NOT NULL CHECK (through_eligibility_index >= 0),
    eligibility_head_hash             TEXT NOT NULL,
    through_settlement_ledger_index   INTEGER NOT NULL CHECK (through_settlement_ledger_index >= 0),
    settlement_boundary_count         INTEGER NOT NULL CHECK (settlement_boundary_count >= 0),
    settlement_boundary_hash          TEXT NOT NULL,
    deployment_count                  INTEGER NOT NULL CHECK (deployment_count > 0),
    membership_hash                   TEXT NOT NULL,
    frozen_at                         TEXT NOT NULL,
    record_hash                       TEXT NOT NULL UNIQUE,
    registry_scope                    TEXT NOT NULL,
    registry_key_id                   TEXT NOT NULL,
    UNIQUE (target_deployment_id, claim_action_id)
);

CREATE INDEX exit_reviews_record_group_idx
    ON exit_reviews (record_date DESC, group_id, review_id);

CREATE TABLE exit_review_deployments (
    review_id          TEXT NOT NULL REFERENCES exit_reviews(review_id),
    member_order       INTEGER NOT NULL CHECK (member_order >= 0),
    deployment_id      TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id    TEXT NOT NULL
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    claim_audit_index  INTEGER NOT NULL CHECK (claim_audit_index > 0),
    claim_audit_hash   TEXT NOT NULL,
    review_index       INTEGER NOT NULL CHECK (review_index >= 0),
    review_hash        TEXT NOT NULL,
    eligibility_index INTEGER NOT NULL CHECK (eligibility_index >= 0),
    eligibility_hash  TEXT NOT NULL,
    PRIMARY KEY (review_id, member_order),
    UNIQUE (review_id, deployment_id),
    UNIQUE (review_id, claim_action_id)
);

CREATE TABLE exit_review_settlement_boundaries (
    review_id           TEXT NOT NULL REFERENCES exit_reviews(review_id),
    boundary_order      INTEGER NOT NULL CHECK (boundary_order >= 0),
    settlement_id       TEXT NOT NULL REFERENCES settlements(settlement_id),
    period              TEXT NOT NULL,
    currency_code       TEXT NOT NULL CHECK (
        length(currency_code) = 3 AND currency_code = upper(currency_code)
    ),
    revision            INTEGER NOT NULL CHECK (revision > 0),
    ledger_index        INTEGER NOT NULL REFERENCES ledger_entries(ledger_index),
    settlement_hash     TEXT NOT NULL,
    source_fingerprint  TEXT NOT NULL,
    allocation_hash     TEXT NOT NULL,
    PRIMARY KEY (review_id, boundary_order),
    UNIQUE (review_id, period, currency_code),
    UNIQUE (review_id, settlement_id)
);

CREATE TABLE exit_review_events (
    event_index                INTEGER PRIMARY KEY CHECK (event_index > 0),
    event_id                   TEXT NOT NULL UNIQUE,
    review_id                  TEXT NOT NULL REFERENCES exit_reviews(review_id),
    action                     TEXT NOT NULL CHECK (action IN (
        'freeze',
        'verify',
        'reject',
        'dispute',
        'withdraw'
    )),
    resulting_status           TEXT NOT NULL CHECK (resulting_status IN (
        'review-pending',
        'verified-eligible',
        'rejected',
        'disputed',
        'withdrawn'
    )),
    effective_date             TEXT NOT NULL,
    actor_role                 TEXT NOT NULL CHECK (actor_role IN ('buyer', 'auditor')),
    actor_id                   TEXT NOT NULL,
    reference                  TEXT NOT NULL,
    evidence_hash              TEXT NOT NULL,
    reason_code                TEXT NOT NULL DEFAULT '',
    idempotency_key            TEXT NOT NULL UNIQUE,
    payload_hash               TEXT NOT NULL,
    record_hash                TEXT NOT NULL REFERENCES exit_reviews(record_hash),
    accepted_at                TEXT NOT NULL,
    previous_event_hash        TEXT NOT NULL,
    previous_review_event_hash TEXT NOT NULL,
    event_hash                 TEXT NOT NULL UNIQUE,
    registry_scope             TEXT NOT NULL,
    registry_key_id            TEXT NOT NULL,
    signature                  BLOB NOT NULL CHECK (length(signature) = 64),
    CHECK (
        (action = 'freeze' AND resulting_status = 'review-pending' AND reason_code = '')
        OR
        (action = 'verify' AND resulting_status = 'verified-eligible' AND reason_code = '')
        OR
        (action = 'reject' AND resulting_status = 'rejected' AND length(reason_code) BETWEEN 3 AND 64)
        OR
        (action = 'dispute' AND resulting_status = 'disputed' AND length(reason_code) BETWEEN 3 AND 64)
        OR
        (action = 'withdraw' AND resulting_status = 'withdrawn' AND length(reason_code) BETWEEN 3 AND 64)
    )
);

CREATE INDEX exit_review_events_review_idx
    ON exit_review_events (review_id, event_index);

CREATE TABLE exit_review_state_rows (
    event_index            INTEGER PRIMARY KEY REFERENCES exit_review_events(event_index),
    event_hash             TEXT NOT NULL UNIQUE REFERENCES exit_review_events(event_hash),
    review_id              TEXT NOT NULL REFERENCES exit_reviews(review_id),
    status                 TEXT NOT NULL CHECK (status IN (
        'review-pending',
        'verified-eligible',
        'rejected',
        'disputed',
        'withdrawn'
    )),
    record_date            TEXT NOT NULL,
    target_deployment_id   TEXT NOT NULL,
    claim_action_id        TEXT NOT NULL,
    group_id               TEXT NOT NULL,
    legal_name             TEXT NOT NULL,
    record_hash            TEXT NOT NULL,
    latest_action          TEXT NOT NULL,
    latest_effective_date  TEXT NOT NULL,
    latest_actor_role      TEXT NOT NULL,
    latest_actor_id        TEXT NOT NULL,
    latest_reference       TEXT NOT NULL,
    latest_evidence_hash   TEXT NOT NULL,
    latest_reason_code     TEXT NOT NULL,
    latest_accepted_at     TEXT NOT NULL
);

CREATE INDEX exit_review_state_status_event_idx
    ON exit_review_state_rows (status, event_index DESC);
CREATE INDEX exit_review_state_review_event_idx
    ON exit_review_state_rows (review_id, event_index DESC);

CREATE TRIGGER exit_reviews_no_update
BEFORE UPDATE ON exit_reviews BEGIN
    SELECT RAISE(ABORT, 'exit review records are append-only');
END;
CREATE TRIGGER exit_reviews_no_delete
BEFORE DELETE ON exit_reviews BEGIN
    SELECT RAISE(ABORT, 'exit review records are append-only');
END;
CREATE TRIGGER exit_review_deployments_no_update
BEFORE UPDATE ON exit_review_deployments BEGIN
    SELECT RAISE(ABORT, 'exit review deployment rows are append-only');
END;
CREATE TRIGGER exit_review_deployments_no_delete
BEFORE DELETE ON exit_review_deployments BEGIN
    SELECT RAISE(ABORT, 'exit review deployment rows are append-only');
END;
CREATE TRIGGER exit_review_settlement_boundaries_no_update
BEFORE UPDATE ON exit_review_settlement_boundaries BEGIN
    SELECT RAISE(ABORT, 'exit review settlement boundaries are append-only');
END;
CREATE TRIGGER exit_review_settlement_boundaries_no_delete
BEFORE DELETE ON exit_review_settlement_boundaries BEGIN
    SELECT RAISE(ABORT, 'exit review settlement boundaries are append-only');
END;
CREATE TRIGGER exit_review_events_no_update
BEFORE UPDATE ON exit_review_events BEGIN
    SELECT RAISE(ABORT, 'exit review events are append-only');
END;
CREATE TRIGGER exit_review_events_no_delete
BEFORE DELETE ON exit_review_events BEGIN
    SELECT RAISE(ABORT, 'exit review events are append-only');
END;
CREATE TRIGGER exit_review_state_rows_no_update
BEFORE UPDATE ON exit_review_state_rows BEGIN
    SELECT RAISE(ABORT, 'exit review query rows are append-only');
END;
CREATE TRIGGER exit_review_state_rows_no_delete
BEFORE DELETE ON exit_review_state_rows BEGIN
    SELECT RAISE(ABORT, 'exit review query rows are append-only');
END;
