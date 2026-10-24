-- Final exit allocations are registry-local contractual/audit records. They
-- pin immutable source revisions and integer minor-unit allocations, but never
-- contain payment execution, bank-account, tax, or invoicing data.
CREATE TABLE exit_allocations (
    allocation_id                           TEXT PRIMARY KEY,
    ruleset_version                         TEXT NOT NULL
        CHECK (ruleset_version = 'final-exit-allocation-v1'),
    exit_review_id                          TEXT NOT NULL UNIQUE
        REFERENCES exit_reviews(review_id),
    target_deployment_id                    TEXT NOT NULL
        REFERENCES deployments(deployment_id),
    claim_action_id                         TEXT NOT NULL
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    source_group_id                         TEXT NOT NULL,
    exit_record_hash                        TEXT NOT NULL
        REFERENCES exit_reviews(record_hash),
    exit_verification_event_index            INTEGER NOT NULL
        REFERENCES exit_review_events(event_index),
    exit_verification_event_hash             TEXT NOT NULL
        REFERENCES exit_review_events(event_hash),
    exit_evidence_hash                       TEXT NOT NULL,
    decision_mode                            TEXT NOT NULL CHECK (
        decision_mode IN ('completed-transfer', 'no-transfer')
    ),
    ownership_transfer_id                    TEXT NOT NULL DEFAULT '',
    ownership_transfer_completion_event_index INTEGER NOT NULL
        CHECK (ownership_transfer_completion_event_index >= 0),
    ownership_transfer_completion_event_hash TEXT NOT NULL,
    through_ownership_transfer_event_index    INTEGER NOT NULL
        CHECK (through_ownership_transfer_event_index >= 0),
    ownership_transfer_head_hash              TEXT NOT NULL,
    beneficiary_type                         TEXT NOT NULL CHECK (
        beneficiary_type IN ('OPERATOR_GROUP', 'CONTRACT_BENEFICIARY')
    ),
    beneficiary_id                           TEXT NOT NULL,
    contract_reference                       TEXT NOT NULL,
    contract_terms_hash                      TEXT NOT NULL,
    evidence_hash                            TEXT NOT NULL,
    settlement_source_count                  INTEGER NOT NULL
        CHECK (settlement_source_count >= 0),
    settlement_source_hash                   TEXT NOT NULL,
    currency_allocation_count                INTEGER NOT NULL
        CHECK (currency_allocation_count >= 0),
    currency_allocation_hash                 TEXT NOT NULL,
    created_at                               TEXT NOT NULL,
    record_hash                              TEXT NOT NULL UNIQUE,
    registry_scope                           TEXT NOT NULL,
    registry_key_id                          TEXT NOT NULL,
    CHECK (
        (
            decision_mode = 'completed-transfer'
            AND ownership_transfer_id <> ''
            AND ownership_transfer_completion_event_index > 0
            AND beneficiary_type = 'OPERATOR_GROUP'
        )
        OR
        (
            decision_mode = 'no-transfer'
            AND ownership_transfer_id = ''
            AND ownership_transfer_completion_event_index = 0
            AND beneficiary_type = 'CONTRACT_BENEFICIARY'
        )
    )
);

CREATE INDEX exit_allocations_claim_idx
    ON exit_allocations (
        target_deployment_id,
        claim_action_id,
        created_at,
        allocation_id
    );
CREATE INDEX exit_allocations_beneficiary_idx
    ON exit_allocations (
        beneficiary_type,
        beneficiary_id,
        created_at,
        allocation_id
    );

-- Every row exactly copies one revision from the exit review's frozen
-- settlement boundary and adds the exiting group's distributable amount.
CREATE TABLE exit_allocation_settlement_sources (
    allocation_id              TEXT NOT NULL
        REFERENCES exit_allocations(allocation_id),
    boundary_order             INTEGER NOT NULL CHECK (boundary_order >= 0),
    settlement_id              TEXT NOT NULL REFERENCES settlements(settlement_id),
    period                     TEXT NOT NULL,
    currency_code              TEXT NOT NULL,
    fraction_digits            INTEGER NOT NULL
        CHECK (fraction_digits BETWEEN 0 AND 9),
    revision                   INTEGER NOT NULL CHECK (revision >= 1),
    ledger_index               INTEGER NOT NULL CHECK (ledger_index > 0),
    settlement_hash            TEXT NOT NULL,
    source_fingerprint         TEXT NOT NULL,
    settlement_allocation_hash TEXT NOT NULL,
    distributable_minor        INTEGER NOT NULL CHECK (
        distributable_minor BETWEEN 0 AND 9007199254740991
    ),
    PRIMARY KEY (allocation_id, boundary_order),
    UNIQUE (allocation_id, settlement_id)
);

CREATE INDEX exit_allocation_source_currency_idx
    ON exit_allocation_settlement_sources (
        allocation_id,
        currency_code,
        boundary_order
    );

-- V1 records one beneficiary for the whole exit. Exact equality is enforced in
-- SQLite as well as recomputed by the full verifier, independently per ISO
-- currency.
CREATE TABLE exit_allocation_currency_allocations (
    allocation_id       TEXT NOT NULL REFERENCES exit_allocations(allocation_id),
    allocation_order    INTEGER NOT NULL CHECK (allocation_order >= 0),
    currency_code       TEXT NOT NULL,
    fraction_digits     INTEGER NOT NULL CHECK (fraction_digits BETWEEN 0 AND 9),
    distributable_minor INTEGER NOT NULL CHECK (
        distributable_minor BETWEEN 0 AND 9007199254740991
    ),
    allocated_minor     INTEGER NOT NULL CHECK (
        allocated_minor BETWEEN 0 AND 9007199254740991
    ),
    beneficiary_type    TEXT NOT NULL CHECK (
        beneficiary_type IN ('OPERATOR_GROUP', 'CONTRACT_BENEFICIARY')
    ),
    beneficiary_id      TEXT NOT NULL,
    PRIMARY KEY (allocation_id, allocation_order),
    UNIQUE (allocation_id, currency_code),
    CHECK (allocated_minor = distributable_minor)
);

CREATE TABLE exit_allocation_events (
    event_index                   INTEGER PRIMARY KEY CHECK (event_index > 0),
    event_id                      TEXT NOT NULL UNIQUE,
    allocation_id                 TEXT NOT NULL
        REFERENCES exit_allocations(allocation_id),
    action                        TEXT NOT NULL CHECK (action IN ('create', 'verify')),
    resulting_status              TEXT NOT NULL CHECK (
        resulting_status IN ('recorded', 'verified-final')
    ),
    actor_role                    TEXT NOT NULL CHECK (
        actor_role IN ('allocator', 'registry-verifier')
    ),
    actor_id                      TEXT NOT NULL,
    reference                     TEXT NOT NULL,
    evidence_hash                 TEXT NOT NULL,
    idempotency_key               TEXT NOT NULL UNIQUE,
    payload_hash                  TEXT NOT NULL,
    record_hash                   TEXT NOT NULL
        REFERENCES exit_allocations(record_hash),
    accepted_at                   TEXT NOT NULL,
    previous_event_hash           TEXT NOT NULL,
    previous_allocation_event_hash TEXT NOT NULL,
    event_hash                    TEXT NOT NULL UNIQUE,
    registry_scope                TEXT NOT NULL,
    registry_key_id               TEXT NOT NULL,
    signature                     BLOB NOT NULL CHECK (length(signature) = 64),
    CHECK (
        (
            action = 'create'
            AND resulting_status = 'recorded'
            AND actor_role = 'allocator'
        )
        OR
        (
            action = 'verify'
            AND resulting_status = 'verified-final'
            AND actor_role = 'registry-verifier'
        )
    )
);

CREATE INDEX exit_allocation_events_record_idx
    ON exit_allocation_events (allocation_id, event_index);

-- One immutable direct query row is written in the same transaction as every
-- event. Reads select the latest row rather than replaying the event history.
CREATE TABLE exit_allocation_state_rows (
    event_index               INTEGER PRIMARY KEY
        REFERENCES exit_allocation_events(event_index),
    event_hash                TEXT NOT NULL UNIQUE
        REFERENCES exit_allocation_events(event_hash),
    allocation_id             TEXT NOT NULL REFERENCES exit_allocations(allocation_id),
    status                    TEXT NOT NULL CHECK (
        status IN ('recorded', 'verified-final')
    ),
    decision_mode             TEXT NOT NULL CHECK (
        decision_mode IN ('completed-transfer', 'no-transfer')
    ),
    beneficiary_type          TEXT NOT NULL,
    beneficiary_id            TEXT NOT NULL,
    exit_review_id            TEXT NOT NULL,
    target_deployment_id      TEXT NOT NULL,
    claim_action_id           TEXT NOT NULL,
    source_group_id           TEXT NOT NULL,
    ownership_transfer_id     TEXT NOT NULL,
    settlement_source_count   INTEGER NOT NULL CHECK (settlement_source_count >= 0),
    settlement_source_hash    TEXT NOT NULL,
    currency_allocation_count INTEGER NOT NULL CHECK (currency_allocation_count >= 0),
    currency_allocation_hash  TEXT NOT NULL,
    record_hash               TEXT NOT NULL,
    latest_action             TEXT NOT NULL,
    latest_actor_role         TEXT NOT NULL,
    latest_actor_id           TEXT NOT NULL,
    latest_reference          TEXT NOT NULL,
    latest_evidence_hash      TEXT NOT NULL,
    latest_accepted_at        TEXT NOT NULL
);

CREATE INDEX exit_allocation_state_status_event_idx
    ON exit_allocation_state_rows (status, event_index DESC);
CREATE INDEX exit_allocation_state_decision_event_idx
    ON exit_allocation_state_rows (decision_mode, event_index DESC);
CREATE INDEX exit_allocation_state_record_event_idx
    ON exit_allocation_state_rows (allocation_id, event_index DESC);

CREATE TRIGGER exit_allocations_no_update
BEFORE UPDATE ON exit_allocations BEGIN
    SELECT RAISE(ABORT, 'final exit allocation records are append-only');
END;
CREATE TRIGGER exit_allocations_no_delete
BEFORE DELETE ON exit_allocations BEGIN
    SELECT RAISE(ABORT, 'final exit allocation records are append-only');
END;
CREATE TRIGGER exit_allocation_settlement_sources_no_update
BEFORE UPDATE ON exit_allocation_settlement_sources BEGIN
    SELECT RAISE(ABORT, 'final exit allocation sources are append-only');
END;
CREATE TRIGGER exit_allocation_settlement_sources_no_delete
BEFORE DELETE ON exit_allocation_settlement_sources BEGIN
    SELECT RAISE(ABORT, 'final exit allocation sources are append-only');
END;
CREATE TRIGGER exit_allocation_currency_allocations_no_update
BEFORE UPDATE ON exit_allocation_currency_allocations BEGIN
    SELECT RAISE(ABORT, 'final exit allocation currencies are append-only');
END;
CREATE TRIGGER exit_allocation_currency_allocations_no_delete
BEFORE DELETE ON exit_allocation_currency_allocations BEGIN
    SELECT RAISE(ABORT, 'final exit allocation currencies are append-only');
END;
CREATE TRIGGER exit_allocation_events_no_update
BEFORE UPDATE ON exit_allocation_events BEGIN
    SELECT RAISE(ABORT, 'final exit allocation events are append-only');
END;
CREATE TRIGGER exit_allocation_events_no_delete
BEFORE DELETE ON exit_allocation_events BEGIN
    SELECT RAISE(ABORT, 'final exit allocation events are append-only');
END;
CREATE TRIGGER exit_allocation_state_rows_no_update
BEFORE UPDATE ON exit_allocation_state_rows BEGIN
    SELECT RAISE(ABORT, 'final exit allocation query rows are append-only');
END;
CREATE TRIGGER exit_allocation_state_rows_no_delete
BEFORE DELETE ON exit_allocation_state_rows BEGIN
    SELECT RAISE(ABORT, 'final exit allocation query rows are append-only');
END;
