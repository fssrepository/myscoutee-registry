-- Ownership transfer is a registry-local, non-payment rail. A prepared
-- transfer pins one exact approved/eligible claim generation and one verified
-- exit-review decision. Manager decisions form an immutable signed chain.
-- Completion never rewrites the source claim or eligibility rows: it appends
-- one effective-dated membership boundary that read paths can apply at an
-- explicitly pinned transfer-event boundary.
CREATE TABLE ownership_transfers (
    transfer_id                    TEXT PRIMARY KEY,
    ruleset_version                TEXT NOT NULL
        CHECK (ruleset_version = 'ownership-transfer-v1'),
    exit_review_id                 TEXT NOT NULL REFERENCES exit_reviews(review_id),
    target_deployment_id           TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id                TEXT NOT NULL
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    source_group_id                TEXT NOT NULL,
    target_group_id                TEXT NOT NULL,
    legal_name                     TEXT NOT NULL,
    exit_record_hash               TEXT NOT NULL REFERENCES exit_reviews(record_hash),
    exit_verification_event_index  INTEGER NOT NULL
        REFERENCES exit_review_events(event_index),
    exit_verification_event_hash   TEXT NOT NULL
        REFERENCES exit_review_events(event_hash),
    exit_evidence_hash             TEXT NOT NULL,
    prepared_at                    TEXT NOT NULL,
    record_hash                    TEXT NOT NULL UNIQUE,
    registry_scope                 TEXT NOT NULL,
    registry_key_id                TEXT NOT NULL,
    CHECK (source_group_id <> target_group_id)
);

CREATE INDEX ownership_transfers_claim_idx
    ON ownership_transfers (
        target_deployment_id,
        claim_action_id,
        prepared_at,
        transfer_id
    );
CREATE INDEX ownership_transfers_target_group_idx
    ON ownership_transfers (target_group_id, prepared_at, transfer_id);

CREATE TABLE ownership_transfer_events (
    event_index                  INTEGER PRIMARY KEY CHECK (event_index > 0),
    event_id                     TEXT NOT NULL UNIQUE,
    transfer_id                  TEXT NOT NULL REFERENCES ownership_transfers(transfer_id),
    action                       TEXT NOT NULL CHECK (action IN (
        'prepare',
        'approve',
        'reject',
        'cancel',
        'complete'
    )),
    resulting_status             TEXT NOT NULL CHECK (resulting_status IN (
        'prepared',
        'approved',
        'rejected',
        'cancelled',
        'completed'
    )),
    effective_date               TEXT NOT NULL,
    actor_role                   TEXT NOT NULL CHECK (actor_role IN (
        'requester',
        'registry-manager'
    )),
    actor_id                     TEXT NOT NULL,
    reference                    TEXT NOT NULL,
    evidence_hash                TEXT NOT NULL,
    reason_code                  TEXT NOT NULL DEFAULT '',
    idempotency_key              TEXT NOT NULL UNIQUE,
    payload_hash                 TEXT NOT NULL,
    record_hash                  TEXT NOT NULL REFERENCES ownership_transfers(record_hash),
    accepted_at                  TEXT NOT NULL,
    previous_event_hash          TEXT NOT NULL,
    previous_transfer_event_hash TEXT NOT NULL,
    event_hash                   TEXT NOT NULL UNIQUE,
    registry_scope               TEXT NOT NULL,
    registry_key_id              TEXT NOT NULL,
    signature                    BLOB NOT NULL CHECK (length(signature) = 64),
    CHECK (
        (
            action = 'prepare'
            AND resulting_status = 'prepared'
            AND actor_role = 'requester'
            AND reason_code = ''
        )
        OR
        (
            action = 'approve'
            AND resulting_status = 'approved'
            AND actor_role = 'registry-manager'
            AND reason_code = ''
        )
        OR
        (
            action = 'reject'
            AND resulting_status = 'rejected'
            AND actor_role = 'registry-manager'
            AND length(reason_code) BETWEEN 3 AND 64
        )
        OR
        (
            action = 'cancel'
            AND resulting_status = 'cancelled'
            AND actor_role = 'registry-manager'
            AND length(reason_code) BETWEEN 3 AND 64
        )
        OR
        (
            action = 'complete'
            AND resulting_status = 'completed'
            AND actor_role = 'registry-manager'
            AND reason_code = ''
        )
    )
);

CREATE INDEX ownership_transfer_events_transfer_idx
    ON ownership_transfer_events (transfer_id, event_index);

-- One directly written immutable state row accompanies every event. Reads
-- select the latest row; they never replay the event chain while serving.
CREATE TABLE ownership_transfer_state_rows (
    event_index                    INTEGER PRIMARY KEY
        REFERENCES ownership_transfer_events(event_index),
    event_hash                     TEXT NOT NULL UNIQUE
        REFERENCES ownership_transfer_events(event_hash),
    transfer_id                    TEXT NOT NULL REFERENCES ownership_transfers(transfer_id),
    status                         TEXT NOT NULL CHECK (status IN (
        'prepared',
        'approved',
        'rejected',
        'cancelled',
        'completed'
    )),
    target_deployment_id           TEXT NOT NULL,
    claim_action_id                TEXT NOT NULL,
    source_group_id                TEXT NOT NULL,
    target_group_id                TEXT NOT NULL,
    legal_name                     TEXT NOT NULL,
    exit_review_id                 TEXT NOT NULL,
    exit_record_hash               TEXT NOT NULL,
    exit_verification_event_index  INTEGER NOT NULL,
    exit_verification_event_hash   TEXT NOT NULL,
    exit_evidence_hash             TEXT NOT NULL,
    record_hash                    TEXT NOT NULL,
    latest_action                  TEXT NOT NULL,
    latest_effective_date          TEXT NOT NULL,
    latest_actor_role              TEXT NOT NULL,
    latest_actor_id                TEXT NOT NULL,
    latest_reference               TEXT NOT NULL,
    latest_evidence_hash           TEXT NOT NULL,
    latest_reason_code             TEXT NOT NULL,
    latest_accepted_at             TEXT NOT NULL
);

CREATE INDEX ownership_transfer_state_status_event_idx
    ON ownership_transfer_state_rows (status, event_index DESC);
CREATE INDEX ownership_transfer_state_transfer_event_idx
    ON ownership_transfer_state_rows (transfer_id, event_index DESC);
CREATE INDEX ownership_transfer_state_claim_event_idx
    ON ownership_transfer_state_rows (
        target_deployment_id,
        claim_action_id,
        event_index DESC
    );

-- Completion writes exactly one historical membership boundary. The pinned
-- operator-audit head gives deterministic precedence: a later deployment
-- claim/link action supersedes this transfer without altering either history.
CREATE TABLE ownership_transfer_memberships (
    transfer_id          TEXT PRIMARY KEY REFERENCES ownership_transfers(transfer_id),
    completion_event_index INTEGER NOT NULL UNIQUE
        REFERENCES ownership_transfer_events(event_index),
    completion_event_hash TEXT NOT NULL UNIQUE
        REFERENCES ownership_transfer_events(event_hash),
    target_deployment_id TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id      TEXT NOT NULL,
    source_group_id      TEXT NOT NULL,
    target_group_id      TEXT NOT NULL,
    effective_date       TEXT NOT NULL,
    through_audit_index  INTEGER NOT NULL CHECK (through_audit_index >= 0),
    audit_head_hash      TEXT NOT NULL,
    completed_at         TEXT NOT NULL,
    membership_hash      TEXT NOT NULL UNIQUE,
    CHECK (source_group_id <> target_group_id)
);

CREATE INDEX ownership_transfer_membership_deployment_idx
    ON ownership_transfer_memberships (
        target_deployment_id,
        completion_event_index DESC
    );
CREATE INDEX ownership_transfer_membership_target_group_idx
    ON ownership_transfer_memberships (
        target_group_id,
        completion_event_index DESC
    );

CREATE TRIGGER ownership_transfers_no_update
BEFORE UPDATE ON ownership_transfers BEGIN
    SELECT RAISE(ABORT, 'ownership transfer records are append-only');
END;
CREATE TRIGGER ownership_transfers_no_delete
BEFORE DELETE ON ownership_transfers BEGIN
    SELECT RAISE(ABORT, 'ownership transfer records are append-only');
END;
CREATE TRIGGER ownership_transfer_events_no_update
BEFORE UPDATE ON ownership_transfer_events BEGIN
    SELECT RAISE(ABORT, 'ownership transfer events are append-only');
END;
CREATE TRIGGER ownership_transfer_events_no_delete
BEFORE DELETE ON ownership_transfer_events BEGIN
    SELECT RAISE(ABORT, 'ownership transfer events are append-only');
END;
CREATE TRIGGER ownership_transfer_state_rows_no_update
BEFORE UPDATE ON ownership_transfer_state_rows BEGIN
    SELECT RAISE(ABORT, 'ownership transfer query rows are append-only');
END;
CREATE TRIGGER ownership_transfer_state_rows_no_delete
BEFORE DELETE ON ownership_transfer_state_rows BEGIN
    SELECT RAISE(ABORT, 'ownership transfer query rows are append-only');
END;
CREATE TRIGGER ownership_transfer_memberships_no_update
BEFORE UPDATE ON ownership_transfer_memberships BEGIN
    SELECT RAISE(ABORT, 'ownership transfer memberships are append-only');
END;
CREATE TRIGGER ownership_transfer_memberships_no_delete
BEFORE DELETE ON ownership_transfer_memberships BEGIN
    SELECT RAISE(ABORT, 'ownership transfer memberships are append-only');
END;
