-- A registry administrator may temporarily suspend one exact, currently
-- approved claim generation and later reinstate that same generation. These
-- decisions are intentionally separate from company verification: suspension
-- does not rewrite an approval, move a deployment to the unclaimed list, or
-- discard measured QMAU weight.
CREATE TABLE operator_claim_eligibility_events (
    eligibility_index         INTEGER PRIMARY KEY CHECK (eligibility_index > 0),
    eligibility_id            TEXT NOT NULL UNIQUE,
    deployment_id             TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id           TEXT NOT NULL
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    group_id                  TEXT NOT NULL,
    legal_name                TEXT NOT NULL,
    decision                  TEXT NOT NULL CHECK (decision IN (
        'suspend',
        'reinstate'
    )),
    actor_id                  TEXT NOT NULL,
    decision_reference        TEXT NOT NULL,
    reason_code               TEXT NOT NULL DEFAULT '',
    idempotency_key           TEXT NOT NULL UNIQUE,
    decided_at                TEXT NOT NULL,
    previous_eligibility_hash TEXT NOT NULL,
    eligibility_hash          TEXT NOT NULL UNIQUE,
    registry_key_id           TEXT NOT NULL,
    signature                 BLOB NOT NULL CHECK (length(signature) = 64),
    CHECK (
        (
            decision = 'suspend'
            AND length(reason_code) BETWEEN 3 AND 64
        )
        OR
        (
            decision = 'reinstate'
            AND reason_code = ''
        )
    )
);

CREATE INDEX operator_claim_eligibility_deployment_idx
    ON operator_claim_eligibility_events (
        deployment_id,
        eligibility_index
    );
CREATE INDEX operator_claim_eligibility_claim_idx
    ON operator_claim_eligibility_events (
        claim_action_id,
        eligibility_index
    );

CREATE TRIGGER operator_claim_eligibility_events_no_update
BEFORE UPDATE ON operator_claim_eligibility_events BEGIN
    SELECT RAISE(ABORT, 'operator claim eligibility events are append-only');
END;
CREATE TRIGGER operator_claim_eligibility_events_no_delete
BEFORE DELETE ON operator_claim_eligibility_events BEGIN
    SELECT RAISE(ABORT, 'operator claim eligibility events are append-only');
END;

-- This is the directly maintained current query row. It is written in the same
-- transaction as approval/rejection, a new claim generation,
-- withdrawal/deactivation, or an eligibility decision. It is never repaired
-- or rebuilt while serving a request.
CREATE TABLE operator_claim_eligibility_current (
    deployment_id             TEXT PRIMARY KEY REFERENCES deployments(deployment_id),
    claim_action_id           TEXT NOT NULL UNIQUE
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    group_id                  TEXT NOT NULL,
    legal_name                TEXT NOT NULL,
    eligibility_state         TEXT NOT NULL CHECK (eligibility_state IN (
        'active',
        'suspended',
        'inactive'
    )),
    approved_review_index     INTEGER NOT NULL DEFAULT 0
        CHECK (approved_review_index >= 0),
    approved_review_hash      TEXT NOT NULL,
    eligibility_id            TEXT NOT NULL DEFAULT '',
    eligibility_index         INTEGER NOT NULL DEFAULT 0
        CHECK (eligibility_index >= 0),
    eligibility_hash          TEXT NOT NULL,
    updated_at                TEXT NOT NULL,
    source_claim_audit_index  INTEGER NOT NULL CHECK (source_claim_audit_index > 0),
    source_claim_audit_hash   TEXT NOT NULL,
    CHECK (
        (
            eligibility_index = 0
            AND eligibility_id = ''
            AND eligibility_hash =
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
        OR
        (
            eligibility_index > 0
            AND eligibility_id <> ''
            AND eligibility_hash <>
                'sha256:0000000000000000000000000000000000000000000000000000000000000000'
        )
    )
);

CREATE INDEX operator_claim_eligibility_current_state_idx
    ON operator_claim_eligibility_current (
        eligibility_state,
        deployment_id
    );

-- Existing approved claim generations begin as active at the migration
-- boundary. No synthetic historical eligibility event or signature is
-- invented. All other current generations are explicitly inactive.
INSERT INTO operator_claim_eligibility_current (
    deployment_id,
    claim_action_id,
    group_id,
    legal_name,
    eligibility_state,
    approved_review_index,
    approved_review_hash,
    eligibility_id,
    eligibility_index,
    eligibility_hash,
    updated_at,
    source_claim_audit_index,
    source_claim_audit_hash
)
SELECT
    deployment_id,
    claim_action_id,
    group_id,
    legal_name,
    CASE
        WHEN verification_state = 'approved' THEN 'active'
        ELSE 'inactive'
    END,
    CASE
        WHEN approved_at <> '' THEN review_index
        ELSE 0
    END,
    CASE
        WHEN approved_at <> '' THEN review_hash
        ELSE
            'sha256:0000000000000000000000000000000000000000000000000000000000000000'
    END,
    '',
    0,
    'sha256:0000000000000000000000000000000000000000000000000000000000000000',
    updated_at,
    claim_audit_index,
    claim_audit_hash
FROM operator_claim_status;
