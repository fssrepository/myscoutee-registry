-- Claim rejection is a terminal review decision for one pending claim
-- generation. It extends the existing registry-signed review chain; it does
-- not append a deployment action or infer suspension, withdrawal, payout, or
-- exit eligibility.
DROP TRIGGER operator_claim_reviews_no_update;
DROP TRIGGER operator_claim_reviews_no_delete;

ALTER TABLE operator_claim_reviews
    RENAME TO operator_claim_reviews_approval_only;

CREATE TABLE operator_claim_reviews (
    review_index         INTEGER PRIMARY KEY CHECK (review_index > 0),
    review_id            TEXT NOT NULL UNIQUE,
    deployment_id        TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id      TEXT NOT NULL UNIQUE
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    group_id             TEXT NOT NULL,
    legal_name           TEXT NOT NULL,
    decision             TEXT NOT NULL CHECK (decision IN (
        'approved',
        'rejected'
    )),
    reviewer_id          TEXT NOT NULL,
    review_reference     TEXT NOT NULL,
    reason_code          TEXT NOT NULL DEFAULT '',
    idempotency_key      TEXT NOT NULL UNIQUE,
    reviewed_at          TEXT NOT NULL,
    previous_review_hash TEXT NOT NULL,
    review_hash          TEXT NOT NULL UNIQUE,
    registry_key_id      TEXT NOT NULL,
    signature            BLOB NOT NULL CHECK (length(signature) = 64),
    CHECK (
        (decision = 'approved' AND reason_code = '')
        OR
        (
            decision = 'rejected'
            AND length(reason_code) BETWEEN 3 AND 64
        )
    )
);

INSERT INTO operator_claim_reviews (
    review_index,
    review_id,
    deployment_id,
    claim_action_id,
    group_id,
    legal_name,
    decision,
    reviewer_id,
    review_reference,
    reason_code,
    idempotency_key,
    reviewed_at,
    previous_review_hash,
    review_hash,
    registry_key_id,
    signature
)
SELECT
    review_index,
    review_id,
    deployment_id,
    claim_action_id,
    group_id,
    legal_name,
    decision,
    reviewer_id,
    review_reference,
    '',
    idempotency_key,
    reviewed_at,
    previous_review_hash,
    review_hash,
    registry_key_id,
    signature
FROM operator_claim_reviews_approval_only;

DROP TABLE operator_claim_reviews_approval_only;

CREATE INDEX operator_claim_reviews_deployment_idx
    ON operator_claim_reviews (deployment_id, review_index);

CREATE TRIGGER operator_claim_reviews_no_update
BEFORE UPDATE ON operator_claim_reviews BEGIN
    SELECT RAISE(ABORT, 'operator claim reviews are append-only');
END;
CREATE TRIGGER operator_claim_reviews_no_delete
BEFORE DELETE ON operator_claim_reviews BEGIN
    SELECT RAISE(ABORT, 'operator claim reviews are append-only');
END;

CREATE TABLE operator_claim_status_with_rejection (
    deployment_id        TEXT PRIMARY KEY REFERENCES deployments(deployment_id),
    claim_action_id      TEXT NOT NULL UNIQUE
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    claim_audit_index    INTEGER NOT NULL CHECK (claim_audit_index > 0),
    claim_audit_hash     TEXT NOT NULL,
    group_id             TEXT NOT NULL,
    legal_name           TEXT NOT NULL,
    verification_state   TEXT NOT NULL CHECK (verification_state IN (
        'pending-review',
        'approved',
        'rejected',
        'withdrawn'
    )),
    submitted_at         TEXT NOT NULL,
    review_id            TEXT NOT NULL DEFAULT '',
    review_index         INTEGER NOT NULL DEFAULT 0 CHECK (review_index >= 0),
    review_hash          TEXT NOT NULL,
    approved_at          TEXT NOT NULL DEFAULT '',
    updated_at           TEXT NOT NULL,
    private_record_hash  TEXT NOT NULL
);

INSERT INTO operator_claim_status_with_rejection (
    deployment_id,
    claim_action_id,
    claim_audit_index,
    claim_audit_hash,
    group_id,
    legal_name,
    verification_state,
    submitted_at,
    review_id,
    review_index,
    review_hash,
    approved_at,
    updated_at,
    private_record_hash
)
SELECT
    deployment_id,
    claim_action_id,
    claim_audit_index,
    claim_audit_hash,
    group_id,
    legal_name,
    verification_state,
    submitted_at,
    review_id,
    review_index,
    review_hash,
    approved_at,
    updated_at,
    private_record_hash
FROM operator_claim_status;

DROP TABLE operator_claim_status;

ALTER TABLE operator_claim_status_with_rejection
    RENAME TO operator_claim_status;

CREATE INDEX operator_claim_status_state_deployment_idx
    ON operator_claim_status (verification_state, deployment_id);
