-- Company-verification submissions are intentionally separated from the
-- public operator audit chain. The public audit event commits to payload_hash
-- and contains only the public legal-name/avatar/group/status fields. Raw
-- address and verification-contact data lives only in this private,
-- append-only review table and is never selected by public HTTP/leaderboard
-- queries.
CREATE TABLE operator_claim_verification_submissions (
    claim_action_id             TEXT PRIMARY KEY
        REFERENCES operator_audit_events(action_id),
    deployment_id              TEXT NOT NULL REFERENCES deployments(deployment_id),
    group_id                   TEXT NOT NULL,
    legal_name                 TEXT NOT NULL,
    registration_number        TEXT NOT NULL,
    jurisdiction               TEXT NOT NULL,
    registered_address         TEXT NOT NULL,
    website                    TEXT NOT NULL DEFAULT '',
    verification_contact_name  TEXT NOT NULL,
    verification_contact_role  TEXT NOT NULL,
    verification_contact_email TEXT NOT NULL,
    authority_attested         INTEGER NOT NULL CHECK (authority_attested = 1),
    operator_avatar_url        TEXT NOT NULL DEFAULT '',
    payload_hash               TEXT NOT NULL,
    submitted_at               TEXT NOT NULL,
    private_record_hash        TEXT NOT NULL UNIQUE
);

CREATE INDEX operator_claim_verification_deployment_idx
    ON operator_claim_verification_submissions (deployment_id, submitted_at);

-- Registry-authorized reviews use their own append-only, registry-signed hash
-- chain. They are never forged into the deployment-signed operator action
-- chain.
CREATE TABLE operator_claim_reviews (
    review_index         INTEGER PRIMARY KEY CHECK (review_index > 0),
    review_id            TEXT NOT NULL UNIQUE,
    deployment_id        TEXT NOT NULL REFERENCES deployments(deployment_id),
    claim_action_id      TEXT NOT NULL UNIQUE
        REFERENCES operator_claim_verification_submissions(claim_action_id),
    group_id             TEXT NOT NULL,
    legal_name           TEXT NOT NULL,
    decision             TEXT NOT NULL CHECK (decision = 'approved'),
    reviewer_id          TEXT NOT NULL,
    review_reference     TEXT NOT NULL,
    idempotency_key      TEXT NOT NULL UNIQUE,
    reviewed_at          TEXT NOT NULL,
    previous_review_hash TEXT NOT NULL,
    review_hash          TEXT NOT NULL UNIQUE,
    registry_key_id      TEXT NOT NULL,
    signature            BLOB NOT NULL CHECK (length(signature) = 64)
);

CREATE INDEX operator_claim_reviews_deployment_idx
    ON operator_claim_reviews (deployment_id, review_index);

-- This is the directly maintained current-state query row. It is written in
-- the same transaction as claim/withdraw audit appends and review appends; it
-- is never projected or rebuilt from the audit chains.
CREATE TABLE operator_claim_status (
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

CREATE INDEX operator_claim_status_state_deployment_idx
    ON operator_claim_status (verification_state, deployment_id);

CREATE TRIGGER operator_claim_verification_no_update
BEFORE UPDATE ON operator_claim_verification_submissions BEGIN
    SELECT RAISE(ABORT, 'operator claim verification submissions are append-only');
END;
CREATE TRIGGER operator_claim_verification_no_delete
BEFORE DELETE ON operator_claim_verification_submissions BEGIN
    SELECT RAISE(ABORT, 'operator claim verification submissions are append-only');
END;
CREATE TRIGGER operator_claim_reviews_no_update
BEFORE UPDATE ON operator_claim_reviews BEGIN
    SELECT RAISE(ABORT, 'operator claim reviews are append-only');
END;
CREATE TRIGGER operator_claim_reviews_no_delete
BEFORE DELETE ON operator_claim_reviews BEGIN
    SELECT RAISE(ABORT, 'operator claim reviews are append-only');
END;
