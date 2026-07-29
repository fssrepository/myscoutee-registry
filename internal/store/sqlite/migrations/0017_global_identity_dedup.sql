-- Privacy-safe cross-deployment identity linking.
--
-- The public audit surface is global_identity_events. It contains only an
-- aggregate commitment and aggregate counts. Opaque VOPRF-derived commitments,
-- internal network identity IDs, and consent-evidence commitments live only in
-- the separately governed direct tables and are never copied to the public
-- event chain.

CREATE TABLE global_identity_voprf_keys (
    key_version     INTEGER PRIMARY KEY CHECK (key_version > 0),
    suite           TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    public_key      BLOB NOT NULL UNIQUE CHECK (length(public_key) = 33),
    activated_at    TEXT NOT NULL
);

CREATE TABLE global_identity_evaluations (
    evaluation_id       TEXT PRIMARY KEY,
    deployment_id       TEXT NOT NULL REFERENCES deployments(deployment_id),
    idempotency_key     TEXT NOT NULL,
    request_nonce       TEXT NOT NULL,
    request_timestamp   TEXT NOT NULL,
    request_hash        TEXT NOT NULL,
    request_signature   BLOB NOT NULL CHECK (length(request_signature) = 64),
    payload_hash        TEXT NOT NULL,
    key_version         INTEGER NOT NULL REFERENCES global_identity_voprf_keys(key_version),
    suite               TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    blinded_element     BLOB NOT NULL CHECK (length(blinded_element) = 33),
    public_key          BLOB NOT NULL CHECK (length(public_key) = 33),
    evaluated_element   BLOB NOT NULL CHECK (length(evaluated_element) = 33),
    proof               BLOB NOT NULL CHECK (length(proof) = 64),
    response_hash       TEXT NOT NULL,
    evaluated_at        TEXT NOT NULL,
    receipt_signature   BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    UNIQUE (deployment_id, idempotency_key),
    UNIQUE (deployment_id, request_nonce)
);

CREATE INDEX global_identity_evaluations_rate_idx
    ON global_identity_evaluations (deployment_id, evaluated_at);

CREATE TABLE global_identities (
    global_identity_id  TEXT PRIMARY KEY,
    created_at          TEXT NOT NULL
);

-- This direct alias map is intentionally mutable only for an audited
-- correction that merges two opaque identities. The corresponding immutable
-- correction event and link-history rows are written in the same transaction.
CREATE TABLE global_identity_aliases (
    key_version                  INTEGER NOT NULL REFERENCES global_identity_voprf_keys(key_version),
    network_identity_commitment  TEXT NOT NULL,
    global_identity_id           TEXT NOT NULL REFERENCES global_identities(global_identity_id),
    created_at                   TEXT NOT NULL,
    PRIMARY KEY (key_version, network_identity_commitment)
);

CREATE INDEX global_identity_aliases_identity_idx
    ON global_identity_aliases (global_identity_id);

CREATE TABLE global_identity_events (
    event_index           INTEGER PRIMARY KEY CHECK (event_index > 0),
    event_id              TEXT NOT NULL UNIQUE,
    action                TEXT NOT NULL CHECK (action IN (
        'LINK',
        'UNLINK',
        'CORRECT',
        'QUALIFIED_PRESENCE'
    )),
    deployment_id         TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                TEXT NOT NULL,
    aggregate_commitment  TEXT NOT NULL,
    reported_count        INTEGER NOT NULL CHECK (reported_count >= 0),
    deduplicated_count    INTEGER NOT NULL CHECK (deduplicated_count >= 0),
    accepted_at           TEXT NOT NULL,
    previous_event_hash   TEXT NOT NULL,
    event_hash            TEXT NOT NULL UNIQUE,
    registry_scope        TEXT NOT NULL,
    registry_key_id       TEXT NOT NULL,
    receipt_signature     BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    idempotency_key       TEXT NOT NULL,
    request_nonce         TEXT NOT NULL,
    request_timestamp     TEXT NOT NULL,
    request_hash          TEXT NOT NULL,
    payload_hash          TEXT NOT NULL,
    request_signature     BLOB NOT NULL CHECK (length(request_signature) = 64),
    private_event_hash    TEXT NOT NULL,
    subject_id            TEXT NOT NULL,
    UNIQUE (deployment_id, idempotency_key),
    UNIQUE (deployment_id, request_nonce)
);

CREATE INDEX global_identity_events_period_idx
    ON global_identity_events (period, event_index);

-- Direct current-state table. Changes are legal only from the transaction
-- that appends the matching immutable event and history row.
CREATE TABLE global_identity_links (
    link_id                       TEXT PRIMARY KEY,
    deployment_id                 TEXT NOT NULL REFERENCES deployments(deployment_id),
    global_identity_id            TEXT NOT NULL REFERENCES global_identities(global_identity_id),
    status                        TEXT NOT NULL CHECK (status IN ('ACTIVE', 'UNLINKED')),
    key_version                   INTEGER NOT NULL,
    suite                         TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    network_identity_commitment   TEXT NOT NULL,
    consent_version               TEXT NOT NULL CHECK (consent_version = 'global-dedup-consent-v1'),
    consent_evidence_commitment   TEXT NOT NULL,
    verified_at                   TEXT NOT NULL,
    active_from_period            TEXT NOT NULL,
    inactive_from_period          TEXT NOT NULL DEFAULT '',
    latest_event_index            INTEGER NOT NULL UNIQUE REFERENCES global_identity_events(event_index),
    latest_event_hash             TEXT NOT NULL,
    FOREIGN KEY (key_version, network_identity_commitment)
        REFERENCES global_identity_aliases(key_version, network_identity_commitment)
);

CREATE INDEX global_identity_links_deployment_status_idx
    ON global_identity_links (deployment_id, status, link_id);
CREATE INDEX global_identity_links_identity_status_idx
    ON global_identity_links (global_identity_id, status, link_id);

CREATE TABLE global_identity_link_history (
    event_index                    INTEGER PRIMARY KEY REFERENCES global_identity_events(event_index),
    link_id                        TEXT NOT NULL,
    deployment_id                  TEXT NOT NULL REFERENCES deployments(deployment_id),
    global_identity_id             TEXT NOT NULL REFERENCES global_identities(global_identity_id),
    status                         TEXT NOT NULL CHECK (status IN ('ACTIVE', 'UNLINKED')),
    key_version                    INTEGER NOT NULL,
    suite                          TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    network_identity_commitment    TEXT NOT NULL,
    consent_version                TEXT NOT NULL,
    consent_evidence_commitment    TEXT NOT NULL,
    verified_at                    TEXT NOT NULL,
    active_from_period             TEXT NOT NULL,
    inactive_from_period           TEXT NOT NULL DEFAULT '',
    reason_commitment              TEXT NOT NULL,
    private_event_hash             TEXT NOT NULL
);

CREATE INDEX global_identity_link_history_link_idx
    ON global_identity_link_history (link_id, event_index);

CREATE TABLE global_identity_presence_batches (
    batch_id                    TEXT PRIMARY KEY,
    deployment_id               TEXT NOT NULL REFERENCES deployments(deployment_id),
    period                      TEXT NOT NULL,
    revision                    INTEGER NOT NULL CHECK (revision > 0),
    supersedes_batch_id         TEXT NOT NULL DEFAULT '',
    reported_qmau_count         INTEGER NOT NULL CHECK (reported_qmau_count >= 0),
    linked_observation_count    INTEGER NOT NULL CHECK (linked_observation_count >= 0),
    unlinked_qmau_count         INTEGER NOT NULL CHECK (unlinked_qmau_count >= 0),
    key_version                 INTEGER NOT NULL REFERENCES global_identity_voprf_keys(key_version),
    suite                       TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    payload_hash                TEXT NOT NULL,
    event_index                 INTEGER NOT NULL UNIQUE REFERENCES global_identity_events(event_index),
    accepted_at                 TEXT NOT NULL,
    UNIQUE (deployment_id, period, revision),
    CHECK (reported_qmau_count = linked_observation_count + unlinked_qmau_count)
);

CREATE INDEX global_identity_presence_batches_current_idx
    ON global_identity_presence_batches (period, deployment_id, revision DESC);

CREATE TABLE global_identity_presence_items (
    batch_id                       TEXT NOT NULL REFERENCES global_identity_presence_batches(batch_id),
    item_index                     INTEGER NOT NULL CHECK (item_index >= 0),
    key_version                    INTEGER NOT NULL,
    network_identity_commitment    TEXT NOT NULL,
    PRIMARY KEY (batch_id, item_index),
    FOREIGN KEY (key_version, network_identity_commitment)
        REFERENCES global_identity_aliases(key_version, network_identity_commitment)
);

CREATE INDEX global_identity_presence_items_alias_idx
    ON global_identity_presence_items (
        key_version,
        network_identity_commitment,
        batch_id
    );

-- Every accepted link mutation or presence batch writes a new immutable
-- snapshot revision for its period in the same transaction.
CREATE TABLE global_identity_dedup_snapshots (
    period                          TEXT NOT NULL,
    revision                        INTEGER NOT NULL CHECK (revision > 0),
    reported_qmau_count             INTEGER NOT NULL CHECK (reported_qmau_count >= 0),
    linked_observation_count        INTEGER NOT NULL CHECK (linked_observation_count >= 0),
    globally_unique_linked_count    INTEGER NOT NULL CHECK (globally_unique_linked_count >= 0),
    unlinked_qmau_count              INTEGER NOT NULL CHECK (unlinked_qmau_count >= 0),
    deduplicated_network_qmau       INTEGER NOT NULL CHECK (deduplicated_network_qmau >= 0),
    duplicate_reduction             INTEGER NOT NULL CHECK (duplicate_reduction >= 0),
    covered_deployment_count        INTEGER NOT NULL CHECK (covered_deployment_count >= 0),
    aggregate_commitment            TEXT NOT NULL,
    through_event_index             INTEGER NOT NULL REFERENCES global_identity_events(event_index),
    through_event_hash              TEXT NOT NULL,
    generated_at                    TEXT NOT NULL,
    PRIMARY KEY (period, revision),
    UNIQUE (period, through_event_index),
    CHECK (
        deduplicated_network_qmau =
            globally_unique_linked_count + unlinked_qmau_count
    ),
    CHECK (
        duplicate_reduction =
            reported_qmau_count - deduplicated_network_qmau
    )
);

CREATE TRIGGER global_identity_voprf_keys_no_update
BEFORE UPDATE ON global_identity_voprf_keys BEGIN
    SELECT RAISE(ABORT, 'global identity VOPRF keys are append-only');
END;
CREATE TRIGGER global_identity_voprf_keys_no_delete
BEFORE DELETE ON global_identity_voprf_keys BEGIN
    SELECT RAISE(ABORT, 'global identity VOPRF keys are append-only');
END;
CREATE TRIGGER global_identity_evaluations_no_update
BEFORE UPDATE ON global_identity_evaluations BEGIN
    SELECT RAISE(ABORT, 'global identity evaluations are append-only');
END;
CREATE TRIGGER global_identity_evaluations_no_delete
BEFORE DELETE ON global_identity_evaluations BEGIN
    SELECT RAISE(ABORT, 'global identity evaluations are append-only');
END;
CREATE TRIGGER global_identities_no_update
BEFORE UPDATE ON global_identities BEGIN
    SELECT RAISE(ABORT, 'global identities are append-only');
END;
CREATE TRIGGER global_identities_no_delete
BEFORE DELETE ON global_identities BEGIN
    SELECT RAISE(ABORT, 'global identities are append-only');
END;
CREATE TRIGGER global_identity_events_no_update
BEFORE UPDATE ON global_identity_events BEGIN
    SELECT RAISE(ABORT, 'global identity events are append-only');
END;
CREATE TRIGGER global_identity_events_no_delete
BEFORE DELETE ON global_identity_events BEGIN
    SELECT RAISE(ABORT, 'global identity events are append-only');
END;
CREATE TRIGGER global_identity_link_history_no_update
BEFORE UPDATE ON global_identity_link_history BEGIN
    SELECT RAISE(ABORT, 'global identity link history is append-only');
END;
CREATE TRIGGER global_identity_link_history_no_delete
BEFORE DELETE ON global_identity_link_history BEGIN
    SELECT RAISE(ABORT, 'global identity link history is append-only');
END;
CREATE TRIGGER global_identity_presence_batches_no_update
BEFORE UPDATE ON global_identity_presence_batches BEGIN
    SELECT RAISE(ABORT, 'global identity presence batches are append-only');
END;
CREATE TRIGGER global_identity_presence_batches_no_delete
BEFORE DELETE ON global_identity_presence_batches BEGIN
    SELECT RAISE(ABORT, 'global identity presence batches are append-only');
END;
CREATE TRIGGER global_identity_presence_items_no_update
BEFORE UPDATE ON global_identity_presence_items BEGIN
    SELECT RAISE(ABORT, 'global identity presence items are append-only');
END;
CREATE TRIGGER global_identity_presence_items_no_delete
BEFORE DELETE ON global_identity_presence_items BEGIN
    SELECT RAISE(ABORT, 'global identity presence items are append-only');
END;
CREATE TRIGGER global_identity_dedup_snapshots_no_update
BEFORE UPDATE ON global_identity_dedup_snapshots BEGIN
    SELECT RAISE(ABORT, 'global identity dedup snapshots are append-only');
END;
CREATE TRIGGER global_identity_dedup_snapshots_no_delete
BEFORE DELETE ON global_identity_dedup_snapshots BEGIN
    SELECT RAISE(ABORT, 'global identity dedup snapshots are append-only');
END;
