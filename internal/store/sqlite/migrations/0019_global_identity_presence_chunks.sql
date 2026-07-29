-- Restricted append-only staging for bounded, deployment-signed presence
-- chunks. A submission is not visible to the current presence or dedup
-- queries until one completion row and the canonical aggregate
-- presence/event/snapshot are written in the same transaction.
CREATE TABLE global_identity_presence_submissions (
    submission_id                 TEXT PRIMARY KEY,
    deployment_id                TEXT NOT NULL REFERENCES deployments(deployment_id),
    registry_scope               TEXT NOT NULL,
    period                       TEXT NOT NULL,
    revision                     INTEGER NOT NULL CHECK (revision > 0),
    supersedes_batch_id          TEXT NOT NULL DEFAULT '',
    reported_qmau_count          INTEGER NOT NULL CHECK (reported_qmau_count >= 0),
    key_version                  INTEGER NOT NULL REFERENCES global_identity_voprf_keys(key_version),
    suite                        TEXT NOT NULL CHECK (suite = 'P256-SHA256'),
    chunk_count                  INTEGER NOT NULL CHECK (
        chunk_count > 0 AND chunk_count <= 4096
    ),
    total_commitment_count       INTEGER NOT NULL CHECK (
        total_commitment_count >= 0
        AND total_commitment_count <= reported_qmau_count
        AND total_commitment_count <= chunk_count * 4096
    ),
    commitment_set_hash          TEXT NOT NULL,
    created_at                   TEXT NOT NULL,
    UNIQUE (deployment_id, period, revision),
    CHECK (
        chunk_count <= CASE
            WHEN total_commitment_count = 0 THEN 1
            ELSE total_commitment_count
        END
    )
);

CREATE INDEX global_identity_presence_submissions_deployment_idx
    ON global_identity_presence_submissions (
        deployment_id,
        period,
        revision
    );

CREATE TABLE global_identity_presence_chunks (
    submission_id          TEXT NOT NULL REFERENCES global_identity_presence_submissions(submission_id),
    chunk_index            INTEGER NOT NULL CHECK (chunk_index >= 0),
    deployment_id          TEXT NOT NULL REFERENCES deployments(deployment_id),
    idempotency_key        TEXT NOT NULL,
    request_nonce          TEXT NOT NULL,
    request_timestamp      TEXT NOT NULL,
    request_hash           TEXT NOT NULL,
    payload_hash           TEXT NOT NULL,
    request_signature      BLOB NOT NULL CHECK (length(request_signature) = 64),
    item_count             INTEGER NOT NULL CHECK (
        item_count >= 0 AND item_count <= 4096
    ),
    acceptance_index       INTEGER NOT NULL CHECK (acceptance_index > 0),
    received_chunk_count   INTEGER NOT NULL CHECK (received_chunk_count > 0),
    complete               INTEGER NOT NULL CHECK (complete IN (0, 1)),
    completed_batch_id     TEXT NOT NULL DEFAULT '',
    completed_event_hash   TEXT NOT NULL DEFAULT '',
    accepted_at            TEXT NOT NULL,
    registry_key_id        TEXT NOT NULL,
    receipt_hash           TEXT NOT NULL,
    receipt_signature      BLOB NOT NULL CHECK (length(receipt_signature) = 64),
    PRIMARY KEY (submission_id, chunk_index),
    UNIQUE (submission_id, acceptance_index),
    UNIQUE (deployment_id, idempotency_key),
    UNIQUE (deployment_id, request_nonce),
    CHECK (acceptance_index = received_chunk_count),
    CHECK (
        (complete = 0
            AND completed_batch_id = ''
            AND completed_event_hash = '')
        OR
        (complete = 1
            AND completed_batch_id <> ''
            AND completed_event_hash <> '')
    )
);

CREATE TABLE global_identity_presence_chunk_items (
    submission_id                  TEXT NOT NULL,
    chunk_index                   INTEGER NOT NULL,
    item_index                    INTEGER NOT NULL CHECK (item_index >= 0),
    key_version                   INTEGER NOT NULL,
    network_identity_commitment   TEXT NOT NULL,
    PRIMARY KEY (submission_id, chunk_index, item_index),
    FOREIGN KEY (submission_id, chunk_index)
        REFERENCES global_identity_presence_chunks(submission_id, chunk_index),
    FOREIGN KEY (key_version, network_identity_commitment)
        REFERENCES global_identity_aliases(key_version, network_identity_commitment)
);

CREATE INDEX global_identity_presence_chunk_items_alias_idx
    ON global_identity_presence_chunk_items (
        key_version,
        network_identity_commitment,
        submission_id,
        chunk_index
    );

CREATE TABLE global_identity_presence_completions (
    submission_id             TEXT PRIMARY KEY REFERENCES global_identity_presence_submissions(submission_id),
    completing_chunk_index    INTEGER NOT NULL,
    batch_id                  TEXT NOT NULL UNIQUE REFERENCES global_identity_presence_batches(batch_id),
    event_index               INTEGER NOT NULL UNIQUE REFERENCES global_identity_events(event_index),
    aggregate_payload_hash    TEXT NOT NULL,
    completed_at              TEXT NOT NULL,
    FOREIGN KEY (submission_id, completing_chunk_index)
        REFERENCES global_identity_presence_chunks(submission_id, chunk_index)
);

CREATE TRIGGER global_identity_presence_submissions_no_update
BEFORE UPDATE ON global_identity_presence_submissions BEGIN
    SELECT RAISE(ABORT, 'global identity presence submissions are append-only');
END;
CREATE TRIGGER global_identity_presence_submissions_no_delete
BEFORE DELETE ON global_identity_presence_submissions BEGIN
    SELECT RAISE(ABORT, 'global identity presence submissions are append-only');
END;
CREATE TRIGGER global_identity_presence_chunks_no_update
BEFORE UPDATE ON global_identity_presence_chunks BEGIN
    SELECT RAISE(ABORT, 'global identity presence chunks are append-only');
END;
CREATE TRIGGER global_identity_presence_chunks_no_delete
BEFORE DELETE ON global_identity_presence_chunks BEGIN
    SELECT RAISE(ABORT, 'global identity presence chunks are append-only');
END;
CREATE TRIGGER global_identity_presence_chunk_items_no_update
BEFORE UPDATE ON global_identity_presence_chunk_items BEGIN
    SELECT RAISE(ABORT, 'global identity presence chunk items are append-only');
END;
CREATE TRIGGER global_identity_presence_chunk_items_no_delete
BEFORE DELETE ON global_identity_presence_chunk_items BEGIN
    SELECT RAISE(ABORT, 'global identity presence chunk items are append-only');
END;
CREATE TRIGGER global_identity_presence_completions_no_update
BEFORE UPDATE ON global_identity_presence_completions BEGIN
    SELECT RAISE(ABORT, 'global identity presence completions are append-only');
END;
CREATE TRIGGER global_identity_presence_completions_no_delete
BEFORE DELETE ON global_identity_presence_completions BEGIN
    SELECT RAISE(ABORT, 'global identity presence completions are append-only');
END;
