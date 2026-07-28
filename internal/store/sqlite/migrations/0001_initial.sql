CREATE TABLE registry_identity (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    protocol_version   TEXT NOT NULL CHECK (protocol_version = '1'),
    registry_scope     TEXT NOT NULL,
    registry_key_id    TEXT NOT NULL UNIQUE,
    public_key_der     BLOB NOT NULL,
    created_at         TEXT NOT NULL
);

CREATE TABLE deployments (
    deployment_id                  TEXT PRIMARY KEY,
    public_key_der                 BLOB NOT NULL UNIQUE,
    public_key_fingerprint         TEXT NOT NULL UNIQUE,
    key_algorithm                  TEXT NOT NULL CHECK (key_algorithm = 'Ed25519'),
    software_version               TEXT NOT NULL,
    registration_timestamp         TEXT NOT NULL,
    registration_nonce             TEXT NOT NULL,
    registration_idempotency_key   TEXT NOT NULL,
    registration_signature         BLOB NOT NULL CHECK (length(registration_signature) = 64),
    registered_at                  TEXT NOT NULL,
    registration_payload_hash      TEXT NOT NULL,
    registration_receipt_signature BLOB NOT NULL CHECK (length(registration_receipt_signature) = 64)
);

CREATE TABLE used_nonces (
    signer             TEXT NOT NULL,
    nonce              TEXT NOT NULL,
    request_hash       TEXT NOT NULL,
    idempotency_key    TEXT NOT NULL,
    payload_hash       TEXT NOT NULL,
    request_timestamp  TEXT NOT NULL,
    request_signature  BLOB NOT NULL CHECK (length(request_signature) = 64),
    result_type        TEXT NOT NULL CHECK (result_type IN ('deployment', 'batch')),
    result_id          TEXT NOT NULL,
    accepted_at        TEXT NOT NULL,
    PRIMARY KEY (signer, nonce)
);

CREATE TABLE idempotency_records (
    signer           TEXT NOT NULL,
    idempotency_key  TEXT NOT NULL,
    payload_hash     TEXT NOT NULL,
    result_type      TEXT NOT NULL CHECK (result_type IN ('deployment', 'batch')),
    result_id        TEXT NOT NULL,
    accepted_at      TEXT NOT NULL,
    PRIMARY KEY (signer, idempotency_key)
);

CREATE TABLE ledger_entries (
    ledger_index         INTEGER PRIMARY KEY CHECK (ledger_index > 0),
    protocol_version     TEXT NOT NULL CHECK (protocol_version = '1'),
    registry_scope       TEXT NOT NULL,
    entry_type           TEXT NOT NULL CHECK (entry_type = 'INSTALLATION_TEST_BATCH_ACCEPTED'),
    deployment_id        TEXT NOT NULL REFERENCES deployments(deployment_id),
    batch_id             TEXT NOT NULL UNIQUE,
    kind                 TEXT NOT NULL CHECK (kind = 'installation-test'),
    period               TEXT NOT NULL,
    ruleset_version      TEXT NOT NULL CHECK (ruleset_version = 'installation-test-v1'),
    qualified_mau_count  INTEGER NOT NULL CHECK (qualified_mau_count = 0),
    batch_hash           TEXT NOT NULL,
    previous_entry_hash  TEXT NOT NULL,
    entry_hash           TEXT NOT NULL UNIQUE,
    accepted_at          TEXT NOT NULL
);

CREATE INDEX ledger_entries_accepted_at_idx
    ON ledger_entries (accepted_at, ledger_index);

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

CREATE TABLE checkpoints (
    registry_scope             TEXT NOT NULL,
    checkpoint_date            TEXT PRIMARY KEY,
    through_ledger_index       INTEGER NOT NULL CHECK (through_ledger_index >= 0),
    entry_count                INTEGER NOT NULL CHECK (entry_count >= 0),
    ledger_head_hash           TEXT NOT NULL,
    previous_checkpoint_hash   TEXT NOT NULL,
    checkpoint_hash            TEXT NOT NULL UNIQUE,
    generated_at               TEXT NOT NULL,
    registry_key_id            TEXT NOT NULL,
    signature                  BLOB NOT NULL CHECK (length(signature) = 64)
);

CREATE TRIGGER registry_identity_no_update
BEFORE UPDATE ON registry_identity BEGIN
    SELECT RAISE(ABORT, 'registry_identity is immutable');
END;
CREATE TRIGGER registry_identity_no_delete
BEFORE DELETE ON registry_identity BEGIN
    SELECT RAISE(ABORT, 'registry_identity is immutable');
END;

CREATE TRIGGER deployments_no_update
BEFORE UPDATE ON deployments BEGIN
    SELECT RAISE(ABORT, 'deployments are immutable in protocol v1');
END;
CREATE TRIGGER deployments_no_delete
BEFORE DELETE ON deployments BEGIN
    SELECT RAISE(ABORT, 'deployments are immutable in protocol v1');
END;

CREATE TRIGGER used_nonces_no_update
BEFORE UPDATE ON used_nonces BEGIN
    SELECT RAISE(ABORT, 'used nonces are append-only');
END;
CREATE TRIGGER used_nonces_no_delete
BEFORE DELETE ON used_nonces BEGIN
    SELECT RAISE(ABORT, 'used nonces are append-only');
END;

CREATE TRIGGER idempotency_records_no_update
BEFORE UPDATE ON idempotency_records BEGIN
    SELECT RAISE(ABORT, 'idempotency records are append-only');
END;
CREATE TRIGGER idempotency_records_no_delete
BEFORE DELETE ON idempotency_records BEGIN
    SELECT RAISE(ABORT, 'idempotency records are append-only');
END;

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

CREATE TRIGGER checkpoints_no_update
BEFORE UPDATE ON checkpoints BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only');
END;
CREATE TRIGGER checkpoints_no_delete
BEFORE DELETE ON checkpoints BEGIN
    SELECT RAISE(ABORT, 'checkpoints are append-only');
END;
