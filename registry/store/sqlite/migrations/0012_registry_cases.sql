-- Registry-administrator anomaly/case actions form a separate registry-signed,
-- hash-linked audit chain. They deliberately do not mutate claim eligibility,
-- measured weight, revenue, or ledger history.
CREATE TABLE registry_case_events (
    event_index         INTEGER PRIMARY KEY CHECK (event_index > 0),
    event_id            TEXT NOT NULL UNIQUE,
    case_id             TEXT NOT NULL,
    action              TEXT NOT NULL CHECK (action IN ('flag', 'clear')),
    subject_type        TEXT NOT NULL CHECK (subject_type IN (
        'deployment',
        'claim',
        'group',
        'qmau',
        'revenue',
        'ledger'
    )),
    subject_id          TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL CHECK (severity IN (
        'info',
        'warning',
        'critical'
    )),
    evidence_hash       TEXT NOT NULL,
    reference           TEXT NOT NULL,
    actor_id            TEXT NOT NULL,
    idempotency_key     TEXT NOT NULL UNIQUE,
    payload_hash        TEXT NOT NULL,
    accepted_at         TEXT NOT NULL,
    previous_event_hash TEXT NOT NULL,
    event_hash          TEXT NOT NULL UNIQUE,
    registry_scope      TEXT NOT NULL,
    registry_key_id     TEXT NOT NULL,
    signature           BLOB NOT NULL CHECK (length(signature) = 64)
);

CREATE INDEX registry_case_events_case_index
    ON registry_case_events (case_id, event_index);

-- Query state is updated in the same transaction as its immutable event. It is
-- never rebuilt in a request path; integrity verification independently
-- derives the expected current row and fails closed on any mismatch.
CREATE TABLE registry_cases (
    case_id               TEXT PRIMARY KEY,
    status                TEXT NOT NULL CHECK (status IN ('OPEN', 'CLEARED')),
    subject_type          TEXT NOT NULL,
    subject_id            TEXT NOT NULL,
    category              TEXT NOT NULL,
    severity              TEXT NOT NULL,
    flag_evidence_hash    TEXT NOT NULL,
    flag_reference        TEXT NOT NULL,
    flag_actor_id         TEXT NOT NULL,
    flagged_at            TEXT NOT NULL,
    flag_event_index      INTEGER NOT NULL UNIQUE,
    flag_event_hash       TEXT NOT NULL UNIQUE,
    clear_evidence_hash   TEXT NOT NULL DEFAULT '',
    clear_reference       TEXT NOT NULL DEFAULT '',
    clear_actor_id        TEXT NOT NULL DEFAULT '',
    cleared_at            TEXT NOT NULL DEFAULT '',
    clear_event_index     INTEGER NOT NULL DEFAULT 0 CHECK (clear_event_index >= 0),
    clear_event_hash      TEXT NOT NULL DEFAULT '',
    latest_event_index    INTEGER NOT NULL UNIQUE,
    latest_event_hash     TEXT NOT NULL UNIQUE
);

CREATE INDEX registry_cases_status_latest_idx
    ON registry_cases (status, latest_event_index DESC);
CREATE INDEX registry_cases_subject_latest_idx
    ON registry_cases (subject_type, subject_id, latest_event_index DESC);

CREATE TRIGGER registry_case_events_no_update
BEFORE UPDATE ON registry_case_events BEGIN
    SELECT RAISE(ABORT, 'registry case events are append-only');
END;

CREATE TRIGGER registry_case_events_no_delete
BEFORE DELETE ON registry_case_events BEGIN
    SELECT RAISE(ABORT, 'registry case events are append-only');
END;
