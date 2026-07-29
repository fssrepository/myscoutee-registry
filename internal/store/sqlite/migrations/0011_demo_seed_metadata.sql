-- Demo data is opt-in and belongs to a dedicated registry identity/database.
-- The marker makes interrupted seeding resumable while preventing the demo
-- command from adding fixtures to an already populated registry.
CREATE TABLE demo_seed_metadata (
    singleton       INTEGER PRIMARY KEY CHECK (singleton = 1),
    seed_version    TEXT NOT NULL,
    registry_scope  TEXT NOT NULL,
    seed_digest     TEXT NOT NULL,
    state           TEXT NOT NULL CHECK (state IN ('STARTED', 'COMPLETE')),
    started_at      TEXT NOT NULL,
    completed_at    TEXT NOT NULL DEFAULT ''
);

CREATE TRIGGER demo_seed_metadata_guard_update
BEFORE UPDATE ON demo_seed_metadata
WHEN NOT (
    OLD.singleton = 1
    AND OLD.state = 'STARTED'
    AND NEW.singleton = OLD.singleton
    AND NEW.seed_version = OLD.seed_version
    AND NEW.registry_scope = OLD.registry_scope
    AND NEW.seed_digest = OLD.seed_digest
    AND NEW.started_at = OLD.started_at
    AND NEW.state = 'COMPLETE'
    AND NEW.completed_at <> ''
)
BEGIN
    SELECT RAISE(ABORT, 'demo seed marker permits only STARTED to COMPLETE');
END;

CREATE TRIGGER demo_seed_metadata_no_delete
BEFORE DELETE ON demo_seed_metadata
BEGIN
    SELECT RAISE(ABORT, 'demo seed marker cannot be deleted');
END;
