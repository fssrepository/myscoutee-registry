-- Forward-only enforcement for databases that already applied migration 0019
-- before the per-chunk capacity bound was introduced. Keep migration 0019
-- immutable so a previously recorded schema version remains reproducible.
--
-- Refuse to bless an already-inconsistent database. The guard table exists
-- only for the duration of this migration; violating legacy rows make the
-- migration transaction fail and roll back.
CREATE TABLE migration_0021_global_identity_presence_capacity_guard (
    valid INTEGER NOT NULL CHECK (valid = 1)
);

INSERT INTO migration_0021_global_identity_presence_capacity_guard (valid)
SELECT CASE
    WHEN EXISTS (
        SELECT 1
        FROM global_identity_presence_submissions
        WHERE total_commitment_count > chunk_count * 4096
    ) THEN 0
    ELSE 1
END;

DROP TABLE migration_0021_global_identity_presence_capacity_guard;

CREATE TRIGGER global_identity_presence_submissions_chunk_capacity
BEFORE INSERT ON global_identity_presence_submissions
WHEN NEW.total_commitment_count > NEW.chunk_count * 4096
BEGIN
    SELECT RAISE(
        ABORT,
        'global identity presence commitment count exceeds chunk capacity'
    );
END;
