-- Registry administrators publish announcements only through the local CLI.
-- Public clients have a read-only, signed, snapshot-bound feed.
CREATE TABLE announcements (
    sequence                    INTEGER PRIMARY KEY CHECK (sequence > 0),
    announcement_id             TEXT NOT NULL UNIQUE,
    publication_id              TEXT NOT NULL UNIQUE,
    protocol_version            TEXT NOT NULL CHECK (protocol_version = '1'),
    registry_scope              TEXT NOT NULL,
    kind                        TEXT NOT NULL CHECK (kind IN (
        'GENERAL',
        'UPDATE',
        'MAINTENANCE',
        'SECURITY'
    )),
    severity                    TEXT NOT NULL CHECK (severity IN (
        'INFO',
        'NOTICE',
        'WARNING',
        'CRITICAL'
    )),
    published_at                TEXT NOT NULL,
    expires_at                  TEXT NOT NULL DEFAULT '',
    title_key                   TEXT NOT NULL DEFAULT '',
    body_key                    TEXT NOT NULL DEFAULT '',
    localizations_json          TEXT NOT NULL,
    links_json                  TEXT NOT NULL,
    update_manifest_json        TEXT NOT NULL DEFAULT '',
    update_channel              TEXT NOT NULL DEFAULT '',
    content_hash                TEXT NOT NULL,
    links_hash                  TEXT NOT NULL,
    update_manifest_hash        TEXT NOT NULL,
    draft_hash                  TEXT NOT NULL,
    previous_announcement_hash  TEXT NOT NULL,
    announcement_hash           TEXT NOT NULL UNIQUE,
    accepted_at                 TEXT NOT NULL,
    registry_key_id             TEXT NOT NULL,
    signature                   BLOB NOT NULL CHECK (length(signature) = 64)
);

CREATE INDEX announcements_feed_idx
    ON announcements (sequence DESC, published_at, expires_at);
CREATE INDEX announcements_kind_feed_idx
    ON announcements (kind, sequence DESC);
CREATE INDEX announcements_update_channel_feed_idx
    ON announcements (update_channel, sequence DESC);

CREATE TRIGGER announcements_no_update
BEFORE UPDATE ON announcements BEGIN
    SELECT RAISE(ABORT, 'announcements are append-only');
END;
CREATE TRIGGER announcements_no_delete
BEFORE DELETE ON announcements BEGIN
    SELECT RAISE(ABORT, 'announcements are append-only');
END;
