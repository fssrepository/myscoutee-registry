-- Historical operator-network state is a directly written read model. Each
-- operator audit event has exactly one immutable state row for its subject
-- deployment at that audit boundary. Leaderboard reads select these rows; they
-- never interpret the action stream.
CREATE TABLE operator_network_state_rows (
    audit_index                 INTEGER PRIMARY KEY
        REFERENCES operator_audit_events(audit_index),
    action_id                  TEXT NOT NULL UNIQUE
        REFERENCES operator_audit_events(action_id),
    deployment_id              TEXT NOT NULL REFERENCES deployments(deployment_id),
    claimed                    INTEGER NOT NULL CHECK (claimed IN (0, 1)),
    active                     INTEGER NOT NULL CHECK (active IN (0, 1)),
    claim_state                TEXT NOT NULL CHECK (claim_state IN (
        '',
        'claimed',
        'pending-review',
        'withdrawn'
    )),
    claim_state_audit_index    INTEGER NOT NULL CHECK (claim_state_audit_index >= 0),
    profile_claim_audit_index  INTEGER NOT NULL CHECK (profile_claim_audit_index >= 0),
    claim_group_id             TEXT NOT NULL DEFAULT '',
    effective_group_id         TEXT NOT NULL DEFAULT '',
    operator_name              TEXT NOT NULL DEFAULT '',
    operator_avatar_url        TEXT NOT NULL DEFAULT '',
    profile_claim_state        TEXT NOT NULL CHECK (profile_claim_state IN (
        '',
        'claimed',
        'pending-review'
    )),
    link_id                    TEXT NOT NULL DEFAULT '',
    related_deployment_id      TEXT NOT NULL DEFAULT '',
    source_audit_hash          TEXT NOT NULL UNIQUE,
    accepted_at                TEXT NOT NULL,
    CHECK (
        (claimed = 1 AND claim_state IN ('claimed', 'pending-review'))
        OR
        (claimed = 0 AND claim_state IN ('', 'withdrawn'))
    ),
    CHECK (
        (profile_claim_audit_index = 0 AND claim_group_id = '' AND profile_claim_state = '')
        OR
        (profile_claim_audit_index > 0 AND claim_group_id <> '' AND profile_claim_state <> '')
    ),
    CHECK (
        (claimed = 0 AND effective_group_id = '')
        OR
        (claimed = 1 AND effective_group_id <> '')
    ),
    CHECK (
        (link_id = '' AND related_deployment_id = '')
        OR
        (link_id <> '' AND related_deployment_id <> '' AND claimed = 1)
    )
);

CREATE INDEX operator_network_state_deployment_audit_idx
    ON operator_network_state_rows (deployment_id, audit_index DESC);
CREATE INDEX operator_network_state_group_audit_idx
    ON operator_network_state_rows (effective_group_id, audit_index DESC);
CREATE INDEX operator_network_state_claim_group_audit_idx
    ON operator_network_state_rows (claim_group_id, audit_index DESC);

-- Existing registries are backfilled once while this migration transaction is
-- exclusively applying the new schema. This is the only replay used to create
-- historical rows; normal reads never rebuild or repair them.
WITH
event_boundaries AS (
    SELECT
        audit_index AS state_audit_index,
        action_id,
        subject_deployment_id AS deployment_id,
        audit_hash AS source_audit_hash,
        accepted_at
    FROM operator_audit_events
),
claim_state_ranked AS (
    SELECT
        boundary.state_audit_index,
        state.audit_index AS claim_state_audit_index,
        state.claim_state,
        ROW_NUMBER() OVER (
            PARTITION BY boundary.state_audit_index
            ORDER BY state.audit_index DESC
        ) AS rank
    FROM event_boundaries boundary
    JOIN operator_audit_events state
      ON state.subject_deployment_id = boundary.deployment_id
     AND state.action_type IN ('claim', 'withdraw-claim')
     AND state.audit_index <= boundary.state_audit_index
),
claim_states AS (
    SELECT
        state_audit_index,
        claim_state_audit_index,
        claim_state
    FROM claim_state_ranked
    WHERE rank = 1
),
profile_ranked AS (
    SELECT
        boundary.state_audit_index,
        claim.audit_index AS profile_claim_audit_index,
        claim.group_id AS claim_group_id,
        claim.operator_name,
        claim.operator_avatar_url,
        claim.claim_state AS profile_claim_state,
        ROW_NUMBER() OVER (
            PARTITION BY boundary.state_audit_index
            ORDER BY claim.audit_index DESC
        ) AS rank
    FROM event_boundaries boundary
    JOIN operator_audit_events claim
      ON claim.subject_deployment_id = boundary.deployment_id
     AND claim.action_type = 'claim'
     AND claim.audit_index <= boundary.state_audit_index
),
profiles AS (
    SELECT
        state_audit_index,
        profile_claim_audit_index,
        claim_group_id,
        operator_name,
        operator_avatar_url,
        profile_claim_state
    FROM profile_ranked
    WHERE rank = 1
),
activity_ranked AS (
    SELECT
        boundary.state_audit_index,
        activity.action_type,
        ROW_NUMBER() OVER (
            PARTITION BY boundary.state_audit_index
            ORDER BY activity.audit_index DESC
        ) AS rank
    FROM event_boundaries boundary
    JOIN operator_audit_events activity
      ON activity.subject_deployment_id = boundary.deployment_id
     AND activity.action_type IN ('deactivate-deployment', 'reactivate-deployment')
     AND activity.audit_index <= boundary.state_audit_index
),
activities AS (
    SELECT state_audit_index, action_type
    FROM activity_ranked
    WHERE rank = 1
),
link_ranked AS (
    SELECT
        boundary.state_audit_index,
        redeem.group_id,
        redeem.link_id,
        redeem.related_deployment_id,
        ROW_NUMBER() OVER (
            PARTITION BY boundary.state_audit_index
            ORDER BY redeem.audit_index DESC
        ) AS rank
    FROM event_boundaries boundary
    JOIN claim_states claim_state
      ON claim_state.state_audit_index = boundary.state_audit_index
     AND claim_state.claim_state IN ('claimed', 'pending-review')
    JOIN operator_audit_events redeem
      ON redeem.subject_deployment_id = boundary.deployment_id
     AND redeem.action_type = 'redeem-client-token'
     AND redeem.audit_index > claim_state.claim_state_audit_index
     AND redeem.audit_index <= boundary.state_audit_index
    WHERE NOT EXISTS (
        SELECT 1
        FROM operator_audit_events revoked
        WHERE revoked.action_type = 'revoke-group-link'
          AND revoked.link_id = redeem.link_id
          AND revoked.audit_index > redeem.audit_index
          AND revoked.audit_index <= boundary.state_audit_index
    )
),
links AS (
    SELECT
        state_audit_index,
        group_id,
        link_id,
        related_deployment_id
    FROM link_ranked
    WHERE rank = 1
)
INSERT INTO operator_network_state_rows (
    audit_index,
    action_id,
    deployment_id,
    claimed,
    active,
    claim_state,
    claim_state_audit_index,
    profile_claim_audit_index,
    claim_group_id,
    effective_group_id,
    operator_name,
    operator_avatar_url,
    profile_claim_state,
    link_id,
    related_deployment_id,
    source_audit_hash,
    accepted_at
)
SELECT
    boundary.state_audit_index,
    boundary.action_id,
    boundary.deployment_id,
    CASE
        WHEN claim_state.claim_state IN ('claimed', 'pending-review') THEN 1
        ELSE 0
    END,
    CASE
        WHEN activity.action_type = 'deactivate-deployment' THEN 0
        ELSE 1
    END,
    COALESCE(claim_state.claim_state, ''),
    COALESCE(claim_state.claim_state_audit_index, 0),
    COALESCE(profile.profile_claim_audit_index, 0),
    COALESCE(profile.claim_group_id, ''),
    CASE
        WHEN claim_state.claim_state IN ('claimed', 'pending-review')
            THEN COALESCE(link.group_id, profile.claim_group_id, '')
        ELSE ''
    END,
    COALESCE(profile.operator_name, ''),
    COALESCE(profile.operator_avatar_url, ''),
    COALESCE(profile.profile_claim_state, ''),
    CASE
        WHEN claim_state.claim_state IN ('claimed', 'pending-review')
            THEN COALESCE(link.link_id, '')
        ELSE ''
    END,
    CASE
        WHEN claim_state.claim_state IN ('claimed', 'pending-review')
            THEN COALESCE(link.related_deployment_id, '')
        ELSE ''
    END,
    boundary.source_audit_hash,
    boundary.accepted_at
FROM event_boundaries boundary
LEFT JOIN claim_states claim_state
  ON claim_state.state_audit_index = boundary.state_audit_index
LEFT JOIN profiles profile
  ON profile.state_audit_index = boundary.state_audit_index
LEFT JOIN activities activity
  ON activity.state_audit_index = boundary.state_audit_index
LEFT JOIN links link
  ON link.state_audit_index = boundary.state_audit_index
ORDER BY boundary.state_audit_index;

CREATE TRIGGER operator_network_state_rows_no_update
BEFORE UPDATE ON operator_network_state_rows BEGIN
    SELECT RAISE(ABORT, 'operator network state rows are append-only');
END;
CREATE TRIGGER operator_network_state_rows_no_delete
BEFORE DELETE ON operator_network_state_rows BEGIN
    SELECT RAISE(ABORT, 'operator network state rows are append-only');
END;
