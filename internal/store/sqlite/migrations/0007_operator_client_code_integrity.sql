-- Token-derived claims name the exact approved private submission they copy.
-- Empty defaults preserve the canonical v1 representation of every existing
-- operator action. Only anchored token-derived redemptions use canonical v2.
ALTER TABLE operator_audit_events
    ADD COLUMN source_claim_action_id TEXT NOT NULL DEFAULT '';

ALTER TABLE operator_audit_events
    ADD COLUMN source_private_record_hash TEXT NOT NULL DEFAULT ''
    CHECK (
        (
            source_claim_action_id = ''
            AND source_private_record_hash = ''
        )
        OR
        (
            action_type = 'redeem-client-token'
            AND claim_state = 'pending-review'
            AND link_id = ''
            AND operator_name <> ''
            AND source_claim_action_id <> ''
            AND source_private_record_hash <> ''
        )
    );

-- Client codes accepted after this migration are single-use. The application
-- also reconstructs this invariant from the append-only audit stream.
CREATE UNIQUE INDEX operator_audit_events_redeem_token_once_idx
    ON operator_audit_events (token_id)
    WHERE action_type = 'redeem-client-token';
