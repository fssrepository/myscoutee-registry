-- Before this lifecycle rule, deactivation made a deployment inactive but left
-- its directly maintained claim and link state current. Preserve the immutable
-- audit/review sources and deterministically upgrade only the direct query
-- state. Normal writes remain dual writes; normal reads never replay or repair.
CREATE TEMP TABLE operator_deactivation_withdrawal_boundaries (
    deployment_id TEXT NOT NULL,
    audit_index    INTEGER NOT NULL,
    accepted_at   TEXT NOT NULL,
    PRIMARY KEY (deployment_id, audit_index)
);

INSERT INTO operator_deactivation_withdrawal_boundaries (
    deployment_id,
    audit_index,
    accepted_at
)
SELECT
    event.subject_deployment_id,
    event.audit_index,
    event.accepted_at
FROM operator_audit_events event
WHERE event.action_type = 'deactivate-deployment'
  AND COALESCE((
      SELECT prior.claimed
      FROM operator_network_state_rows prior
      WHERE prior.deployment_id = event.subject_deployment_id
        AND prior.audit_index < event.audit_index
      ORDER BY prior.audit_index DESC
      LIMIT 1
  ), 0) = 1;

DROP TRIGGER operator_network_state_rows_no_update;

UPDATE operator_network_state_rows
SET claimed = 0,
    claim_state = 'withdrawn',
    claim_state_audit_index = (
        SELECT MIN(boundary.audit_index)
        FROM operator_deactivation_withdrawal_boundaries boundary
        WHERE boundary.deployment_id =
                operator_network_state_rows.deployment_id
          AND boundary.audit_index <= operator_network_state_rows.audit_index
          AND NOT EXISTS (
              SELECT 1
              FROM operator_audit_events claim
              WHERE claim.subject_deployment_id =
                        operator_network_state_rows.deployment_id
                AND claim.audit_index > boundary.audit_index
                AND claim.audit_index <=
                        operator_network_state_rows.audit_index
                AND (
                    claim.action_type = 'claim'
                    OR (
                        claim.action_type = 'redeem-client-token'
                        AND claim.claim_state = 'pending-review'
                        AND claim.operator_name <> ''
                        AND claim.link_id = ''
                    )
                )
          )
    ),
    effective_group_id = '',
    link_id = '',
    related_deployment_id = ''
WHERE EXISTS (
    SELECT 1
    FROM operator_deactivation_withdrawal_boundaries boundary
    WHERE boundary.deployment_id =
            operator_network_state_rows.deployment_id
      AND boundary.audit_index <= operator_network_state_rows.audit_index
      AND NOT EXISTS (
          SELECT 1
          FROM operator_audit_events claim
          WHERE claim.subject_deployment_id =
                    operator_network_state_rows.deployment_id
            AND claim.audit_index > boundary.audit_index
            AND claim.audit_index <= operator_network_state_rows.audit_index
            AND (
                claim.action_type = 'claim'
                OR (
                    claim.action_type = 'redeem-client-token'
                    AND claim.claim_state = 'pending-review'
                    AND claim.operator_name <> ''
                    AND claim.link_id = ''
                )
            )
      )
);

CREATE TRIGGER operator_network_state_rows_no_update
BEFORE UPDATE ON operator_network_state_rows BEGIN
    SELECT RAISE(ABORT, 'operator network state rows are append-only');
END;

UPDATE operator_claim_status
SET verification_state = 'withdrawn',
    updated_at = (
        SELECT boundary.accepted_at
        FROM operator_deactivation_withdrawal_boundaries boundary
        WHERE boundary.deployment_id = operator_claim_status.deployment_id
          AND boundary.audit_index > operator_claim_status.claim_audit_index
        ORDER BY boundary.audit_index
        LIMIT 1
    )
WHERE verification_state IN ('pending-review', 'approved')
  AND EXISTS (
      SELECT 1
      FROM operator_deactivation_withdrawal_boundaries boundary
      WHERE boundary.deployment_id = operator_claim_status.deployment_id
        AND boundary.audit_index > operator_claim_status.claim_audit_index
  );

DROP TABLE operator_deactivation_withdrawal_boundaries;
