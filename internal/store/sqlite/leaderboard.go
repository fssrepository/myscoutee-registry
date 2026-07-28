package sqlite

import (
	"context"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const leaderboardStateCTE = `
	WITH
	bounds(audit_bound, ledger_bound, from_period, through_period) AS (
		VALUES (?, ?, ?, ?)
	),
	claim_ranked AS (
		SELECT
			subject_deployment_id AS deployment_id,
			claim_state,
			group_id,
			operator_name,
			operator_avatar_url,
			audit_index,
			ROW_NUMBER() OVER (
				PARTITION BY subject_deployment_id
				ORDER BY audit_index DESC
			) AS rank
		FROM operator_audit_events
		WHERE action_type IN ('claim', 'withdraw-claim')
		  AND audit_index <= (SELECT audit_bound FROM bounds)
	),
	claims AS (
		SELECT
			deployment_id,
			claim_state,
			group_id,
			operator_name,
			operator_avatar_url,
			audit_index
		FROM claim_ranked
		WHERE rank = 1
	),
	activity_ranked AS (
		SELECT
			subject_deployment_id AS deployment_id,
			action_type,
			ROW_NUMBER() OVER (
				PARTITION BY subject_deployment_id
				ORDER BY audit_index DESC
			) AS rank
		FROM operator_audit_events
		WHERE action_type IN ('deactivate-deployment', 'reactivate-deployment')
		  AND audit_index <= (SELECT audit_bound FROM bounds)
	),
	activity AS (
		SELECT deployment_id, action_type
		FROM activity_ranked
		WHERE rank = 1
	),
	link_ranked AS (
		SELECT
			redeem.subject_deployment_id AS deployment_id,
			redeem.related_deployment_id,
			redeem.group_id,
			redeem.link_id,
			ROW_NUMBER() OVER (
				PARTITION BY redeem.subject_deployment_id
				ORDER BY redeem.audit_index DESC
			) AS rank
		FROM operator_audit_events redeem
			JOIN claims claim
			  ON claim.deployment_id = redeem.subject_deployment_id
			 AND claim.claim_state IN ('claimed', 'pending-review')
		 AND redeem.audit_index > claim.audit_index
		WHERE redeem.action_type = 'redeem-client-token'
		  AND redeem.audit_index <= (SELECT audit_bound FROM bounds)
		  AND NOT EXISTS (
			SELECT 1
			FROM operator_audit_events revoked
			WHERE revoked.action_type = 'revoke-group-link'
			  AND revoked.link_id = redeem.link_id
			  AND revoked.audit_index > redeem.audit_index
			  AND revoked.audit_index <= (SELECT audit_bound FROM bounds)
		  )
	),
	links AS (
		SELECT deployment_id, related_deployment_id, group_id, link_id
		FROM link_ranked
		WHERE rank = 1
	),
	memberships AS (
		SELECT
			deployment.deployment_id,
				CASE
					WHEN claim.claim_state IN ('claimed', 'pending-review') THEN 1
					ELSE 0
				END AS claimed,
				COALESCE(claim.claim_state, '') AS claim_state,
			CASE
				WHEN activity.action_type = 'deactivate-deployment' THEN 0
				ELSE 1
			END AS active,
				CASE
					WHEN claim.claim_state IN ('claimed', 'pending-review')
						THEN COALESCE(link.group_id, claim.group_id)
				ELSE ''
			END AS group_id,
			COALESCE(link.link_id, '') AS link_id
		FROM deployments deployment
		LEFT JOIN claims claim
		  ON claim.deployment_id = deployment.deployment_id
		LEFT JOIN activity
		  ON activity.deployment_id = deployment.deployment_id
		LEFT JOIN links link
		  ON link.deployment_id = deployment.deployment_id
	),
	group_profile_ranked AS (
		SELECT
				group_id,
				operator_name,
				operator_avatar_url,
				claim_state,
			ROW_NUMBER() OVER (
				PARTITION BY group_id
				ORDER BY audit_index DESC
			) AS rank
		FROM operator_audit_events
			WHERE action_type = 'claim'
			  AND claim_state IN ('claimed', 'pending-review')
		  AND audit_index <= (SELECT audit_bound FROM bounds)
	),
	group_profiles AS (
			SELECT group_id, operator_name, operator_avatar_url, claim_state
		FROM group_profile_ranked
		WHERE rank = 1
	),
	deployment_weights AS (
		SELECT
			deployment_id,
			COALESCE(SUM(weight_numerator), 0) AS weight
		FROM ledger_weight_rows
		WHERE ledger_index <= (SELECT ledger_bound FROM bounds)
		  AND period >= (SELECT from_period FROM bounds)
		  AND period <= (SELECT through_period FROM bounds)
		GROUP BY deployment_id
	)`

func (sqliteStore *Store) LeaderboardBoundary(
	ctx context.Context,
) (store.LeaderboardBoundary, error) {
	ledgerHead, err := sqliteStore.LedgerHead(ctx)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	auditHead, err := sqliteStore.OperatorAuditHead(ctx)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	return store.LeaderboardBoundary{
		LedgerIndex: ledgerHead.LedgerIndex,
		AuditIndex:  auditHead.AuditIndex,
		LedgerHash:  ledgerHead.EntryHash,
		AuditHash:   auditHead.AuditHash,
	}, nil
}

func (sqliteStore *Store) LeaderboardTotals(
	ctx context.Context,
	fromPeriod string,
	throughPeriod string,
	throughLedgerIndex int64,
	throughAuditIndex int64,
) (store.LeaderboardTotals, error) {
	var totals store.LeaderboardTotals
	err := sqliteStore.db.QueryRowContext(
		ctx,
		leaderboardStateCTE+`
		SELECT
			COALESCE(SUM(weight.weight), 0),
			COALESCE(SUM(
				CASE
					WHEN membership.active = 1 AND membership.claimed = 1
						THEN weight.weight
					ELSE 0
				END
			), 0)
		FROM memberships membership
		LEFT JOIN deployment_weights weight
		  ON weight.deployment_id = membership.deployment_id`,
		throughAuditIndex,
		throughLedgerIndex,
		fromPeriod,
		throughPeriod,
	).Scan(&totals.MeasuredWeight, &totals.ClaimedWeight)
	if err != nil {
		return store.LeaderboardTotals{}, fmt.Errorf("read leaderboard totals: %w", err)
	}
	return totals, nil
}

func (sqliteStore *Store) LeaderboardRows(
	ctx context.Context,
	query store.LeaderboardQuery,
) ([]store.LeaderboardRecord, error) {
	var statement string
	switch query.View {
	case "claimed":
		statement = leaderboardStateCTE + `
				SELECT
					membership.group_id,
					'claimed',
					membership.group_id,
					COALESCE(NULLIF(profile.operator_name, ''), membership.group_id),
					COALESCE(profile.operator_avatar_url, ''),
					COALESCE(NULLIF(profile.claim_state, ''), 'pending-review'),
				COUNT(*),
				COALESCE(SUM(weight.weight), 0)
			FROM memberships membership
			LEFT JOIN group_profiles profile
			  ON profile.group_id = membership.group_id
			LEFT JOIN deployment_weights weight
			  ON weight.deployment_id = membership.deployment_id
			WHERE membership.active = 1
			  AND membership.claimed = 1
			  AND membership.group_id <> ''
			GROUP BY
				membership.group_id,
					profile.operator_name,
					profile.operator_avatar_url,
					profile.claim_state
			HAVING (
				? = 0
				OR COALESCE(SUM(weight.weight), 0) < ?
				OR (
					COALESCE(SUM(weight.weight), 0) = ?
					AND membership.group_id > ?
				)
			)
			ORDER BY COALESCE(SUM(weight.weight), 0) DESC, membership.group_id
			LIMIT ?`
	case "unclaimed":
		statement = leaderboardStateCTE + `
			SELECT
				membership.deployment_id,
				'unclaimed',
				'',
				membership.deployment_id,
				'',
				'unclaimed',
				1,
				COALESCE(weight.weight, 0)
			FROM memberships membership
			LEFT JOIN deployment_weights weight
			  ON weight.deployment_id = membership.deployment_id
			WHERE membership.active = 1
			  AND membership.claimed = 0
			  AND (
				? = 0
				OR COALESCE(weight.weight, 0) < ?
				OR (
					COALESCE(weight.weight, 0) = ?
					AND membership.deployment_id > ?
				)
			  )
			ORDER BY COALESCE(weight.weight, 0) DESC, membership.deployment_id
			LIMIT ?`
	default:
		return nil, fmt.Errorf("unsupported leaderboard view %q", query.View)
	}

	hasAfter := 0
	if query.HasAfter {
		hasAfter = 1
	}
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		statement,
		query.ThroughAuditIndex,
		query.ThroughLedgerIndex,
		query.FromPeriod,
		query.ThroughPeriod,
		hasAfter,
		query.AfterWeight,
		query.AfterWeight,
		query.AfterID,
		query.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("read leaderboard %s rows: %w", query.View, err)
	}
	defer rows.Close()

	records := make([]store.LeaderboardRecord, 0, query.Limit)
	for rows.Next() {
		var record store.LeaderboardRecord
		if err := rows.Scan(
			&record.RowID,
			&record.View,
			&record.GroupID,
			&record.Label,
			&record.AvatarURL,
			&record.ClaimState,
			&record.DeploymentCount,
			&record.Weight,
		); err != nil {
			return nil, fmt.Errorf("scan leaderboard row: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leaderboard rows: %w", err)
	}
	return records, nil
}

func (sqliteStore *Store) LeaderboardDeployments(
	ctx context.Context,
	query store.LeaderboardDeploymentQuery,
) ([]store.LeaderboardDeploymentRecord, error) {
	hasAfter := 0
	if query.HasAfter {
		hasAfter = 1
	}
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		leaderboardStateCTE+`
		SELECT
			membership.deployment_id,
			membership.group_id,
				membership.claim_state,
			CASE
				WHEN membership.link_id = '' THEN 'owner'
				ELSE 'linked'
			END,
			COALESCE(weight.weight, 0)
		FROM memberships membership
		LEFT JOIN deployment_weights weight
		  ON weight.deployment_id = membership.deployment_id
		WHERE membership.active = 1
		  AND membership.claimed = 1
		  AND membership.group_id = ?
		  AND (
			? = 0
			OR COALESCE(weight.weight, 0) < ?
			OR (
				COALESCE(weight.weight, 0) = ?
				AND membership.deployment_id > ?
			)
		  )
		ORDER BY COALESCE(weight.weight, 0) DESC, membership.deployment_id
		LIMIT ?`,
		query.ThroughAuditIndex,
		query.ThroughLedgerIndex,
		query.FromPeriod,
		query.ThroughPeriod,
		query.GroupID,
		hasAfter,
		query.AfterWeight,
		query.AfterWeight,
		query.AfterID,
		query.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("read leaderboard group deployments: %w", err)
	}
	defer rows.Close()

	records := make([]store.LeaderboardDeploymentRecord, 0, query.Limit)
	for rows.Next() {
		var record store.LeaderboardDeploymentRecord
		if err := rows.Scan(
			&record.DeploymentID,
			&record.GroupID,
			&record.ClaimState,
			&record.MembershipState,
			&record.Weight,
		); err != nil {
			return nil, fmt.Errorf("scan leaderboard group deployment: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate leaderboard group deployments: %w", err)
	}
	return records, nil
}
