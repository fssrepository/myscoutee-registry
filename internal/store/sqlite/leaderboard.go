package sqlite

import (
	"context"
	"fmt"

	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const leaderboardStateCTE = `
	WITH
	bounds(
		audit_bound,
		ledger_bound,
		review_bound,
		eligibility_bound,
		from_period,
		through_period
	) AS (
		VALUES (?, ?, ?, ?, ?, ?)
	),
	state_ranked AS (
		SELECT
			deployment_id,
			claimed,
			active,
			claim_state,
			claim_state_audit_index,
			claim_group_id,
			effective_group_id,
			operator_name,
			operator_avatar_url,
			profile_claim_state,
			link_id,
			related_deployment_id,
			profile_claim_audit_index,
			audit_index,
			ROW_NUMBER() OVER (
				PARTITION BY deployment_id
				ORDER BY audit_index DESC
			) AS rank
		FROM operator_network_state_rows
		WHERE audit_index <= (SELECT audit_bound FROM bounds)
	),
	states AS (
		SELECT
			deployment_id,
			claimed,
			active,
			claim_state,
			claim_state_audit_index,
			claim_group_id,
			effective_group_id,
			operator_name,
			operator_avatar_url,
			profile_claim_state,
			link_id,
			related_deployment_id,
			profile_claim_audit_index,
			audit_index
		FROM state_ranked
		WHERE rank = 1
	),
	membership_states AS (
		SELECT
			deployment.deployment_id,
			COALESCE(state.claimed, 0) AS claimed,
			CASE
				WHEN state.claim_state = 'pending-review'
				 AND review.decision = 'approved'
					THEN 'approved'
				WHEN state.claim_state = 'pending-review'
				 AND review.decision = 'rejected'
					THEN 'rejected'
				ELSE COALESCE(state.claim_state, '')
			END AS claim_state,
			COALESCE(state.active, 1) AS active,
			COALESCE(state.effective_group_id, '') AS group_id,
			COALESCE(state.link_id, '') AS link_id,
			COALESCE(claim.action_id, '') AS claim_action_id
		FROM deployments deployment
		LEFT JOIN states state
		  ON state.deployment_id = deployment.deployment_id
		LEFT JOIN operator_audit_events claim
		  ON claim.audit_index = state.claim_state_audit_index
		LEFT JOIN operator_claim_reviews review
		  ON review.claim_action_id = claim.action_id
		 AND review.review_index <= (SELECT review_bound FROM bounds)
	),
	eligibility_ranked AS (
		SELECT
			claim_action_id,
			decision,
			ROW_NUMBER() OVER (
				PARTITION BY claim_action_id
				ORDER BY eligibility_index DESC
			) AS rank
		FROM operator_claim_eligibility_events
		WHERE eligibility_index <=
			(SELECT eligibility_bound FROM bounds)
	),
	eligibility_decisions AS (
		SELECT claim_action_id, decision
		FROM eligibility_ranked
		WHERE rank = 1
	),
	memberships AS (
		SELECT
			membership_state.*,
			CASE
				WHEN membership_state.claim_state = 'claimed'
					THEN 'active'
				WHEN membership_state.claim_state = 'approved'
				 AND eligibility.decision = 'suspend'
					THEN 'suspended'
				WHEN membership_state.claim_state = 'approved'
					THEN 'active'
				ELSE 'inactive'
			END AS eligibility_state,
			CASE
				WHEN membership_state.claim_state = 'claimed'
					THEN 1
				WHEN membership_state.claim_state = 'approved'
				 AND COALESCE(eligibility.decision, '') <> 'suspend'
					THEN 1
				ELSE 0
			END AS eligible
		FROM membership_states membership_state
		LEFT JOIN eligibility_decisions eligibility
		  ON eligibility.claim_action_id =
			membership_state.claim_action_id
	),
	group_profile_ranked AS (
		SELECT
			state.claim_group_id AS group_id,
			state.operator_name,
			state.operator_avatar_url,
			CASE
				WHEN state.profile_claim_state = 'pending-review'
				 AND review.decision = 'approved'
					THEN 'approved'
				WHEN state.profile_claim_state = 'pending-review'
				 AND review.decision = 'rejected'
					THEN 'rejected'
				ELSE state.profile_claim_state
			END AS claim_state,
			ROW_NUMBER() OVER (
				PARTITION BY state.claim_group_id
				ORDER BY
					state.profile_claim_audit_index DESC,
					state.audit_index DESC
			) AS rank
		FROM states state
		LEFT JOIN operator_audit_events claim
		  ON claim.audit_index = state.profile_claim_audit_index
		LEFT JOIN operator_claim_reviews review
		  ON review.claim_action_id = claim.action_id
		 AND review.review_index <= (SELECT review_bound FROM bounds)
		WHERE state.active = 1
		  AND state.claimed = 1
		  AND state.claim_group_id <> ''
		  AND state.profile_claim_state IN ('claimed', 'pending-review')
	),
	group_profiles AS (
		SELECT group_id, operator_name, operator_avatar_url, claim_state
		FROM group_profile_ranked
		WHERE rank = 1
	),
	weight_revisions AS (
		SELECT
			deployment_id,
			period,
			weight_numerator,
			ROW_NUMBER() OVER (
				PARTITION BY deployment_id, period
				ORDER BY revision DESC, ledger_index DESC
			) AS rank
		FROM ledger_weight_rows
		WHERE ledger_index <= (SELECT ledger_bound FROM bounds)
		  AND period >= (SELECT from_period FROM bounds)
		  AND period <= (SELECT through_period FROM bounds)
	),
	deployment_weights AS (
		SELECT
			deployment_id,
			COALESCE(SUM(weight_numerator), 0) AS weight
		FROM weight_revisions
		WHERE rank = 1
			GROUP BY deployment_id
	),
	weighted_memberships AS (
		SELECT
			membership.*,
			COALESCE(weight.weight, 0) AS measured_weight,
			CASE
				WHEN membership.eligible = 1
					THEN COALESCE(weight.weight, 0)
				ELSE 0
			END AS eligible_weight
		FROM memberships membership
		LEFT JOIN deployment_weights weight
		  ON weight.deployment_id = membership.deployment_id
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
	reviewHead, err := operatorClaimReviewHeadQuery(ctx, sqliteStore.db)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	eligibilityHead, err := operatorClaimEligibilityHeadQuery(
		ctx,
		sqliteStore.db,
	)
	if err != nil {
		return store.LeaderboardBoundary{}, err
	}
	return store.LeaderboardBoundary{
		LedgerIndex:      ledgerHead.LedgerIndex,
		AuditIndex:       auditHead.AuditIndex,
		ReviewIndex:      reviewHead.ReviewIndex,
		EligibilityIndex: eligibilityHead.EligibilityIndex,
		LedgerHash:       ledgerHead.EntryHash,
		AuditHash:        auditHead.AuditHash,
		ReviewHash:       reviewHead.ReviewHash,
		EligibilityHash:  eligibilityHead.EligibilityHash,
	}, nil
}

func (sqliteStore *Store) LeaderboardTotals(
	ctx context.Context,
	fromPeriod string,
	throughPeriod string,
	throughLedgerIndex int64,
	throughAuditIndex int64,
	throughReviewIndex int64,
) (store.LeaderboardTotals, error) {
	return sqliteStore.LeaderboardTotalsAtEligibility(
		ctx,
		fromPeriod,
		throughPeriod,
		throughLedgerIndex,
		throughAuditIndex,
		throughReviewIndex,
		0,
	)
}

func (sqliteStore *Store) LeaderboardTotalsAtEligibility(
	ctx context.Context,
	fromPeriod string,
	throughPeriod string,
	throughLedgerIndex int64,
	throughAuditIndex int64,
	throughReviewIndex int64,
	throughEligibilityIndex int64,
) (store.LeaderboardTotals, error) {
	var totals store.LeaderboardTotals
	err := sqliteStore.db.QueryRowContext(
		ctx,
		leaderboardStateCTE+`
		SELECT
			COALESCE(SUM(membership.measured_weight), 0),
			COALESCE(SUM(
				CASE
					WHEN membership.active = 1 AND membership.claimed = 1
						THEN membership.eligible_weight
					ELSE 0
				END
			), 0)
		FROM weighted_memberships membership`,
		throughAuditIndex,
		throughLedgerIndex,
		throughReviewIndex,
		throughEligibilityIndex,
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
			,
			claimed_rows AS (
				SELECT
					membership.group_id AS row_id,
					COALESCE(
						NULLIF(profile.operator_name, ''),
						membership.group_id
					) AS label,
					COALESCE(profile.operator_avatar_url, '') AS avatar_url,
					COALESCE(
						NULLIF(profile.claim_state, ''),
						'claimed'
					) AS claim_state,
					COUNT(*) AS deployment_count,
					COALESCE(SUM(membership.measured_weight), 0) AS weight,
					CASE
						WHEN COALESCE(
							NULLIF(profile.claim_state, ''),
							'claimed'
						) = 'pending-review'
							THEN 0
						ELSE COALESCE(SUM(membership.eligible_weight), 0)
					END AS sort_weight,
					CASE
						WHEN SUM(
							CASE
								WHEN membership.eligibility_state =
									'suspended'
									THEN 1
								ELSE 0
							END
						) = 0
						 AND SUM(membership.eligible) = 0
							THEN 'inactive'
						WHEN SUM(
							CASE
								WHEN membership.eligibility_state =
									'suspended'
									THEN 1
								ELSE 0
							END
						) = 0
							THEN 'active'
						WHEN SUM(membership.eligible) > 0
							THEN 'partially-suspended'
						ELSE 'suspended'
					END AS eligibility_state
				FROM weighted_memberships membership
				LEFT JOIN group_profiles profile
				  ON profile.group_id = membership.group_id
				WHERE membership.active = 1
				  AND membership.claimed = 1
				  AND membership.group_id <> ''
				GROUP BY
					membership.group_id,
					profile.operator_name,
					profile.operator_avatar_url,
					profile.claim_state
			)
			SELECT
				row_id,
				'claimed',
				row_id,
				label,
				avatar_url,
				claim_state,
				deployment_count,
				weight,
				sort_weight,
				eligibility_state
			FROM claimed_rows
			WHERE (
				? = 0
				OR sort_weight < ?
				OR (
					sort_weight = ?
					AND row_id > ?
				)
			)
			ORDER BY sort_weight DESC, row_id
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
				membership.measured_weight,
				membership.measured_weight,
				'inactive'
			FROM weighted_memberships membership
			WHERE membership.active = 1
			  AND membership.claimed = 0
			  AND (
				? = 0
				OR membership.measured_weight < ?
				OR (
					membership.measured_weight = ?
					AND membership.deployment_id > ?
				)
			  )
			ORDER BY membership.measured_weight DESC, membership.deployment_id
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
		query.ThroughReviewIndex,
		query.ThroughEligibilityIndex,
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
			&record.SortWeight,
			&record.EligibilityState,
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
			membership.eligibility_state,
			CASE
				WHEN membership.link_id = '' THEN 'owner'
				ELSE 'linked'
			END,
			membership.measured_weight,
			membership.eligible_weight
		FROM weighted_memberships membership
		WHERE membership.active = 1
		  AND membership.claimed = 1
		  AND membership.group_id = ?
		  AND (
			? = 0
			OR membership.eligible_weight < ?
			OR (
				membership.eligible_weight = ?
				AND membership.deployment_id > ?
			)
		  )
		ORDER BY membership.eligible_weight DESC, membership.deployment_id
		LIMIT ?`,
		query.ThroughAuditIndex,
		query.ThroughLedgerIndex,
		query.ThroughReviewIndex,
		query.ThroughEligibilityIndex,
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
			&record.EligibilityState,
			&record.MembershipState,
			&record.Weight,
			&record.SortWeight,
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
