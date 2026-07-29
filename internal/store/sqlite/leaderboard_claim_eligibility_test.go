package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestLeaderboardPendingClaimKeepsMeasuredWeightButIsNotEligible(t *testing.T) {
	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open leaderboard eligibility store: %v", err)
	}
	defer registryStore.Close()

	const (
		pendingDeployment  = "dep_leaderboard_pending"
		pendingAction      = "opa_leaderboard_pending"
		pendingGroup       = "opg_leaderboard_pending"
		approvedDeployment = "dep_leaderboard_approved"
		approvedAction     = "opa_leaderboard_approved"
		approvedGroup      = "opg_leaderboard_approved"
	)
	insertPreStateDeployment(
		t,
		registryStore.db,
		pendingDeployment,
		"leaderboard-pending",
	)
	insertPreStateDeployment(
		t,
		registryStore.db,
		approvedDeployment,
		"leaderboard-approved",
	)
	insertLeaderboardClaimState(
		t,
		registryStore,
		1,
		pendingAction,
		pendingDeployment,
		pendingGroup,
		"Pending Cooperative",
		protocol.OperatorClaimStatePendingReview,
	)
	insertLeaderboardClaimState(
		t,
		registryStore,
		2,
		approvedAction,
		approvedDeployment,
		approvedGroup,
		"Approved Cooperative",
		protocol.OperatorClaimStateClaimed,
	)
	insertLeaderboardPendingStatus(
		t,
		registryStore,
		pendingAction,
		pendingDeployment,
		pendingGroup,
	)

	// The accepted v1 HTTP flow still admits only zero-count installation
	// batches. Seed positive immutable read rows directly so this query-focused
	// test exercises the future QMAU eligibility boundary.
	insertLeaderboardWeight(t, registryStore, 1, pendingDeployment, 600)
	insertLeaderboardWeight(t, registryStore, 2, approvedDeployment, 300)

	totals, err := registryStore.LeaderboardTotals(
		context.Background(),
		"2026-01",
		"2026-06",
		2,
		2,
		0,
	)
	if err != nil {
		t.Fatalf("read pending leaderboard totals: %v", err)
	}
	if totals.MeasuredWeight != 900 || totals.ClaimedWeight != 300 {
		t.Fatalf("pending leaderboard totals = %+v", totals)
	}

	rows, err := registryStore.LeaderboardRows(
		context.Background(),
		store.LeaderboardQuery{
			View:               "claimed",
			FromPeriod:         "2026-01",
			ThroughPeriod:      "2026-06",
			ThroughLedgerIndex: 2,
			ThroughAuditIndex:  2,
			ThroughReviewIndex: 0,
			Limit:              10,
		},
	)
	if err != nil {
		t.Fatalf("read pending leaderboard rows: %v", err)
	}
	if len(rows) != 2 ||
		rows[0].RowID != approvedGroup ||
		rows[0].ClaimState != protocol.OperatorClaimStateClaimed ||
		rows[0].Weight != 300 ||
		rows[0].SortWeight != 300 ||
		rows[1].RowID != pendingGroup ||
		rows[1].ClaimState != protocol.OperatorClaimStatePendingReview ||
		rows[1].Weight != 600 ||
		rows[1].SortWeight != 0 {
		t.Fatalf("pending leaderboard rows = %+v", rows)
	}

	insertLeaderboardApproval(
		t,
		registryStore,
		pendingAction,
		pendingDeployment,
		pendingGroup,
	)

	frozenTotals, err := registryStore.LeaderboardTotals(
		context.Background(),
		"2026-01",
		"2026-06",
		2,
		2,
		0,
	)
	if err != nil {
		t.Fatalf("read frozen pre-approval leaderboard totals: %v", err)
	}
	if frozenTotals != totals {
		t.Fatalf(
			"approval changed frozen leaderboard totals: before=%+v after=%+v",
			totals,
			frozenTotals,
		)
	}
	frozenRows, err := registryStore.LeaderboardRows(
		context.Background(),
		store.LeaderboardQuery{
			View:               "claimed",
			FromPeriod:         "2026-01",
			ThroughPeriod:      "2026-06",
			ThroughLedgerIndex: 2,
			ThroughAuditIndex:  2,
			ThroughReviewIndex: 0,
			Limit:              10,
		},
	)
	if err != nil {
		t.Fatalf("read frozen pre-approval leaderboard rows: %v", err)
	}
	if len(frozenRows) != 2 ||
		frozenRows[1].RowID != pendingGroup ||
		frozenRows[1].ClaimState != protocol.OperatorClaimStatePendingReview ||
		frozenRows[1].SortWeight != 0 {
		t.Fatalf("approval changed frozen leaderboard rows: %+v", frozenRows)
	}

	totals, err = registryStore.LeaderboardTotals(
		context.Background(),
		"2026-01",
		"2026-06",
		2,
		2,
		1,
	)
	if err != nil {
		t.Fatalf("read approved leaderboard totals: %v", err)
	}
	if totals.MeasuredWeight != 900 || totals.ClaimedWeight != 900 {
		t.Fatalf("approved leaderboard totals = %+v", totals)
	}
	rows, err = registryStore.LeaderboardRows(
		context.Background(),
		store.LeaderboardQuery{
			View:               "claimed",
			FromPeriod:         "2026-01",
			ThroughPeriod:      "2026-06",
			ThroughLedgerIndex: 2,
			ThroughAuditIndex:  2,
			ThroughReviewIndex: 1,
			Limit:              10,
		},
	)
	if err != nil {
		t.Fatalf("read approved leaderboard rows: %v", err)
	}
	if len(rows) != 2 ||
		rows[0].RowID != pendingGroup ||
		rows[0].ClaimState != protocol.OperatorClaimStateApproved ||
		rows[0].Weight != 600 ||
		rows[0].SortWeight != 600 {
		t.Fatalf("approved leaderboard rows = %+v", rows)
	}

	insertLeaderboardEligibilitySuspension(
		t,
		registryStore,
		pendingAction,
		pendingDeployment,
		pendingGroup,
	)
	suspendedTotals, err := registryStore.LeaderboardTotalsAtEligibility(
		context.Background(),
		"2026-01",
		"2026-06",
		2,
		2,
		1,
		1,
	)
	if err != nil {
		t.Fatalf("read suspended leaderboard totals: %v", err)
	}
	if suspendedTotals.MeasuredWeight != 900 ||
		suspendedTotals.ClaimedWeight != 300 {
		t.Fatalf(
			"suspended leaderboard totals = %+v",
			suspendedTotals,
		)
	}
	rows, err = registryStore.LeaderboardRows(
		context.Background(),
		store.LeaderboardQuery{
			View:                    "claimed",
			FromPeriod:              "2026-01",
			ThroughPeriod:           "2026-06",
			ThroughLedgerIndex:      2,
			ThroughAuditIndex:       2,
			ThroughReviewIndex:      1,
			ThroughEligibilityIndex: 1,
			Limit:                   10,
		},
	)
	if err != nil {
		t.Fatalf("read suspended leaderboard rows: %v", err)
	}
	if len(rows) != 2 ||
		rows[1].RowID != pendingGroup ||
		rows[1].Weight != 600 ||
		rows[1].SortWeight != 0 ||
		rows[1].EligibilityState !=
			protocol.OperatorEligibilitySuspended {
		t.Fatalf("suspended leaderboard rows = %+v", rows)
	}
}

func insertLeaderboardEligibilitySuspension(
	t *testing.T,
	registryStore *Store,
	actionID string,
	deploymentID string,
	groupID string,
) {
	t.Helper()
	if _, err := registryStore.db.Exec(`
		INSERT INTO operator_claim_eligibility_events (
			eligibility_index,
			eligibility_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			actor_id,
			decision_reference,
			reason_code,
			idempotency_key,
			decided_at,
			previous_eligibility_hash,
			eligibility_hash,
			registry_key_id,
			signature
		) VALUES (
			1, ?, ?, ?, ?, ?, 'suspend', ?, ?, ?, ?, ?, ?, ?, ?, zeroblob(64)
		)`,
		"ope_00000000000000000000000000000001",
		deploymentID,
		actionID,
		groupID,
		"Pending Cooperative",
		"leaderboard-eligibility",
		"case:leaderboard-suspension",
		"policy-hold",
		"suspend-leaderboard-pending",
		"2026-07-28T00:00:04Z",
		protocol.OperatorClaimEligibilityZeroHash,
		"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		"registry-key",
	); err != nil {
		t.Fatalf("insert leaderboard eligibility suspension: %v", err)
	}
}

func insertLeaderboardApproval(
	t *testing.T,
	registryStore *Store,
	actionID string,
	deploymentID string,
	groupID string,
) {
	t.Helper()
	const (
		reviewID   = "opr_leaderboard_pending"
		reviewHash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		reviewedAt = "2026-07-28T00:00:03Z"
	)
	if _, err := registryStore.db.Exec(`
		INSERT INTO operator_claim_reviews (
			review_index,
			review_id,
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			decision,
			reviewer_id,
			review_reference,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		) VALUES (1, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?, ?, ?, ?, zeroblob(64))`,
		reviewID,
		deploymentID,
		actionID,
		groupID,
		"Pending Cooperative",
		"leaderboard-reviewer",
		"case:leaderboard-pending",
		"approve-leaderboard-pending",
		reviewedAt,
		protocol.OperatorClaimReviewZeroHash,
		reviewHash,
		"registry-key",
	); err != nil {
		t.Fatalf("insert leaderboard approval review: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		UPDATE operator_claim_status
		SET verification_state = 'approved',
		    review_id = ?,
		    review_index = 1,
		    review_hash = ?,
		    approved_at = ?,
		    updated_at = ?
		WHERE deployment_id = ?`,
		reviewID,
		reviewHash,
		reviewedAt,
		reviewedAt,
		deploymentID,
	); err != nil {
		t.Fatalf("update current leaderboard approval status: %v", err)
	}
}

func insertLeaderboardClaimState(
	t *testing.T,
	registryStore *Store,
	auditIndex int64,
	actionID string,
	deploymentID string,
	groupID string,
	operatorName string,
	claimState string,
) {
	t.Helper()
	auditHash := "sha256:leaderboard-" + actionID
	insertPreStateOperatorEvent(
		t,
		registryStore.db,
		auditIndex,
		actionID,
		deploymentID,
		deploymentID,
		"",
		protocol.OperatorActionClaim,
		operatorName,
		claimState,
		groupID,
		"",
		auditHash,
	)
	if _, err := registryStore.db.Exec(`
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
		) VALUES (?, ?, ?, 1, 1, ?, ?, ?, ?, ?, ?, '', ?, '', '', ?, ?)`,
		auditIndex,
		actionID,
		deploymentID,
		claimState,
		auditIndex,
		auditIndex,
		groupID,
		groupID,
		operatorName,
		claimState,
		auditHash,
		"2026-07-28T00:00:01Z",
	); err != nil {
		t.Fatalf("insert leaderboard claim state %s: %v", deploymentID, err)
	}
}

func insertLeaderboardPendingStatus(
	t *testing.T,
	registryStore *Store,
	actionID string,
	deploymentID string,
	groupID string,
) {
	t.Helper()
	if _, err := registryStore.db.Exec(`
		INSERT INTO operator_claim_verification_submissions (
			claim_action_id,
			deployment_id,
			group_id,
			legal_name,
			registration_number,
			jurisdiction,
			registered_address,
			website,
			verification_contact_name,
			verification_contact_role,
			verification_contact_email,
			authority_attested,
			operator_avatar_url,
			payload_hash,
			submitted_at,
			private_record_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '', ?, ?, ?)`,
		actionID,
		deploymentID,
		groupID,
		"Pending Cooperative",
		"REG-PENDING",
		"Slovakia",
		"Pending Street 1",
		"https://pending.example.test",
		"Pending Reviewer",
		"Director",
		"reviewer@pending.example.test",
		"payload-"+actionID,
		"2026-07-28T00:00:01Z",
		"sha256:private-"+actionID,
	); err != nil {
		t.Fatalf("insert pending leaderboard submission: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		INSERT INTO operator_claim_status (
			deployment_id,
			claim_action_id,
			claim_audit_index,
			claim_audit_hash,
			group_id,
			legal_name,
			verification_state,
			submitted_at,
			review_id,
			review_index,
			review_hash,
			approved_at,
			updated_at,
			private_record_hash
		) VALUES (?, ?, 1, ?, ?, ?, 'pending-review', ?, '', 0, ?, '', ?, ?)`,
		deploymentID,
		actionID,
		"sha256:leaderboard-"+actionID,
		groupID,
		"Pending Cooperative",
		"2026-07-28T00:00:01Z",
		protocol.OperatorClaimReviewZeroHash,
		"2026-07-28T00:00:01Z",
		"sha256:private-"+actionID,
	); err != nil {
		t.Fatalf("insert pending leaderboard status: %v", err)
	}
}

func insertLeaderboardWeight(
	t *testing.T,
	registryStore *Store,
	ledgerIndex int64,
	deploymentID string,
	weight int64,
) {
	t.Helper()
	entryHash := "sha256:leaderboard-entry-" + deploymentID
	if _, err := registryStore.db.Exec(`
		INSERT INTO ledger_entries (
			ledger_index,
			protocol_version,
			registry_scope,
			entry_type,
			deployment_id,
			batch_id,
			kind,
			period,
			ruleset_version,
			qualified_mau_count,
			batch_hash,
			previous_entry_hash,
			entry_hash,
			accepted_at
		) VALUES (?, '1', 'test:leaderboard', 'INSTALLATION_TEST_BATCH_ACCEPTED', ?, ?, 'installation-test', '2026-06', 'installation-test-v1', 0, ?, ?, ?, ?)`,
		ledgerIndex,
		deploymentID,
		"batch-"+deploymentID,
		"sha256:batch-"+deploymentID,
		"sha256:previous-"+deploymentID,
		entryHash,
		"2026-07-28T00:00:02Z",
	); err != nil {
		t.Fatalf("insert leaderboard ledger entry %s: %v", deploymentID, err)
	}
	if _, err := registryStore.db.Exec(`
		INSERT INTO ledger_weight_rows (
			ledger_index,
			deployment_id,
			period,
			ruleset_version,
			qualified_mau_count,
			weight_numerator,
			weight_denominator,
			accepted_at,
			source_entry_hash
		) VALUES (?, ?, '2026-06', 'future-qmau-test-v1', ?, ?, 1, ?, ?)`,
		ledgerIndex,
		deploymentID,
		weight,
		weight,
		"2026-07-28T00:00:02Z",
		entryHash,
	); err != nil {
		t.Fatalf("insert leaderboard weight %s: %v", deploymentID, err)
	}
}
