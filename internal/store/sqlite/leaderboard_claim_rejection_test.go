package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestLeaderboardRejectedClaimKeepsWeightButIsNotShareEligible(
	t *testing.T,
) {
	registryStore, err := Open(filepath.Join(t.TempDir(), "registry.db"))
	if err != nil {
		t.Fatalf("open rejected-claim leaderboard store: %v", err)
	}
	defer registryStore.Close()

	const (
		rejectedDeployment = "dep_leaderboard_rejected"
		rejectedAction     = "opa_leaderboard_rejected"
		rejectedGroup      = "opg_leaderboard_rejected"
		legacyDeployment   = "dep_leaderboard_legacy"
		legacyAction       = "opa_leaderboard_legacy"
		legacyGroup        = "opg_leaderboard_legacy"
		reviewID           = "opr_leaderboard_rejected"
		reviewHash         = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	)
	insertPreStateDeployment(
		t,
		registryStore.db,
		rejectedDeployment,
		"leaderboard-rejected",
	)
	insertPreStateDeployment(
		t,
		registryStore.db,
		legacyDeployment,
		"leaderboard-legacy",
	)
	insertLeaderboardClaimState(
		t,
		registryStore,
		1,
		rejectedAction,
		rejectedDeployment,
		rejectedGroup,
		"Rejected Cooperative",
		protocol.OperatorClaimStatePendingReview,
	)
	insertLeaderboardClaimState(
		t,
		registryStore,
		2,
		legacyAction,
		legacyDeployment,
		legacyGroup,
		"Legacy Cooperative",
		protocol.OperatorClaimStateClaimed,
	)
	insertLeaderboardPendingStatus(
		t,
		registryStore,
		rejectedAction,
		rejectedDeployment,
		rejectedGroup,
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
			reason_code,
			idempotency_key,
			reviewed_at,
			previous_review_hash,
			review_hash,
			registry_key_id,
			signature
		) VALUES (1, ?, ?, ?, ?, ?, 'rejected', ?, ?, ?, ?, ?, ?, ?, ?, zeroblob(64))`,
		reviewID,
		rejectedDeployment,
		rejectedAction,
		rejectedGroup,
		"Pending Cooperative",
		"network-review-team",
		"case:leaderboard-rejected",
		"identity-not-verified",
		"reject-leaderboard-claim",
		"2026-07-28T00:00:03Z",
		protocol.OperatorClaimReviewZeroHash,
		reviewHash,
		"registry-key",
	); err != nil {
		t.Fatalf("insert rejected claim review: %v", err)
	}
	if _, err := registryStore.db.Exec(`
		UPDATE operator_claim_status
		SET verification_state = 'rejected',
		    review_id = ?,
		    review_index = 1,
		    review_hash = ?,
		    updated_at = '2026-07-28T00:00:03Z'
		WHERE deployment_id = ?`,
		reviewID,
		reviewHash,
		rejectedDeployment,
	); err != nil {
		t.Fatalf("update rejected claim status: %v", err)
	}
	insertLeaderboardWeight(t, registryStore, 1, rejectedDeployment, 600)
	insertLeaderboardWeight(t, registryStore, 2, legacyDeployment, 300)

	totals, err := registryStore.LeaderboardTotals(
		context.Background(),
		"2026-01",
		"2026-06",
		2,
		2,
		1,
	)
	if err != nil {
		t.Fatalf("read rejected leaderboard totals: %v", err)
	}
	if totals.MeasuredWeight != 900 || totals.ClaimedWeight != 300 {
		t.Fatalf("rejected leaderboard totals = %+v", totals)
	}
	rows, err := registryStore.LeaderboardRows(
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
		t.Fatalf("read rejected leaderboard rows: %v", err)
	}
	if len(rows) != 2 ||
		rows[0].RowID != legacyGroup ||
		rows[0].SortWeight != 300 ||
		rows[1].RowID != rejectedGroup ||
		rows[1].ClaimState != protocol.OperatorClaimStateRejected ||
		rows[1].Weight != 600 ||
		rows[1].SortWeight != 0 {
		t.Fatalf("rejected leaderboard rows = %+v", rows)
	}
}
