package service

import (
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestLeaderboardShareExcludesPendingClaim(t *testing.T) {
	registry := &Service{}
	snapshot := protocol.LeaderboardSnapshotDto{
		FounderShareNumerator:   "1",
		FounderShareDenominator: "4",
	}
	totals := store.LeaderboardTotals{
		MeasuredWeight: 900,
		ClaimedWeight:  300,
	}

	pending := registry.leaderboardShare(
		"claimed",
		protocol.OperatorClaimStatePendingReview,
		600,
		totals,
		snapshot,
	)
	if pending.Sign() != 0 {
		t.Fatalf("pending claim share = %s, want 0", pending.RatString())
	}

	rejected := registry.leaderboardShare(
		"claimed",
		protocol.OperatorClaimStateRejected,
		600,
		totals,
		snapshot,
	)
	if rejected.Sign() != 0 {
		t.Fatalf("rejected claim share = %s, want 0", rejected.RatString())
	}

	approved := registry.leaderboardShare(
		"claimed",
		protocol.OperatorClaimStateApproved,
		300,
		totals,
		snapshot,
	)
	if approved.RatString() != "3/4" {
		t.Fatalf("approved claim share = %s, want 3/4", approved.RatString())
	}
}
