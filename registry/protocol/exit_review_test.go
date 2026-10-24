package protocol

import "testing"

func TestExitReviewMembershipAndSettlementHashesCommitToOrder(t *testing.T) {
	t.Parallel()
	members := []ExitReviewDeployment{
		{
			MemberOrder:       0,
			DeploymentID:     "dep_0123456789abcdef0123456789abcdef",
			ClaimActionID:    "opa_0123456789abcdef0123456789abcdef",
			ClaimState:       "approved",
			EligibilityState: "active",
			ClaimAuditIndex:  1,
			ClaimAuditHash:   ZeroHash,
			ReviewIndex:      1,
			ReviewHash:       ZeroHash,
			EligibilityIndex: 0,
			EligibilityHash:  ZeroHash,
		},
		{
			MemberOrder:       1,
			DeploymentID:     "dep_1123456789abcdef0123456789abcdef",
			ClaimActionID:    "opa_1123456789abcdef0123456789abcdef",
			ClaimState:       "approved",
			EligibilityState: "active",
			ClaimAuditIndex:  2,
			ClaimAuditHash:   ZeroHash,
			ReviewIndex:      2,
			ReviewHash:       ZeroHash,
			EligibilityIndex: 0,
			EligibilityHash:  ZeroHash,
		},
	}
	forward := ExitReviewMembershipHash(members)
	reversed := ExitReviewMembershipHash([]ExitReviewDeployment{
		members[1],
		members[0],
	})
	if forward == reversed || !IsDigest(forward) || !IsDigest(reversed) {
		t.Fatalf("membership hash must be canonical and order-sensitive")
	}

	boundaries := []ExitReviewSettlementBoundary{
		{
			BoundaryOrder:     0,
			SettlementID:      "stl_0123456789abcdef0123456789abcdef",
			Period:            "2026-06",
			CurrencyCode:      "EUR",
			Revision:          1,
			LedgerIndex:       9,
			SettlementHash:    ZeroHash,
			SourceFingerprint: ZeroHash,
			AllocationHash:    ZeroHash,
		},
	}
	first := ExitReviewSettlementBoundaryHash(boundaries)
	boundaries[0].Revision = 2
	second := ExitReviewSettlementBoundaryHash(boundaries)
	if first == second || !IsDigest(first) || !IsDigest(second) {
		t.Fatalf("settlement boundary hash must commit to exact revisions")
	}
}

func TestExitReviewEventHashCommitsToBothChains(t *testing.T) {
	t.Parallel()
	event := ExitReviewEvent{
		EventIndex:              2,
		EventID:                 "exe_0123456789abcdef0123456789abcdef",
		ReviewID:                "exr_0123456789abcdef0123456789abcdef",
		Action:                  ExitReviewActionVerify,
		ResultingStatus:         ExitReviewStatusEligible,
		EffectiveDate:           "2026-07-29",
		ActorRole:               ExitReviewActorAuditor,
		ActorID:                 "audit-team",
		Reference:               "exit:2026-0042",
		EvidenceHash:            ZeroHash,
		IdempotencyKey:          "verify-exit-2026-0042",
		PayloadHash:             ZeroHash,
		RecordHash:              ZeroHash,
		AcceptedAt:              "2026-07-29T10:00:00Z",
		PreviousEventHash:       ZeroHash,
		PreviousReviewEventHash: ZeroHash,
		RegistryScope:           "example:registry",
		RegistryKeyID:           "rkey_0123456789abcdef0123456789abcdef",
	}
	first := Digest(ExitReviewEventHashMessage(event))
	event.PreviousReviewEventHash =
		"sha256:1111111111111111111111111111111111111111111111111111111111111111"
	second := Digest(ExitReviewEventHashMessage(event))
	if first == second {
		t.Fatalf("event hash must commit to the per-review chain")
	}
}
