package protocol

import (
	"bytes"
	"strconv"
	"testing"
)

func TestOperatorClaimReviewHashPreservesApprovalV1AndBindsRejectionReason(
	t *testing.T,
) {
	approval := OperatorClaimReviewReceipt{
		ReviewIndex:        7,
		ReviewID:           "review",
		DeploymentID:       "deployment",
		ClaimActionID:      "claim",
		GroupID:            "group",
		LegalName:          "Operator",
		Decision:           OperatorClaimReviewApproved,
		ReviewerID:         "review-team",
		ReviewReference:    "case:7",
		IdempotencyKey:     "approval-key",
		ReviewedAt:         "2026-07-29T12:00:00Z",
		PreviousReviewHash: "previous",
		RegistryScope:      "scope",
		RegistryKeyID:      "registry-key",
	}
	wantApproval := canonical(
		"myscoutee-registry-operator-claim-review-v1",
		strconv.FormatInt(approval.ReviewIndex, 10),
		approval.ReviewID,
		approval.DeploymentID,
		approval.ClaimActionID,
		approval.GroupID,
		approval.LegalName,
		approval.Decision,
		approval.ReviewerID,
		approval.ReviewReference,
		approval.IdempotencyKey,
		approval.ReviewedAt,
		approval.PreviousReviewHash,
		approval.RegistryScope,
		approval.RegistryKeyID,
	)
	if !bytes.Equal(
		OperatorClaimReviewHashMessage(approval),
		wantApproval,
	) {
		t.Fatal("approval review changed its v1 canonical hash message")
	}

	rejection := approval
	rejection.Decision = OperatorClaimReviewRejected
	rejection.ReasonCode = "identity-not-verified"
	rejection.IdempotencyKey = "rejection-key"
	wantRejection := canonical(
		"myscoutee-registry-operator-claim-review-v2",
		strconv.FormatInt(rejection.ReviewIndex, 10),
		rejection.ReviewID,
		rejection.DeploymentID,
		rejection.ClaimActionID,
		rejection.GroupID,
		rejection.LegalName,
		rejection.Decision,
		rejection.ReviewerID,
		rejection.ReviewReference,
		rejection.ReasonCode,
		rejection.IdempotencyKey,
		rejection.ReviewedAt,
		rejection.PreviousReviewHash,
		rejection.RegistryScope,
		rejection.RegistryKeyID,
	)
	if !bytes.Equal(
		OperatorClaimReviewHashMessage(rejection),
		wantRejection,
	) {
		t.Fatal("rejection review does not bind its reason code in v2")
	}
}

func TestOperatorClaimReviewReasonCodeIsBoundedMachineData(t *testing.T) {
	for _, valid := range []string{
		"identity-not-verified",
		"authority-2",
		"bad",
	} {
		if !IsOperatorClaimReviewReasonCode(valid) {
			t.Fatalf("valid reason code %q was rejected", valid)
		}
	}
	for _, invalid := range []string{
		"",
		"no",
		"Contains-Personal-Text",
		"identity_not_verified",
		"reviewer@example.test",
		"identity not verified",
	} {
		if IsOperatorClaimReviewReasonCode(invalid) {
			t.Fatalf("invalid reason code %q was accepted", invalid)
		}
	}
}
