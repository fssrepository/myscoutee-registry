package sqlite

import (
	"strings"
	"testing"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func TestVerifyOperatorActionSemanticsRejectsSecondTokenRedemption(t *testing.T) {
	const (
		issuerID = "dep_00000000000000000000000000000001"
		targetA  = "dep_00000000000000000000000000000002"
		targetB  = "dep_00000000000000000000000000000003"
		tokenID  = "opt_00000000000000000000000000000001"
	)
	tokenHash := protocol.Digest([]byte("single-use-client-code"))
	actions := map[string]verifiedOperatorAction{}
	add := func(event store.OperatorAuditEvent) {
		actions[event.ActionID] = verifiedOperatorAction{event: event}
	}
	add(store.OperatorAuditEvent{
		AuditIndex:          1,
		ActionID:            "issuer-claim",
		DeploymentID:        issuerID,
		SubjectDeploymentID: issuerID,
		Action:              protocol.OperatorActionClaim,
		ClaimState:          protocol.OperatorClaimStateClaimed,
		GroupID:             "issuer-group",
		AcceptedAt:          "2026-07-28T12:00:00Z",
	})
	add(store.OperatorAuditEvent{
		AuditIndex:          2,
		ActionID:            "target-a-claim",
		DeploymentID:        targetA,
		SubjectDeploymentID: targetA,
		Action:              protocol.OperatorActionClaim,
		ClaimState:          protocol.OperatorClaimStateClaimed,
		GroupID:             "target-a-group",
		AcceptedAt:          "2026-07-28T12:00:01Z",
	})
	add(store.OperatorAuditEvent{
		AuditIndex:          3,
		ActionID:            "target-b-claim",
		DeploymentID:        targetB,
		SubjectDeploymentID: targetB,
		Action:              protocol.OperatorActionClaim,
		ClaimState:          protocol.OperatorClaimStateClaimed,
		GroupID:             "target-b-group",
		AcceptedAt:          "2026-07-28T12:00:02Z",
	})
	add(store.OperatorAuditEvent{
		AuditIndex:          4,
		ActionID:            "issue",
		DeploymentID:        issuerID,
		SubjectDeploymentID: issuerID,
		Action:              protocol.OperatorActionIssueClientToken,
		GroupID:             "issuer-group",
		TokenID:             tokenID,
		ClientTokenHash:     tokenHash,
		TokenTTLSeconds:     300,
		TokenExpiresAt:      "2026-07-28T12:05:03Z",
		AcceptedAt:          "2026-07-28T12:00:03Z",
	})
	add(store.OperatorAuditEvent{
		AuditIndex:          5,
		ActionID:            "redeem-a",
		DeploymentID:        targetA,
		SubjectDeploymentID: targetA,
		RelatedDeploymentID: issuerID,
		Action:              protocol.OperatorActionRedeemClientToken,
		ClaimState:          protocol.OperatorClaimStateClaimed,
		GroupID:             "issuer-group",
		LinkID:              "link-a",
		TokenID:             tokenID,
		ClientTokenHash:     tokenHash,
		AcceptedAt:          "2026-07-28T12:00:04Z",
	})
	add(store.OperatorAuditEvent{
		AuditIndex:          6,
		ActionID:            "redeem-b",
		DeploymentID:        targetB,
		SubjectDeploymentID: targetB,
		RelatedDeploymentID: issuerID,
		Action:              protocol.OperatorActionRedeemClientToken,
		ClaimState:          protocol.OperatorClaimStateClaimed,
		GroupID:             "issuer-group",
		LinkID:              "link-b",
		TokenID:             tokenID,
		ClientTokenHash:     tokenHash,
		AcceptedAt:          "2026-07-28T12:00:05Z",
	})

	err := verifyOperatorActionSemantics(
		actions,
		map[string]store.OperatorClaimSubmission{},
		map[string]store.OperatorClaimReview{},
	)
	if err == nil || !strings.Contains(err.Error(), "does not consume one active issue") {
		t.Fatalf("second-redemption semantic verification error = %v", err)
	}
}
