package protocol

import (
	"bytes"
	"strconv"
	"testing"
)

func TestOperatorAuditMessageKeepsV1WithoutSourceAnchors(t *testing.T) {
	message := OperatorAuditMessage(
		7,
		"action",
		"deployment",
		"subject",
		"related",
		OperatorActionRedeemClientToken,
		"payload",
		"2026-07-28T12:00:00Z",
		OperatorClaimStateClaimed,
		"group",
		"link",
		"token",
		"token-hash",
		"",
		"",
		"2026-07-28T12:05:00Z",
		"previous",
	)
	want := canonical(
		"myscoutee-registry-operator-audit-v1",
		strconv.FormatInt(7, 10),
		"action",
		"deployment",
		"subject",
		"related",
		OperatorActionRedeemClientToken,
		"payload",
		"2026-07-28T12:00:00Z",
		OperatorClaimStateClaimed,
		"group",
		"link",
		"token",
		"token-hash",
		"2026-07-28T12:05:00Z",
		"previous",
	)
	if !bytes.Equal(message, want) {
		t.Fatalf("unanchored operator audit message changed its v1 canonical form")
	}
}

func TestOperatorReceiptMessageUsesV2WithSourceAnchors(t *testing.T) {
	receipt := OperatorActionReceipt{
		AuditIndex:              8,
		AuditHash:               "audit-hash",
		PreviousAuditHash:       "previous",
		ActionID:                "action",
		DeploymentID:            "deployment",
		SubjectDeploymentID:     "subject",
		RelatedDeploymentID:     "issuer",
		Action:                  OperatorActionRedeemClientToken,
		AcceptedAt:              "2026-07-28T12:00:00Z",
		ClaimState:              OperatorClaimStatePendingReview,
		GroupID:                 "group",
		TokenID:                 "token",
		ClientTokenHash:         "token-hash",
		SourceClaimActionID:     "source-claim",
		SourcePrivateRecordHash: "source-private-hash",
		RegistryScope:           "scope",
		RegistryKeyID:           "registry-key",
	}
	message := OperatorActionReceiptMessage(receipt)
	want := canonical(
		"myscoutee-registry-operator-action-receipt-v2",
		strconv.FormatInt(receipt.AuditIndex, 10),
		receipt.AuditHash,
		receipt.PreviousAuditHash,
		receipt.ActionID,
		receipt.DeploymentID,
		receipt.SubjectDeploymentID,
		receipt.RelatedDeploymentID,
		receipt.Action,
		receipt.AcceptedAt,
		receipt.ClaimState,
		receipt.GroupID,
		receipt.LinkID,
		receipt.TokenID,
		receipt.ClientTokenHash,
		receipt.SourceClaimActionID,
		receipt.SourcePrivateRecordHash,
		receipt.TokenExpiresAt,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
	if !bytes.Equal(message, want) {
		t.Fatalf("anchored operator receipt does not use its v2 canonical form")
	}
}

func TestOperatorReceiptMessageKeepsV1WithoutSourceAnchors(t *testing.T) {
	receipt := OperatorActionReceipt{
		AuditIndex:          9,
		AuditHash:           "audit-hash",
		PreviousAuditHash:   "previous",
		ActionID:            "action",
		DeploymentID:        "deployment",
		SubjectDeploymentID: "subject",
		RelatedDeploymentID: "issuer",
		Action:              OperatorActionRedeemClientToken,
		AcceptedAt:          "2026-07-28T12:00:00Z",
		ClaimState:          OperatorClaimStateClaimed,
		GroupID:             "group",
		LinkID:              "link",
		TokenID:             "token",
		ClientTokenHash:     "token-hash",
		TokenExpiresAt:      "2026-07-28T12:05:00Z",
		RegistryScope:       "scope",
		RegistryKeyID:       "registry-key",
	}
	message := OperatorActionReceiptMessage(receipt)
	want := canonical(
		"myscoutee-registry-operator-action-receipt-v1",
		strconv.FormatInt(receipt.AuditIndex, 10),
		receipt.AuditHash,
		receipt.PreviousAuditHash,
		receipt.ActionID,
		receipt.DeploymentID,
		receipt.SubjectDeploymentID,
		receipt.RelatedDeploymentID,
		receipt.Action,
		receipt.AcceptedAt,
		receipt.ClaimState,
		receipt.GroupID,
		receipt.LinkID,
		receipt.TokenID,
		receipt.ClientTokenHash,
		receipt.TokenExpiresAt,
		receipt.RegistryScope,
		receipt.RegistryKeyID,
	)
	if !bytes.Equal(message, want) {
		t.Fatalf("unanchored operator receipt changed its v1 canonical form")
	}
}
