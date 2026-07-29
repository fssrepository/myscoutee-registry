package sqlite

import (
	"context"
	"crypto/ed25519"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) verifiedOperatorClaimEligibilityRows(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
	submissions map[string]store.OperatorClaimSubmission,
	reviews map[string]store.OperatorClaimReview,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]store.OperatorClaimEligibility, error) {
	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorClaimEligibilitySelect+" ORDER BY eligibility_index",
	)
	if err != nil {
		return nil, inconsistent("read operator claim eligibility chain", err)
	}
	defer rows.Close()

	latest := make(map[string]store.OperatorClaimEligibility)
	expectedIndex := int64(1)
	previousHash := protocol.OperatorClaimEligibilityZeroHash
	var previousDecidedAt time.Time
	for rows.Next() {
		decision, err := scanOperatorClaimEligibility(rows)
		if err != nil {
			return nil, inconsistent("scan operator claim eligibility chain", err)
		}
		action, actionExists := actions[decision.ClaimActionID]
		submission, submissionExists := submissions[decision.ClaimActionID]
		review, reviewExists := reviews[decision.ClaimActionID]
		validDecision := (decision.Decision ==
			protocol.OperatorClaimEligibilitySuspend &&
			protocol.IsOperatorClaimEligibilityReasonCode(
				decision.ReasonCode,
			)) ||
			(decision.Decision ==
				protocol.OperatorClaimEligibilityReinstate &&
				decision.ReasonCode == "")
		if decision.EligibilityIndex != expectedIndex ||
			!validHexID(decision.EligibilityID, "ope_", 32) ||
			decision.PreviousEligibilityHash != previousHash ||
			decision.RegistryKeyID != registryKeyID ||
			!validDecision ||
			!validOperatorEligibilityAuditField(decision.ActorID, 120) ||
			!validOperatorEligibilityAuditField(
				decision.DecisionReference,
				240,
			) ||
			!actionExists ||
			!submissionExists ||
			!reviewExists ||
			review.Decision != protocol.OperatorClaimReviewApproved ||
			decision.DeploymentID != submission.DeploymentID ||
			decision.GroupID != submission.GroupID ||
			decision.LegalName != submission.LegalName {
			return nil, inconsistentMessage(
				"operator claim eligibility decision %s has inconsistent metadata",
				decision.EligibilityID,
			)
		}
		decidedAt, decidedErr := time.Parse(
			time.RFC3339Nano,
			decision.DecidedAt,
		)
		reviewedAt, reviewErr := time.Parse(
			time.RFC3339Nano,
			review.ReviewedAt,
		)
		if decidedErr != nil ||
			reviewErr != nil ||
			decidedAt.Before(reviewedAt) ||
			(expectedIndex > 1 && decidedAt.Before(previousDecidedAt)) ||
			operatorClaimWasSupersededBefore(
				actions,
				action.event,
				decidedAt,
			) {
			return nil, inconsistentMessage(
				"operator claim eligibility decision %s has invalid ordering",
				decision.EligibilityID,
			)
		}
		prior, hasPrior := latest[decision.ClaimActionID]
		if (decision.Decision ==
			protocol.OperatorClaimEligibilitySuspend &&
			hasPrior &&
			prior.Decision !=
				protocol.OperatorClaimEligibilityReinstate) ||
			(decision.Decision ==
				protocol.OperatorClaimEligibilityReinstate &&
				(!hasPrior ||
					prior.Decision !=
						protocol.OperatorClaimEligibilitySuspend)) {
			return nil, inconsistentMessage(
				"operator claim eligibility decision %s does not extend the current eligibility state",
				decision.EligibilityID,
			)
		}
		receipt := operatorClaimEligibilityReceipt(
			decision,
			registryScope,
		)
		expectedHash := protocol.Digest(
			protocol.OperatorClaimEligibilityHashMessage(receipt),
		)
		if decision.EligibilityHash != expectedHash {
			return nil, inconsistentMessage(
				"operator claim eligibility decision %s hash verification failed",
				decision.EligibilityID,
			)
		}
		if !ed25519.Verify(
			registryPublicKey,
			protocol.OperatorClaimEligibilityReceiptMessage(receipt),
			decision.Signature,
		) {
			return nil, inconsistentMessage(
				"operator claim eligibility decision %s signature verification failed",
				decision.EligibilityID,
			)
		}
		latest[decision.ClaimActionID] = decision
		expectedIndex++
		previousHash = decision.EligibilityHash
		previousDecidedAt = decidedAt
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent(
			"iterate operator claim eligibility chain",
			err,
		)
	}
	return latest, nil
}

func validOperatorEligibilityAuditField(value string, maximum int) bool {
	return len(value) >= 1 &&
		len(value) <= maximum &&
		!protocol.HasCanonicalLineBreak(value)
}

func operatorClaimWasSupersededBefore(
	actions map[string]verifiedOperatorAction,
	claim store.OperatorAuditEvent,
	decidedAt time.Time,
) bool {
	for _, verified := range actions {
		event := verified.event
		if event.SubjectDeploymentID != claim.DeploymentID ||
			event.AuditIndex <= claim.AuditIndex {
			continue
		}
		acceptedAt, err := time.Parse(time.RFC3339Nano, event.AcceptedAt)
		if err != nil || !acceptedAt.Before(decidedAt) {
			continue
		}
		switch event.Action {
		case protocol.OperatorActionClaim,
			protocol.OperatorActionWithdrawClaim,
			protocol.OperatorActionDeactivateDeployment:
			return true
		case protocol.OperatorActionRedeemClientToken:
			if event.ClaimState ==
				protocol.OperatorClaimStatePendingReview {
				return true
			}
		}
	}
	return false
}

type operatorClaimEligibilityCurrentRow struct {
	DeploymentID        string
	ClaimActionID       string
	GroupID             string
	LegalName           string
	EligibilityState    string
	ApprovedReviewIndex int64
	ApprovedReviewHash  string
	EligibilityID       string
	EligibilityIndex    int64
	EligibilityHash     string
	UpdatedAt           string
	SourceAuditIndex    int64
	SourceAuditHash     string
}

func (sqliteStore *Store) verifyOperatorClaimEligibilityCurrentRows(
	ctx context.Context,
	statuses map[string]store.OperatorClaimStatus,
	eligibilities map[string]store.OperatorClaimEligibility,
) error {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
			deployment_id,
			claim_action_id,
			group_id,
			legal_name,
			eligibility_state,
			approved_review_index,
			approved_review_hash,
			eligibility_id,
			eligibility_index,
			eligibility_hash,
			updated_at,
			source_claim_audit_index,
			source_claim_audit_hash
		FROM operator_claim_eligibility_current
		ORDER BY deployment_id`)
	if err != nil {
		return inconsistent(
			"read direct operator claim eligibility rows",
			err,
		)
	}
	defer rows.Close()

	actualCount := 0
	for rows.Next() {
		var actual operatorClaimEligibilityCurrentRow
		if err := rows.Scan(
			&actual.DeploymentID,
			&actual.ClaimActionID,
			&actual.GroupID,
			&actual.LegalName,
			&actual.EligibilityState,
			&actual.ApprovedReviewIndex,
			&actual.ApprovedReviewHash,
			&actual.EligibilityID,
			&actual.EligibilityIndex,
			&actual.EligibilityHash,
			&actual.UpdatedAt,
			&actual.SourceAuditIndex,
			&actual.SourceAuditHash,
		); err != nil {
			return inconsistent(
				"scan direct operator claim eligibility row",
				err,
			)
		}
		status, exists := statuses[actual.DeploymentID]
		if !exists {
			return inconsistentMessage(
				"direct operator claim eligibility for %s has no structured claim status",
				actual.DeploymentID,
			)
		}
		want := expectedOperatorClaimEligibilityCurrent(
			status,
			eligibilities[status.ClaimActionID],
		)
		if actual != want {
			return inconsistentMessage(
				"direct operator claim eligibility for %s does not match its immutable sources",
				actual.DeploymentID,
			)
		}
		actualCount++
	}
	if err := rows.Err(); err != nil {
		return inconsistent(
			"iterate direct operator claim eligibility rows",
			err,
		)
	}
	if actualCount != len(statuses) {
		return inconsistentMessage(
			"direct operator claim eligibility row count is %d, expected %d",
			actualCount,
			len(statuses),
		)
	}
	return nil
}

func expectedOperatorClaimEligibilityCurrent(
	status store.OperatorClaimStatus,
	decision store.OperatorClaimEligibility,
) operatorClaimEligibilityCurrentRow {
	state := protocol.OperatorEligibilityInactive
	approvedReviewIndex := int64(0)
	approvedReviewHash := protocol.OperatorClaimReviewZeroHash
	if status.ApprovedAt != "" {
		approvedReviewIndex = status.ReviewIndex
		approvedReviewHash = status.ReviewHash
	}
	if status.VerificationState == protocol.OperatorClaimStateApproved {
		state = protocol.OperatorEligibilityActive
	}
	current := operatorClaimEligibilityCurrentRow{
		DeploymentID:        status.DeploymentID,
		ClaimActionID:       status.ClaimActionID,
		GroupID:             status.GroupID,
		LegalName:           status.LegalName,
		EligibilityState:    state,
		ApprovedReviewIndex: approvedReviewIndex,
		ApprovedReviewHash:  approvedReviewHash,
		EligibilityHash:     protocol.OperatorClaimEligibilityZeroHash,
		UpdatedAt:           status.UpdatedAt,
		SourceAuditIndex:    status.ClaimAuditIndex,
		SourceAuditHash:     status.ClaimAuditHash,
	}
	if decision.EligibilityID != "" {
		current.EligibilityID = decision.EligibilityID
		current.EligibilityIndex = decision.EligibilityIndex
		current.EligibilityHash = decision.EligibilityHash
		if status.VerificationState ==
			protocol.OperatorClaimStateApproved {
			if decision.Decision ==
				protocol.OperatorClaimEligibilitySuspend {
				current.EligibilityState =
					protocol.OperatorEligibilitySuspended
			}
			if decision.DecidedAt > current.UpdatedAt {
				current.UpdatedAt = decision.DecidedAt
			}
		}
	}
	return current
}
