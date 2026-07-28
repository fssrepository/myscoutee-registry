package sqlite

import (
	"context"
	"crypto/ed25519"
	"sort"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

func (sqliteStore *Store) operatorClaimSubmissions(
	ctx context.Context,
) (map[string]store.OperatorClaimSubmission, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
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
		FROM operator_claim_verification_submissions
		ORDER BY claim_action_id`)
	if err != nil {
		return nil, inconsistent("read private operator claim submissions", err)
	}
	defer rows.Close()
	submissions := make(map[string]store.OperatorClaimSubmission)
	for rows.Next() {
		submission, err := scanOperatorClaimSubmission(rows)
		if err != nil {
			return nil, inconsistent("scan private operator claim submission", err)
		}
		submissions[submission.ClaimActionID] = submission
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate private operator claim submissions", err)
	}
	return submissions, nil
}

func (sqliteStore *Store) verifyOperatorClaimReviews(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
	registryPublicKey []byte,
	registryKeyID string,
	registryScope string,
) error {
	submissions, err := sqliteStore.operatorClaimSubmissions(ctx)
	if err != nil {
		return err
	}
	reviews, err := sqliteStore.verifiedOperatorClaimReviewRows(
		ctx,
		actions,
		submissions,
		ed25519.PublicKey(registryPublicKey),
		registryKeyID,
		registryScope,
	)
	if err != nil {
		return err
	}
	return sqliteStore.verifyOperatorClaimStatusRows(
		ctx,
		actions,
		submissions,
		reviews,
	)
}

func (sqliteStore *Store) verifiedOperatorClaimReviewRows(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
	submissions map[string]store.OperatorClaimSubmission,
	registryPublicKey ed25519.PublicKey,
	registryKeyID string,
	registryScope string,
) (map[string]store.OperatorClaimReview, error) {
	rows, err := sqliteStore.db.QueryContext(ctx, `
		SELECT
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
		FROM operator_claim_reviews
		ORDER BY review_index`)
	if err != nil {
		return nil, inconsistent("read operator claim review chain", err)
	}
	defer rows.Close()

	reviews := make(map[string]store.OperatorClaimReview)
	expectedIndex := int64(1)
	previousHash := protocol.OperatorClaimReviewZeroHash
	var previousReviewedAt time.Time
	for rows.Next() {
		review, err := scanOperatorClaimReview(rows)
		if err != nil {
			return nil, inconsistent("scan operator claim review", err)
		}
		action, actionExists := actions[review.ClaimActionID]
		submission, submissionExists := submissions[review.ClaimActionID]
		if review.ReviewIndex != expectedIndex ||
			!validHexID(review.ReviewID, "opr_", 32) ||
			review.PreviousReviewHash != previousHash ||
			review.Decision != protocol.OperatorClaimReviewApproved ||
			review.RegistryKeyID != registryKeyID ||
			!actionExists ||
			!submissionExists ||
			action.event.Action != protocol.OperatorActionClaim ||
			action.event.ClaimState != protocol.OperatorClaimStatePendingReview ||
			review.DeploymentID != submission.DeploymentID ||
			review.GroupID != submission.GroupID ||
			review.LegalName != submission.LegalName {
			return nil, inconsistentMessage(
				"operator claim review %s has inconsistent metadata",
				review.ReviewID,
			)
		}
		if len(review.ReviewerID) < 1 || len(review.ReviewerID) > 120 ||
			len(review.ReviewReference) < 1 || len(review.ReviewReference) > 240 ||
			protocol.HasCanonicalLineBreak(review.ReviewerID) ||
			protocol.HasCanonicalLineBreak(review.ReviewReference) {
			return nil, inconsistentMessage(
				"operator claim review %s has invalid reviewer audit fields",
				review.ReviewID,
			)
		}
		reviewedAt, err := time.Parse(time.RFC3339Nano, review.ReviewedAt)
		submittedAt, submittedErr := time.Parse(time.RFC3339Nano, submission.SubmittedAt)
		if err != nil || submittedErr != nil ||
			reviewedAt.Before(submittedAt) ||
			(expectedIndex > 1 && reviewedAt.Before(previousReviewedAt)) {
			return nil, inconsistentMessage(
				"operator claim review %s has invalid reviewed_at ordering",
				review.ReviewID,
			)
		}
		receipt := operatorClaimReviewReceipt(review, registryScope)
		expectedHash := protocol.Digest(protocol.OperatorClaimReviewHashMessage(receipt))
		if review.ReviewHash != expectedHash {
			return nil, inconsistentMessage(
				"operator claim review %s hash verification failed",
				review.ReviewID,
			)
		}
		if !ed25519.Verify(
			registryPublicKey,
			protocol.OperatorClaimReviewReceiptMessage(receipt),
			review.Signature,
		) {
			return nil, inconsistentMessage(
				"operator claim review %s signature verification failed",
				review.ReviewID,
			)
		}
		if _, duplicate := reviews[review.ClaimActionID]; duplicate {
			return nil, inconsistentMessage(
				"operator claim %s has multiple reviews",
				review.ClaimActionID,
			)
		}
		reviews[review.ClaimActionID] = review
		expectedIndex++
		previousHash = review.ReviewHash
		previousReviewedAt = reviewedAt
	}
	if err := rows.Err(); err != nil {
		return nil, inconsistent("iterate operator claim reviews", err)
	}
	return reviews, nil
}

func (sqliteStore *Store) verifyOperatorClaimStatusRows(
	ctx context.Context,
	actions map[string]verifiedOperatorAction,
	submissions map[string]store.OperatorClaimSubmission,
	reviews map[string]store.OperatorClaimReview,
) error {
	ordered := make([]store.OperatorAuditEvent, 0, len(actions))
	for _, action := range actions {
		ordered = append(ordered, action.event)
	}
	sort.Slice(ordered, func(left, right int) bool {
		return ordered[left].AuditIndex < ordered[right].AuditIndex
	})
	expected := make(map[string]store.OperatorClaimStatus)
	for _, event := range ordered {
		switch event.Action {
		case protocol.OperatorActionClaim:
			submission, structured := submissions[event.ActionID]
			if !structured {
				continue
			}
			expected[event.DeploymentID] = store.OperatorClaimStatus{
				DeploymentID:      event.DeploymentID,
				ClaimActionID:     event.ActionID,
				ClaimAuditIndex:   event.AuditIndex,
				ClaimAuditHash:    event.AuditHash,
				GroupID:           event.GroupID,
				LegalName:         submission.LegalName,
				VerificationState: protocol.OperatorClaimStatePendingReview,
				SubmittedAt:       event.AcceptedAt,
				ReviewHash:        protocol.OperatorClaimReviewZeroHash,
				UpdatedAt:         event.AcceptedAt,
				PrivateRecordHash: submission.PrivateRecordHash,
			}
		case protocol.OperatorActionWithdrawClaim:
			status, exists := expected[event.SubjectDeploymentID]
			if exists {
				status.VerificationState = protocol.OperatorClaimStateWithdrawn
				status.UpdatedAt = event.AcceptedAt
				expected[event.SubjectDeploymentID] = status
			}
		}
	}
	for deploymentID, status := range expected {
		review, approved := reviews[status.ClaimActionID]
		if approved {
			status.ReviewID = review.ReviewID
			status.ReviewIndex = review.ReviewIndex
			status.ReviewHash = review.ReviewHash
			status.ApprovedAt = review.ReviewedAt
			if status.VerificationState == protocol.OperatorClaimStatePendingReview {
				status.VerificationState = protocol.OperatorClaimStateApproved
				status.UpdatedAt = review.ReviewedAt
			}
			expected[deploymentID] = status
		}
	}

	rows, err := sqliteStore.db.QueryContext(
		ctx,
		operatorClaimStatusSelect+" ORDER BY deployment_id",
	)
	if err != nil {
		return inconsistent("read direct operator claim status rows", err)
	}
	defer rows.Close()
	actualCount := 0
	for rows.Next() {
		actual, err := scanOperatorClaimStatus(rows)
		if err != nil {
			return inconsistent("scan direct operator claim status", err)
		}
		want, exists := expected[actual.DeploymentID]
		if !exists || actual != want {
			return inconsistentMessage(
				"direct operator claim status for %s does not match its audit sources",
				actual.DeploymentID,
			)
		}
		actualCount++
	}
	if err := rows.Err(); err != nil {
		return inconsistent("iterate direct operator claim statuses", err)
	}
	if actualCount != len(expected) {
		return inconsistentMessage(
			"direct operator claim status row count is %d, expected %d",
			actualCount,
			len(expected),
		)
	}
	return nil
}
