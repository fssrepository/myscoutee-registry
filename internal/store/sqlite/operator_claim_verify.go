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
	if err := verifyOperatorActionSemantics(actions, submissions, reviews); err != nil {
		return err
	}
	return sqliteStore.verifyOperatorClaimStatusRows(
		ctx,
		actions,
		submissions,
		reviews,
	)
}

type verifiedOperatorDeploymentState struct {
	Active          bool
	Claimed         bool
	ClaimActionID   string
	ClaimGroupID    string
	EffectiveGroupID string
	LinkID          string
}

type verifiedOperatorTokenState struct {
	Issue    store.OperatorAuditEvent
	Legacy   bool
	Revoked  bool
	Redeemed bool
}

func verifyOperatorActionSemantics(
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

	deployments := make(map[string]verifiedOperatorDeploymentState)
	tokens := make(map[string]verifiedOperatorTokenState)
	tokenHashes := make(map[string]string)
	for _, event := range ordered {
		state, exists := deployments[event.SubjectDeploymentID]
		if !exists {
			state.Active = true
		}
		switch event.Action {
		case protocol.OperatorActionClaim:
			state.Claimed = true
			state.ClaimActionID = event.ActionID
			state.ClaimGroupID = event.GroupID
			state.EffectiveGroupID = event.GroupID
			state.LinkID = ""
		case protocol.OperatorActionWithdrawClaim:
			state.Claimed = false
			state.EffectiveGroupID = ""
			state.LinkID = ""
		case protocol.OperatorActionIssueClientToken:
			source, approved, legacy := verifiedApprovedOperatorSource(
				state,
				event.AcceptedAt,
				submissions,
				reviews,
			)
			if !state.Active ||
				!state.Claimed ||
				state.EffectiveGroupID != event.GroupID ||
				(!approved && !legacy) ||
				(approved && source.GroupID != event.GroupID) ||
				!validHexID(event.TokenID, "opt_", 32) ||
				!protocol.IsDigest(event.ClientTokenHash) ||
				event.TokenTTLSeconds < 60 ||
				event.TokenTTLSeconds > 3600 {
				return inconsistentMessage(
					"operator token issue %s is not authorized by its current approved claim",
					event.ActionID,
				)
			}
			acceptedAt, acceptedErr := time.Parse(time.RFC3339Nano, event.AcceptedAt)
			expiresAt, expiresErr := time.Parse(time.RFC3339Nano, event.TokenExpiresAt)
			if acceptedErr != nil ||
				expiresErr != nil ||
				!expiresAt.Equal(acceptedAt.Add(time.Duration(event.TokenTTLSeconds)*time.Second)) {
				return inconsistentMessage(
					"operator token issue %s has an invalid expiry",
					event.ActionID,
				)
			}
			if _, duplicate := tokens[event.TokenID]; duplicate {
				return inconsistentMessage(
					"operator token %s has multiple issue events",
					event.TokenID,
				)
			}
			if priorTokenID, duplicate := tokenHashes[event.ClientTokenHash]; duplicate {
				return inconsistentMessage(
					"operator tokens %s and %s reuse a client-token hash",
					priorTokenID,
					event.TokenID,
				)
			}
			tokens[event.TokenID] = verifiedOperatorTokenState{
				Issue:  event,
				Legacy: legacy,
			}
			tokenHashes[event.ClientTokenHash] = event.TokenID
		case protocol.OperatorActionRevokeClientToken:
			token, found := tokens[event.TokenID]
			if !found ||
				token.Revoked ||
				event.DeploymentID != token.Issue.DeploymentID ||
				event.GroupID != token.Issue.GroupID ||
				event.ClientTokenHash != token.Issue.ClientTokenHash ||
				event.TokenExpiresAt != token.Issue.TokenExpiresAt ||
				!operatorEventBeforeExpiry(event.AcceptedAt, token.Issue.TokenExpiresAt) {
				return inconsistentMessage(
					"operator token revocation %s does not extend one active issue",
					event.ActionID,
				)
			}
			token.Revoked = true
			tokens[event.TokenID] = token
		case protocol.OperatorActionRedeemClientToken:
			token, found := tokens[event.TokenID]
			issuerState, issuerExists := deployments[event.RelatedDeploymentID]
			if !found ||
				token.Revoked ||
				token.Redeemed ||
				event.RelatedDeploymentID != token.Issue.DeploymentID ||
				event.GroupID != token.Issue.GroupID ||
				event.ClientTokenHash != token.Issue.ClientTokenHash ||
				!operatorEventBeforeExpiry(event.AcceptedAt, token.Issue.TokenExpiresAt) ||
				!issuerExists ||
				!issuerState.Active ||
				!issuerState.Claimed ||
				issuerState.EffectiveGroupID != token.Issue.GroupID {
				return inconsistentMessage(
					"operator token redemption %s does not consume one active issue",
					event.ActionID,
				)
			}
			source, approved, legacy := verifiedApprovedOperatorSource(
				issuerState,
				event.AcceptedAt,
				submissions,
				reviews,
			)
			if (!approved && !(legacy && token.Legacy)) ||
				(approved && source.GroupID != token.Issue.GroupID) {
				return inconsistentMessage(
					"operator token redemption %s is not authorized by the issuer claim",
					event.ActionID,
				)
			}
			copied, tokenDerivedClaim := submissions[event.ActionID]
			if tokenDerivedClaim {
				if state.Claimed ||
					!approved ||
					event.SourceClaimActionID != source.ClaimActionID ||
					event.SourcePrivateRecordHash != source.PrivateRecordHash ||
					!sameOperatorCompanySubmission(copied, source) {
					return inconsistentMessage(
						"operator token-derived claim %s does not match its approved source",
						event.ActionID,
					)
				}
				state.Claimed = true
				state.ClaimActionID = event.ActionID
				state.ClaimGroupID = event.GroupID
				state.EffectiveGroupID = event.GroupID
				state.LinkID = ""
			} else {
				if !state.Claimed ||
					event.LinkID == "" ||
					event.SourceClaimActionID != "" ||
					event.SourcePrivateRecordHash != "" {
					return inconsistentMessage(
						"operator group redemption %s has unexpected source anchors",
						event.ActionID,
					)
				}
				state.EffectiveGroupID = event.GroupID
				state.LinkID = event.LinkID
			}
			token.Redeemed = true
			tokens[event.TokenID] = token
		case protocol.OperatorActionRevokeGroupLink:
			state.EffectiveGroupID = state.ClaimGroupID
			state.LinkID = ""
		case protocol.OperatorActionDeactivateDeployment:
			state.Active = false
		case protocol.OperatorActionReactivateDeployment:
			state.Active = true
		}
		deployments[event.SubjectDeploymentID] = state
	}
	return nil
}

func verifiedApprovedOperatorSource(
	state verifiedOperatorDeploymentState,
	acceptedAt string,
	submissions map[string]store.OperatorClaimSubmission,
	reviews map[string]store.OperatorClaimReview,
) (store.OperatorClaimSubmission, bool, bool) {
	submission, structured := submissions[state.ClaimActionID]
	if !structured {
		return store.OperatorClaimSubmission{}, false, state.Claimed
	}
	review, approved := reviews[state.ClaimActionID]
	if !approved {
		return submission, false, false
	}
	reviewedAt, reviewErr := time.Parse(time.RFC3339Nano, review.ReviewedAt)
	actionAt, actionErr := time.Parse(time.RFC3339Nano, acceptedAt)
	if reviewErr != nil || actionErr != nil || reviewedAt.After(actionAt) {
		return submission, false, false
	}
	if submission.Website == "" {
		return submission, false, false
	}
	return submission, true, false
}

func sameOperatorCompanySubmission(
	copied store.OperatorClaimSubmission,
	source store.OperatorClaimSubmission,
) bool {
	return copied.GroupID == source.GroupID &&
		copied.LegalName == source.LegalName &&
		copied.RegistrationNumber == source.RegistrationNumber &&
		copied.Jurisdiction == source.Jurisdiction &&
		copied.RegisteredAddress == source.RegisteredAddress &&
		copied.Website == source.Website &&
		copied.VerificationContactName == source.VerificationContactName &&
		copied.VerificationContactRole == source.VerificationContactRole &&
		copied.VerificationContactEmail == source.VerificationContactEmail &&
		copied.AuthorityAttested == source.AuthorityAttested &&
		copied.OperatorAvatarURL == source.OperatorAvatarURL
}

func operatorEventBeforeExpiry(acceptedAt string, expiresAt string) bool {
	accepted, acceptedErr := time.Parse(time.RFC3339Nano, acceptedAt)
	expires, expiresErr := time.Parse(time.RFC3339Nano, expiresAt)
	return acceptedErr == nil && expiresErr == nil && accepted.Before(expires)
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
			(action.event.Action != protocol.OperatorActionClaim &&
				action.event.Action != protocol.OperatorActionRedeemClientToken) ||
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
		case protocol.OperatorActionClaim,
			protocol.OperatorActionRedeemClientToken:
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
