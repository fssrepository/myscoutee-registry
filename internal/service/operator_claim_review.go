package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultOperatorClaimListLimit = 50
	maxOperatorClaimListLimit     = 200
)

type OperatorClaimApproval struct {
	DeploymentID    string
	ClaimActionID   string
	GroupID         string
	LegalName       string
	ReviewerID      string
	ReviewReference string
	IdempotencyKey  string
}

func (registry *Service) ApproveOperatorClaim(
	ctx context.Context,
	approval OperatorClaimApproval,
) (protocol.OperatorClaimReviewResult, error) {
	if !deploymentIDPattern.MatchString(approval.DeploymentID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("deployment_id is malformed")
	}
	if !operatorActionIDPattern.MatchString(approval.ClaimActionID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("claim_action_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(approval.GroupID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("group_id is malformed")
	}
	if err := validateClaimText("legal_name", approval.LegalName, 160); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := validateClaimText("reviewer_id", approval.ReviewerID, 120); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := validateClaimText(
		"review_reference",
		approval.ReviewReference,
		240,
	); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := validateToken("idempotency_key", approval.IdempotencyKey); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
			"registry integrity verification failed before claim approval: %w",
			err,
		)
	}
	reviewID, err := registry.newID("opr_")
	if err != nil {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
			"generate operator claim review ID: %w",
			err,
		)
	}
	review, duplicate, err := registry.store.ApproveOperatorClaim(
		ctx,
		store.OperatorClaimReviewInput{
			RegistryScope:     registry.registryScope,
			DeploymentID:      approval.DeploymentID,
			ClaimActionID:     approval.ClaimActionID,
			GroupID:           approval.GroupID,
			LegalName:         approval.LegalName,
			ReviewerID:        approval.ReviewerID,
			ReviewReference:   approval.ReviewReference,
			IdempotencyKey:    approval.IdempotencyKey,
			CandidateReviewID: reviewID,
			ReviewedAt:        registry.canonicalNow().Format(time.RFC3339),
			RegistryKeyID:     registry.signingKey.KeyID(),
		},
		func(review store.OperatorClaimReview) ([]byte, error) {
			receipt := registry.operatorClaimReviewReceipt(review)
			return registry.signingKey.Sign(
				protocol.OperatorClaimReviewReceiptMessage(receipt),
			), nil
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrIdempotencyConflict):
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"idempotency_key was already used for a different review: %w",
				err,
			)
		case errors.Is(err, store.ErrOperatorClaimStale):
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"approval target is stale; run show-operator-claim and copy the current identifiers: %w",
				err,
			)
		case errors.Is(err, store.ErrOperatorClaimAlreadyReviewed):
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"operator claim is not pending review: %w",
				err,
			)
		case errors.Is(err, store.ErrNotFound):
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"operator claim was not found: %w",
				err,
			)
		default:
			return protocol.OperatorClaimReviewResult{}, err
		}
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
			"verify registry after claim approval: %w",
			err,
		)
	}
	receipt := registry.operatorClaimReviewReceipt(review)
	receipt.Signature = protocol.EncodeSignature(review.Signature)
	return protocol.OperatorClaimReviewResult{
		Duplicate: duplicate,
		Receipt:   receipt,
	}, nil
}

func (registry *Service) OperatorClaimStatus(
	ctx context.Context,
	deploymentID string,
) (protocol.OperatorClaimStatusResponse, error) {
	if !deploymentIDPattern.MatchString(deploymentID) {
		return protocol.OperatorClaimStatusResponse{}, requestError(
			"invalid_request",
			"deployment_id is malformed",
		)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OperatorClaimStatusResponse{}, requestError(
			"registry_integrity_unavailable",
			"registry integrity verification failed; claim status is temporarily unavailable",
		)
	}
	status, err := registry.store.OperatorClaimStatus(ctx, deploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.OperatorClaimStatusResponse{}, requestError(
				"operator_claim_not_found",
				"the deployment has no structured operator claim",
			)
		}
		return protocol.OperatorClaimStatusResponse{}, err
	}
	receipt := registry.operatorClaimStatusReceipt(status)
	receipt.Signature = protocol.EncodeSignature(registry.signingKey.Sign(
		protocol.OperatorClaimStatusReceiptMessage(receipt),
	))
	return protocol.OperatorClaimStatusResponse{
		ProtocolVersion: protocol.Version,
		RegistryScope:   registry.registryScope,
		Status:          receipt,
	}, nil
}

func (registry *Service) OperatorClaimsForReview(
	ctx context.Context,
	status string,
	limit int,
	afterDeploymentID string,
) (protocol.OperatorClaimReviewListPage, error) {
	internalStatus, err := operatorVerificationState(status, true)
	if err != nil {
		return protocol.OperatorClaimReviewListPage{}, err
	}
	if limit == 0 {
		limit = defaultOperatorClaimListLimit
	}
	if limit < 1 || limit > maxOperatorClaimListLimit {
		return protocol.OperatorClaimReviewListPage{}, fmt.Errorf(
			"limit must be between 1 and %d",
			maxOperatorClaimListLimit,
		)
	}
	if afterDeploymentID != "" && !deploymentIDPattern.MatchString(afterDeploymentID) {
		return protocol.OperatorClaimReviewListPage{}, fmt.Errorf(
			"after_deployment_id is malformed",
		)
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.OperatorClaimReviewListPage{}, fmt.Errorf(
			"registry integrity verification failed before claim listing: %w",
			err,
		)
	}
	page, err := registry.store.OperatorClaims(ctx, store.OperatorClaimQuery{
		Status:            internalStatus,
		Limit:             limit,
		AfterDeploymentID: afterDeploymentID,
	})
	if err != nil {
		return protocol.OperatorClaimReviewListPage{}, err
	}
	items := make([]protocol.OperatorClaimReviewListItem, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, operatorClaimListItem(item))
	}
	return protocol.OperatorClaimReviewListPage{
		Items:            items,
		NextDeploymentID: page.NextDeploymentID,
	}, nil
}

func (registry *Service) OperatorClaimForReview(
	ctx context.Context,
	deploymentID string,
) (protocol.OperatorClaimReviewDetail, error) {
	if !deploymentIDPattern.MatchString(deploymentID) {
		return protocol.OperatorClaimReviewDetail{}, fmt.Errorf("deployment_id is malformed")
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.OperatorClaimReviewDetail{}, fmt.Errorf(
			"registry integrity verification failed before claim disclosure: %w",
			err,
		)
	}
	submission, status, err := registry.store.OperatorClaimSubmission(ctx, deploymentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.OperatorClaimReviewDetail{}, fmt.Errorf(
				"structured operator claim was not found: %w",
				err,
			)
		}
		return protocol.OperatorClaimReviewDetail{}, err
	}
	return protocol.OperatorClaimReviewDetail{
		OperatorClaimReviewListItem: operatorClaimListItem(status),
		RegistrationNumber:          submission.RegistrationNumber,
		Jurisdiction:                submission.Jurisdiction,
		RegisteredAddress:           submission.RegisteredAddress,
		Website:                     submission.Website,
		VerificationContactName:     submission.VerificationContactName,
		VerificationContactRole:     submission.VerificationContactRole,
		VerificationContactEmail:    submission.VerificationContactEmail,
		AuthorityAttested:           submission.AuthorityAttested,
	}, nil
}

func (registry *Service) operatorClaimReviewReceipt(
	review store.OperatorClaimReview,
) protocol.OperatorClaimReviewReceipt {
	return protocol.OperatorClaimReviewReceipt{
		ReviewIndex:        review.ReviewIndex,
		ReviewID:           review.ReviewID,
		DeploymentID:       review.DeploymentID,
		ClaimActionID:      review.ClaimActionID,
		GroupID:            review.GroupID,
		LegalName:          review.LegalName,
		Decision:           review.Decision,
		ReviewerID:         review.ReviewerID,
		ReviewReference:    review.ReviewReference,
		IdempotencyKey:     review.IdempotencyKey,
		ReviewedAt:         review.ReviewedAt,
		PreviousReviewHash: review.PreviousReviewHash,
		ReviewHash:         review.ReviewHash,
		RegistryScope:      registry.registryScope,
		RegistryKeyID:      review.RegistryKeyID,
	}
}

func (registry *Service) operatorClaimStatusReceipt(
	status store.OperatorClaimStatus,
) protocol.OperatorClaimStatusReceipt {
	publicStatus, _ := operatorVerificationState(status.VerificationState, false)
	return protocol.OperatorClaimStatusReceipt{
		DeploymentID:       status.DeploymentID,
		ClaimActionID:      status.ClaimActionID,
		ClaimAuditIndex:    status.ClaimAuditIndex,
		ClaimAuditHash:     status.ClaimAuditHash,
		GroupID:            status.GroupID,
		LegalName:          status.LegalName,
		VerificationStatus: publicStatus,
		SubmittedAt:        status.SubmittedAt,
		ReviewID:           status.ReviewID,
		ReviewIndex:        status.ReviewIndex,
		ReviewHash:         status.ReviewHash,
		ApprovedAt:         status.ApprovedAt,
		RegistryScope:      registry.registryScope,
		RegistryKeyID:      registry.signingKey.KeyID(),
	}
}

func operatorClaimListItem(
	status store.OperatorClaimStatus,
) protocol.OperatorClaimReviewListItem {
	publicStatus, _ := operatorVerificationState(status.VerificationState, false)
	return protocol.OperatorClaimReviewListItem{
		DeploymentID:       status.DeploymentID,
		ClaimActionID:      status.ClaimActionID,
		GroupID:            status.GroupID,
		LegalName:          status.LegalName,
		VerificationStatus: publicStatus,
		SubmittedAt:        status.SubmittedAt,
		ApprovedAt:         status.ApprovedAt,
		ReviewID:           status.ReviewID,
	}
}

func operatorVerificationState(value string, fromPublic bool) (string, error) {
	if fromPublic {
		switch strings.ToUpper(strings.TrimSpace(value)) {
		case "":
			return "", nil
		case protocol.OperatorVerificationStatusPendingReview:
			return protocol.OperatorClaimStatePendingReview, nil
		case protocol.OperatorVerificationStatusApproved:
			return protocol.OperatorClaimStateApproved, nil
		case protocol.OperatorVerificationStatusWithdrawn:
			return protocol.OperatorClaimStateWithdrawn, nil
		default:
			return "", fmt.Errorf(
				"status must be PENDING_REVIEW, APPROVED, or WITHDRAWN",
			)
		}
	}
	switch value {
	case protocol.OperatorClaimStatePendingReview:
		return protocol.OperatorVerificationStatusPendingReview, nil
	case protocol.OperatorClaimStateApproved:
		return protocol.OperatorVerificationStatusApproved, nil
	case protocol.OperatorClaimStateWithdrawn:
		return protocol.OperatorVerificationStatusWithdrawn, nil
	default:
		return "", fmt.Errorf("stored operator verification state is invalid")
	}
}
