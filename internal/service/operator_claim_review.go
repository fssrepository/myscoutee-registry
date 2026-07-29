package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultOperatorClaimListLimit = 50
	maxOperatorClaimListLimit     = 200
)

var (
	operatorClaimReviewAuditIDPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,239}$`,
	)
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

type OperatorClaimRejection struct {
	DeploymentID    string
	ClaimActionID   string
	GroupID         string
	LegalName       string
	ReviewerID      string
	ReviewReference string
	ReasonCode      string
	IdempotencyKey  string
}

func (registry *Service) ApproveOperatorClaim(
	ctx context.Context,
	approval OperatorClaimApproval,
) (protocol.OperatorClaimReviewResult, error) {
	return registry.decideOperatorClaim(ctx, store.OperatorClaimReviewInput{
		DeploymentID:    approval.DeploymentID,
		ClaimActionID:   approval.ClaimActionID,
		GroupID:         approval.GroupID,
		LegalName:       approval.LegalName,
		Decision:        protocol.OperatorClaimReviewApproved,
		ReviewerID:      approval.ReviewerID,
		ReviewReference: approval.ReviewReference,
		IdempotencyKey:  approval.IdempotencyKey,
	})
}

func (registry *Service) RejectOperatorClaim(
	ctx context.Context,
	rejection OperatorClaimRejection,
) (protocol.OperatorClaimReviewResult, error) {
	return registry.decideOperatorClaim(ctx, store.OperatorClaimReviewInput{
		DeploymentID:    rejection.DeploymentID,
		ClaimActionID:   rejection.ClaimActionID,
		GroupID:         rejection.GroupID,
		LegalName:       rejection.LegalName,
		Decision:        protocol.OperatorClaimReviewRejected,
		ReviewerID:      rejection.ReviewerID,
		ReviewReference: rejection.ReviewReference,
		ReasonCode:      rejection.ReasonCode,
		IdempotencyKey:  rejection.IdempotencyKey,
	})
}

func (registry *Service) decideOperatorClaim(
	ctx context.Context,
	input store.OperatorClaimReviewInput,
) (protocol.OperatorClaimReviewResult, error) {
	if !deploymentIDPattern.MatchString(input.DeploymentID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("deployment_id is malformed")
	}
	if !operatorActionIDPattern.MatchString(input.ClaimActionID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("claim_action_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(input.GroupID) {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf("group_id is malformed")
	}
	if err := validateClaimText("legal_name", input.LegalName, 160); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := validateClaimText("reviewer_id", input.ReviewerID, 120); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	if err := validateClaimText(
		"review_reference",
		input.ReviewReference,
		240,
	); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	switch input.Decision {
	case protocol.OperatorClaimReviewApproved:
		if input.ReasonCode != "" {
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"reason_code must be empty for approval",
			)
		}
	case protocol.OperatorClaimReviewRejected:
		if !operatorClaimReviewAuditIDPattern.MatchString(input.ReviewerID) {
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"reviewer_id must be a non-personal audit identifier",
			)
		}
		if !operatorClaimReviewAuditIDPattern.MatchString(input.ReviewReference) {
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"review_reference must be a non-personal audit reference",
			)
		}
		if !protocol.IsOperatorClaimReviewReasonCode(input.ReasonCode) {
			return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
				"reason_code must be a 3-64 character lowercase token",
			)
		}
	default:
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
			"operator claim review decision is invalid",
		)
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return protocol.OperatorClaimReviewResult{}, err
	}
	decisionNoun := "approval"
	if input.Decision == protocol.OperatorClaimReviewRejected {
		decisionNoun = "rejection"
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OperatorClaimReviewResult{}, fmt.Errorf(
			"registry integrity verification failed before claim %s: %w",
			decisionNoun,
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
	input.RegistryScope = registry.registryScope
	input.CandidateReviewID = reviewID
	input.ReviewedAt = registry.canonicalNow().Format(time.RFC3339)
	input.RegistryKeyID = registry.signingKey.KeyID()
	review, duplicate, err := registry.store.DecideOperatorClaim(
		ctx,
		input,
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
				"%s target is stale; run show-operator-claim and copy the current identifiers: %w",
				decisionNoun,
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
			"verify registry after claim %s: %w",
			decisionNoun,
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
		ReasonCode:         review.ReasonCode,
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
		case protocol.OperatorVerificationStatusRejected:
			return protocol.OperatorClaimStateRejected, nil
		case protocol.OperatorVerificationStatusWithdrawn:
			return protocol.OperatorClaimStateWithdrawn, nil
		default:
			return "", fmt.Errorf(
				"status must be PENDING_REVIEW, APPROVED, REJECTED, or WITHDRAWN",
			)
		}
	}
	switch value {
	case protocol.OperatorClaimStatePendingReview:
		return protocol.OperatorVerificationStatusPendingReview, nil
	case protocol.OperatorClaimStateApproved:
		return protocol.OperatorVerificationStatusApproved, nil
	case protocol.OperatorClaimStateRejected:
		return protocol.OperatorVerificationStatusRejected, nil
	case protocol.OperatorClaimStateWithdrawn:
		return protocol.OperatorVerificationStatusWithdrawn, nil
	default:
		return "", fmt.Errorf("stored operator verification state is invalid")
	}
}
