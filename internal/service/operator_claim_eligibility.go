package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

type OperatorClaimSuspension struct {
	DeploymentID      string
	ClaimActionID     string
	GroupID           string
	LegalName         string
	ActorID           string
	DecisionReference string
	ReasonCode        string
	IdempotencyKey    string
}

type OperatorClaimReinstatement struct {
	DeploymentID      string
	ClaimActionID     string
	GroupID           string
	LegalName         string
	ActorID           string
	DecisionReference string
	IdempotencyKey    string
}

func (registry *Service) SuspendOperatorClaim(
	ctx context.Context,
	suspension OperatorClaimSuspension,
) (protocol.OperatorClaimEligibilityResult, error) {
	return registry.decideOperatorClaimEligibility(
		ctx,
		store.OperatorClaimEligibilityInput{
			DeploymentID:      suspension.DeploymentID,
			ClaimActionID:     suspension.ClaimActionID,
			GroupID:           suspension.GroupID,
			LegalName:         suspension.LegalName,
			Decision:          protocol.OperatorClaimEligibilitySuspend,
			ActorID:           suspension.ActorID,
			DecisionReference: suspension.DecisionReference,
			ReasonCode:        suspension.ReasonCode,
			IdempotencyKey:    suspension.IdempotencyKey,
		},
	)
}

func (registry *Service) ReinstateOperatorClaim(
	ctx context.Context,
	reinstatement OperatorClaimReinstatement,
) (protocol.OperatorClaimEligibilityResult, error) {
	return registry.decideOperatorClaimEligibility(
		ctx,
		store.OperatorClaimEligibilityInput{
			DeploymentID:      reinstatement.DeploymentID,
			ClaimActionID:     reinstatement.ClaimActionID,
			GroupID:           reinstatement.GroupID,
			LegalName:         reinstatement.LegalName,
			Decision:          protocol.OperatorClaimEligibilityReinstate,
			ActorID:           reinstatement.ActorID,
			DecisionReference: reinstatement.DecisionReference,
			IdempotencyKey:    reinstatement.IdempotencyKey,
		},
	)
}

func (registry *Service) decideOperatorClaimEligibility(
	ctx context.Context,
	input store.OperatorClaimEligibilityInput,
) (protocol.OperatorClaimEligibilityResult, error) {
	if !deploymentIDPattern.MatchString(input.DeploymentID) {
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("deployment_id is malformed")
	}
	if !operatorActionIDPattern.MatchString(input.ClaimActionID) {
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("claim_action_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(input.GroupID) {
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("group_id is malformed")
	}
	if err := validateClaimText("legal_name", input.LegalName, 160); err != nil {
		return protocol.OperatorClaimEligibilityResult{}, err
	}
	if len(input.ActorID) > 120 ||
		!operatorClaimReviewAuditIDPattern.MatchString(input.ActorID) {
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("actor_id must be a non-personal audit identifier")
	}
	if len(input.DecisionReference) > 240 ||
		!operatorClaimReviewAuditIDPattern.MatchString(input.DecisionReference) {
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("decision_reference must be a non-personal audit reference")
	}
	switch input.Decision {
	case protocol.OperatorClaimEligibilitySuspend:
		if !protocol.IsOperatorClaimEligibilityReasonCode(input.ReasonCode) {
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"reason_code must be a 3-64 character lowercase token",
			)
		}
	case protocol.OperatorClaimEligibilityReinstate:
		if input.ReasonCode != "" {
			return protocol.OperatorClaimEligibilityResult{},
				fmt.Errorf("reason_code must be empty for reinstatement")
		}
	default:
		return protocol.OperatorClaimEligibilityResult{},
			fmt.Errorf("operator claim eligibility decision is invalid")
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return protocol.OperatorClaimEligibilityResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
			"registry integrity verification failed before claim eligibility decision: %w",
			err,
		)
	}
	eligibilityID, err := registry.newID("ope_")
	if err != nil {
		return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
			"generate operator claim eligibility ID: %w",
			err,
		)
	}
	input.RegistryScope = registry.registryScope
	input.CandidateEligibilityID = eligibilityID
	input.DecidedAt = registry.canonicalNow().Format(time.RFC3339)
	input.RegistryKeyID = registry.signingKey.KeyID()
	decision, duplicate, err := registry.store.DecideOperatorClaimEligibility(
		ctx,
		input,
		func(decision store.OperatorClaimEligibility) ([]byte, error) {
			return registry.signingKey.Sign(
				protocol.OperatorClaimEligibilityReceiptMessage(
					registry.operatorClaimEligibilityReceipt(decision),
				),
			), nil
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrIdempotencyConflict):
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"idempotency_key was already used for a different eligibility decision: %w",
				err,
			)
		case errors.Is(err, store.ErrOperatorClaimEligibilityStale):
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"eligibility target is stale; run show-operator-claim and copy the current identifiers: %w",
				err,
			)
		case errors.Is(err, store.ErrOperatorClaimNotEligible):
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"only the exact current approved active claim may be suspended: %w",
				err,
			)
		case errors.Is(err, store.ErrOperatorClaimNotSuspended):
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"only the exact current suspended claim may be reinstated: %w",
				err,
			)
		case errors.Is(err, store.ErrNotFound):
			return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
				"operator claim was not found: %w",
				err,
			)
		default:
			return protocol.OperatorClaimEligibilityResult{}, err
		}
	}
	if err := registry.VerifyState(ctx); err != nil {
		return protocol.OperatorClaimEligibilityResult{}, fmt.Errorf(
			"verify registry after claim eligibility decision: %w",
			err,
		)
	}
	receipt := registry.operatorClaimEligibilityReceipt(decision)
	receipt.Signature = protocol.EncodeSignature(decision.Signature)
	return protocol.OperatorClaimEligibilityResult{
		Duplicate: duplicate,
		Receipt:   receipt,
	}, nil
}

func (registry *Service) operatorClaimEligibilityReceipt(
	decision store.OperatorClaimEligibility,
) protocol.OperatorClaimEligibilityReceipt {
	return protocol.OperatorClaimEligibilityReceipt{
		EligibilityIndex:         decision.EligibilityIndex,
		EligibilityID:            decision.EligibilityID,
		DeploymentID:             decision.DeploymentID,
		ClaimActionID:            decision.ClaimActionID,
		GroupID:                  decision.GroupID,
		LegalName:                decision.LegalName,
		Decision:                 decision.Decision,
		ActorID:                  decision.ActorID,
		DecisionReference:        decision.DecisionReference,
		ReasonCode:               decision.ReasonCode,
		IdempotencyKey:           decision.IdempotencyKey,
		DecidedAt:                decision.DecidedAt,
		PreviousEligibilityHash: decision.PreviousEligibilityHash,
		EligibilityHash:          decision.EligibilityHash,
		RegistryScope:            registry.registryScope,
		RegistryKeyID:            decision.RegistryKeyID,
	}
}
