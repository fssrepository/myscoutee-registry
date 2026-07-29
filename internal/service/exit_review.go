package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultExitReviewLimit = 50
	maxExitReviewLimit     = 200
)

var (
	exitReviewIDPattern      = regexp.MustCompile(`^exr_[0-9a-f]{32}$`)
	exitReviewEventIDPattern = regexp.MustCompile(`^exe_[0-9a-f]{32}$`)
	exitReviewActorPattern   = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$`,
	)
	exitReviewReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
)

type ExitReviewFreeze struct {
	RecordDate         string
	TargetDeploymentID string
	ClaimActionID      string
	GroupID            string
	ActorRole          string
	ActorID            string
	Reference          string
	EvidenceHash       string
	IdempotencyKey     string
}

type ExitReviewDecision struct {
	ReviewID       string
	Decision       string
	EffectiveDate  string
	ActorRole      string
	ActorID        string
	Reference      string
	EvidenceHash   string
	ReasonCode     string
	IdempotencyKey string
}

type ExitReviewStateChange struct {
	ReviewID       string
	EffectiveDate  string
	ActorRole      string
	ActorID        string
	Reference      string
	EvidenceHash   string
	ReasonCode     string
	IdempotencyKey string
}

func (registry *Service) FreezeExitReview(
	ctx context.Context,
	input ExitReviewFreeze,
) (protocol.ExitReviewMutationResult, error) {
	if err := validateExitReviewDate(
		"record_date",
		input.RecordDate,
		registry.canonicalNow(),
		true,
	); err != nil {
		return protocol.ExitReviewMutationResult{}, err
	}
	if !deploymentIDPattern.MatchString(input.TargetDeploymentID) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("target_deployment_id is malformed")
	}
	if !operatorActionIDPattern.MatchString(input.ClaimActionID) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("claim_action_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(input.GroupID) {
		return protocol.ExitReviewMutationResult{}, fmt.Errorf("group_id is malformed")
	}
	evidenceHash, err := validateExitReviewActorFields(
		input.ActorRole,
		input.ActorID,
		input.Reference,
		input.EvidenceHash,
		input.IdempotencyKey,
	)
	if err != nil {
		return protocol.ExitReviewMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitReviewMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before exit freeze: %w",
			err,
		)
	}
	reviewID, err := registry.newID("exr_")
	if err != nil {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("generate exit review ID: %w", err)
	}
	eventID, err := registry.newID("exe_")
	if err != nil {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("generate exit review event ID: %w", err)
	}
	if !exitReviewIDPattern.MatchString(reviewID) ||
		!exitReviewEventIDPattern.MatchString(eventID) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("generated exit review identifier is malformed")
	}
	event, review, duplicate, err := registry.store.FreezeExitReview(
		ctx,
		store.ExitReviewFreezeInput{
			RecordDate:         input.RecordDate,
			TargetDeploymentID: input.TargetDeploymentID,
			ClaimActionID:      input.ClaimActionID,
			GroupID:            input.GroupID,
			ActorRole:          input.ActorRole,
			ActorID:            input.ActorID,
			Reference:          input.Reference,
			EvidenceHash:       evidenceHash,
			IdempotencyKey:     input.IdempotencyKey,
			CandidateReviewID:  reviewID,
			CandidateEventID:   eventID,
			AcceptedAt:         registry.canonicalNow().Format(time.RFC3339),
			RegistryScope:      registry.registryScope,
			RegistryKeyID:      registry.signingKey.KeyID(),
		},
		registry.signExitReviewEvent,
	)
	if err != nil {
		return protocol.ExitReviewMutationResult{}, mapExitReviewStoreError(err)
	}
	return protocol.ExitReviewMutationResult{
		Duplicate: duplicate,
		Review:    exitReviewProtocolReview(review),
		Event:     exitReviewServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) DecideExitReview(
	ctx context.Context,
	input ExitReviewDecision,
) (protocol.ExitReviewMutationResult, error) {
	decision := strings.TrimSpace(input.Decision)
	action := ""
	status := ""
	switch decision {
	case protocol.ExitReviewActionVerify:
		action = protocol.ExitReviewActionVerify
		status = protocol.ExitReviewStatusEligible
		if input.ReasonCode != "" {
			return protocol.ExitReviewMutationResult{},
				fmt.Errorf("reason_code must be empty for verify")
		}
	case protocol.ExitReviewActionReject:
		action = protocol.ExitReviewActionReject
		status = protocol.ExitReviewStatusRejected
		if !exitReviewReasonPattern.MatchString(input.ReasonCode) {
			return protocol.ExitReviewMutationResult{},
				fmt.Errorf("reason_code must be a 3-64 character lowercase token for reject")
		}
	default:
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("decision must be verify or reject")
	}
	return registry.appendExitReviewMutation(
		ctx,
		action,
		status,
		ExitReviewStateChange{
			ReviewID:       input.ReviewID,
			EffectiveDate:  input.EffectiveDate,
			ActorRole:      input.ActorRole,
			ActorID:        input.ActorID,
			Reference:      input.Reference,
			EvidenceHash:   input.EvidenceHash,
			ReasonCode:     input.ReasonCode,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
}

func (registry *Service) DisputeExitReview(
	ctx context.Context,
	input ExitReviewStateChange,
) (protocol.ExitReviewMutationResult, error) {
	if !exitReviewReasonPattern.MatchString(input.ReasonCode) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("reason_code must be a 3-64 character lowercase token")
	}
	return registry.appendExitReviewMutation(
		ctx,
		protocol.ExitReviewActionDispute,
		protocol.ExitReviewStatusDisputed,
		input,
	)
}

func (registry *Service) WithdrawExitReview(
	ctx context.Context,
	input ExitReviewStateChange,
) (protocol.ExitReviewMutationResult, error) {
	if !exitReviewReasonPattern.MatchString(input.ReasonCode) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("reason_code must be a 3-64 character lowercase token")
	}
	return registry.appendExitReviewMutation(
		ctx,
		protocol.ExitReviewActionWithdraw,
		protocol.ExitReviewStatusWithdrawn,
		input,
	)
}

func (registry *Service) ExitReview(
	ctx context.Context,
	reviewID string,
) (protocol.ExitReview, error) {
	if !exitReviewIDPattern.MatchString(reviewID) {
		return protocol.ExitReview{}, fmt.Errorf("review_id is malformed")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitReview{}, fmt.Errorf(
			"registry integrity verification failed before exit review read: %w",
			err,
		)
	}
	review, err := registry.store.ExitReview(ctx, reviewID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.ExitReview{}, fmt.Errorf(
				"exit review was not found: %w",
				err,
			)
		}
		return protocol.ExitReview{}, err
	}
	return exitReviewProtocolReview(review), nil
}

func (registry *Service) ExitReviews(
	ctx context.Context,
	status string,
	limit int,
	beforeEventIndex int64,
) (protocol.ExitReviewPage, error) {
	status = strings.TrimSpace(status)
	if status != "" && !validExitReviewStatus(status) {
		return protocol.ExitReviewPage{}, fmt.Errorf("status is invalid")
	}
	if limit == 0 {
		limit = defaultExitReviewLimit
	}
	if limit < 1 || limit > maxExitReviewLimit {
		return protocol.ExitReviewPage{},
			fmt.Errorf("limit must be between 1 and %d", maxExitReviewLimit)
	}
	if beforeEventIndex < 0 {
		return protocol.ExitReviewPage{},
			fmt.Errorf("before_event_index cannot be negative")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitReviewPage{}, fmt.Errorf(
			"registry integrity verification failed before exit review list: %w",
			err,
		)
	}
	page, err := registry.store.ExitReviews(ctx, store.ExitReviewQuery{
		Status:           status,
		Limit:            limit,
		BeforeEventIndex: beforeEventIndex,
	})
	if err != nil {
		return protocol.ExitReviewPage{}, err
	}
	items := make([]protocol.ExitReview, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, exitReviewProtocolReview(item))
	}
	return protocol.ExitReviewPage{
		Items:          items,
		NextEventIndex: page.NextEventIndex,
	}, nil
}

func (registry *Service) appendExitReviewMutation(
	ctx context.Context,
	action string,
	status string,
	input ExitReviewStateChange,
) (protocol.ExitReviewMutationResult, error) {
	if !exitReviewIDPattern.MatchString(input.ReviewID) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("review_id is malformed")
	}
	if err := validateExitReviewDate(
		"effective_date",
		input.EffectiveDate,
		registry.canonicalNow(),
		false,
	); err != nil {
		return protocol.ExitReviewMutationResult{}, err
	}
	evidenceHash, err := validateExitReviewActorFields(
		input.ActorRole,
		input.ActorID,
		input.Reference,
		input.EvidenceHash,
		input.IdempotencyKey,
	)
	if err != nil {
		return protocol.ExitReviewMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitReviewMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before exit review mutation: %w",
			err,
		)
	}
	current, err := registry.store.ExitReview(ctx, input.ReviewID)
	if err != nil {
		return protocol.ExitReviewMutationResult{}, mapExitReviewStoreError(err)
	}
	eventID, err := registry.newID("exe_")
	if err != nil {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("generate exit review event ID: %w", err)
	}
	if !exitReviewEventIDPattern.MatchString(eventID) {
		return protocol.ExitReviewMutationResult{},
			fmt.Errorf("generated exit review event ID is malformed")
	}
	unsigned := protocol.ExitReviewEvent{
		ReviewID:        input.ReviewID,
		Action:          action,
		ResultingStatus: status,
		EffectiveDate:   input.EffectiveDate,
		ActorRole:       input.ActorRole,
		ActorID:         input.ActorID,
		Reference:       input.Reference,
		EvidenceHash:    evidenceHash,
		ReasonCode:      input.ReasonCode,
		RecordHash:      current.Record.RecordHash,
	}
	payloadHash := protocol.Digest(
		protocol.ExitReviewEventPayloadMessage(unsigned),
	)
	event, review, duplicate, err := registry.store.AppendExitReviewEvent(
		ctx,
		store.ExitReviewMutationInput{
			ReviewID:         input.ReviewID,
			Action:           action,
			ResultingStatus:  status,
			EffectiveDate:    input.EffectiveDate,
			ActorRole:        input.ActorRole,
			ActorID:          input.ActorID,
			Reference:        input.Reference,
			EvidenceHash:     evidenceHash,
			ReasonCode:       input.ReasonCode,
			IdempotencyKey:   input.IdempotencyKey,
			PayloadHash:      payloadHash,
			CandidateEventID: eventID,
			AcceptedAt:       registry.canonicalNow().Format(time.RFC3339),
			RegistryScope:    registry.registryScope,
			RegistryKeyID:    registry.signingKey.KeyID(),
		},
		registry.signExitReviewEvent,
	)
	if err != nil {
		return protocol.ExitReviewMutationResult{}, mapExitReviewStoreError(err)
	}
	return protocol.ExitReviewMutationResult{
		Duplicate: duplicate,
		Review:    exitReviewProtocolReview(review),
		Event:     exitReviewServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) signExitReviewEvent(
	event store.ExitReviewEvent,
) ([]byte, error) {
	return registry.signingKey.Sign(
		protocol.ExitReviewEventReceiptMessage(
			exitReviewServiceProtocolEvent(event),
		),
	), nil
}

func validateExitReviewActorFields(
	actorRole string,
	actorID string,
	reference string,
	evidenceHash string,
	idempotencyKey string,
) (string, error) {
	if actorRole != protocol.ExitReviewActorBuyer &&
		actorRole != protocol.ExitReviewActorAuditor {
		return "", fmt.Errorf("actor_role must be buyer or auditor")
	}
	if !exitReviewActorPattern.MatchString(actorID) {
		return "", fmt.Errorf("actor_id is malformed")
	}
	if err := validateClaimText("reference", reference, 240); err != nil {
		return "", err
	}
	if err := validateToken("idempotency_key", idempotencyKey); err != nil {
		return "", err
	}
	evidenceHash = strings.TrimSpace(evidenceHash)
	if evidenceHash == "" {
		evidenceHash = protocol.ExitReviewZeroHash
	}
	if !protocol.IsDigest(evidenceHash) {
		return "", fmt.Errorf(
			"evidence_hash must be a canonical lowercase SHA-256 digest",
		)
	}
	return evidenceHash, nil
}

func validateExitReviewDate(
	name string,
	value string,
	now time.Time,
	requireCompletedDay bool,
) error {
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value {
		return fmt.Errorf("%s must be a canonical UTC date", name)
	}
	today := time.Date(
		now.UTC().Year(),
		now.UTC().Month(),
		now.UTC().Day(),
		0,
		0,
		0,
		0,
		time.UTC,
	)
	if requireCompletedDay {
		if !parsed.Before(today) {
			return fmt.Errorf("%s must identify a completed UTC day", name)
		}
	} else if parsed.After(today) {
		return fmt.Errorf("%s cannot be in the future", name)
	}
	return nil
}

func validExitReviewStatus(value string) bool {
	switch value {
	case protocol.ExitReviewStatusPending,
		protocol.ExitReviewStatusEligible,
		protocol.ExitReviewStatusRejected,
		protocol.ExitReviewStatusDisputed,
		protocol.ExitReviewStatusWithdrawn:
		return true
	default:
		return false
	}
}

func mapExitReviewStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrIdempotencyConflict):
		return fmt.Errorf("idempotency_key conflicts with another exit review mutation: %w", err)
	case errors.Is(err, store.ErrExitReviewAlreadyFrozen):
		return fmt.Errorf("this exact claim generation already has an exit review: %w", err)
	case errors.Is(err, store.ErrExitReviewClaimBoundary):
		return fmt.Errorf("claim generation is not eligible at the requested record date: %w", err)
	case errors.Is(err, store.ErrExitReviewTransition):
		return fmt.Errorf("exit review state transition is not allowed: %w", err)
	case errors.Is(err, store.ErrExitReviewClockBeforeHead):
		return fmt.Errorf("registry clock is before the immutable exit-review head: %w", err)
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("exit review or frozen boundary was not found: %w", err)
	default:
		return err
	}
}

func exitReviewServiceProtocolEvent(
	event store.ExitReviewEvent,
) protocol.ExitReviewEvent {
	return protocol.ExitReviewEvent{
		EventIndex:              event.EventIndex,
		EventID:                 event.EventID,
		ReviewID:                event.ReviewID,
		Action:                  event.Action,
		ResultingStatus:         event.ResultingStatus,
		EffectiveDate:           event.EffectiveDate,
		ActorRole:               event.ActorRole,
		ActorID:                 event.ActorID,
		Reference:               event.Reference,
		EvidenceHash:            event.EvidenceHash,
		ReasonCode:              event.ReasonCode,
		IdempotencyKey:          event.IdempotencyKey,
		PayloadHash:             event.PayloadHash,
		RecordHash:              event.RecordHash,
		AcceptedAt:              event.AcceptedAt,
		PreviousEventHash:       event.PreviousEventHash,
		PreviousReviewEventHash: event.PreviousReviewEventHash,
		EventHash:               event.EventHash,
		RegistryScope:           event.RegistryScope,
		RegistryKeyID:           event.RegistryKeyID,
		Signature: base64.StdEncoding.EncodeToString(
			event.Signature,
		),
	}
}

func exitReviewProtocolReview(item store.ExitReview) protocol.ExitReview {
	record := exitReviewServiceProtocolRecord(item.Record)
	events := make([]protocol.ExitReviewEvent, 0, len(item.Events))
	for _, event := range item.Events {
		events = append(events, exitReviewServiceProtocolEvent(event))
	}
	return protocol.ExitReview{
		Record:                record,
		Status:                item.Status,
		LatestEventIndex:      item.LatestEventIndex,
		LatestEventHash:       item.LatestEventHash,
		LatestAction:          item.LatestAction,
		LatestEffectiveDate:   item.LatestEffectiveDate,
		LatestActorRole:       item.LatestActorRole,
		LatestActorID:         item.LatestActorID,
		LatestReference:       item.LatestReference,
		LatestEvidenceHash:    item.LatestEvidenceHash,
		LatestReasonCode:      item.LatestReasonCode,
		LatestAcceptedAt:      item.LatestAcceptedAt,
		Events:                events,
	}
}

func exitReviewServiceProtocolRecord(
	record store.ExitReviewRecord,
) protocol.ExitReviewRecord {
	deployments := make([]protocol.ExitReviewDeployment, 0, len(record.Deployments))
	for _, item := range record.Deployments {
		deployments = append(deployments, protocol.ExitReviewDeployment{
			MemberOrder:       item.MemberOrder,
			DeploymentID:     item.DeploymentID,
			ClaimActionID:    item.ClaimActionID,
			ClaimState:       item.ClaimState,
			EligibilityState: item.EligibilityState,
			ClaimAuditIndex:  item.ClaimAuditIndex,
			ClaimAuditHash:   item.ClaimAuditHash,
			ReviewIndex:      item.ReviewIndex,
			ReviewHash:       item.ReviewHash,
			EligibilityIndex: item.EligibilityIndex,
			EligibilityHash:  item.EligibilityHash,
		})
	}
	settlements := make(
		[]protocol.ExitReviewSettlementBoundary,
		0,
		len(record.Settlements),
	)
	for _, item := range record.Settlements {
		settlements = append(
			settlements,
			protocol.ExitReviewSettlementBoundary{
				BoundaryOrder:     item.BoundaryOrder,
				SettlementID:      item.SettlementID,
				Period:            item.Period,
				CurrencyCode:      item.CurrencyCode,
				Revision:          item.Revision,
				LedgerIndex:       item.LedgerIndex,
				SettlementHash:    item.SettlementHash,
				SourceFingerprint: item.SourceFingerprint,
				AllocationHash:    item.AllocationHash,
			},
		)
	}
	return protocol.ExitReviewRecord{
		ReviewID:                     record.ReviewID,
		RulesetVersion:               record.RulesetVersion,
		RecordDate:                   record.RecordDate,
		TargetDeploymentID:           record.TargetDeploymentID,
		ClaimActionID:                record.ClaimActionID,
		GroupID:                      record.GroupID,
		LegalName:                    record.LegalName,
		CheckpointHash:               record.CheckpointHash,
		ThroughLedgerIndex:           record.ThroughLedgerIndex,
		LedgerHeadHash:               record.LedgerHeadHash,
		MerkleTreeSize:               record.MerkleTreeSize,
		MerkleRootHash:               record.MerkleRootHash,
		ThroughAuditIndex:            record.ThroughAuditIndex,
		AuditHeadHash:                record.AuditHeadHash,
		ThroughReviewIndex:           record.ThroughReviewIndex,
		ClaimReviewHeadHash:          record.ClaimReviewHeadHash,
		ThroughEligibilityIndex:      record.ThroughEligibilityIndex,
		EligibilityHeadHash:          record.EligibilityHeadHash,
		ThroughSettlementLedgerIndex: record.ThroughSettlementLedgerIndex,
		SettlementBoundaryCount:      record.SettlementBoundaryCount,
		SettlementBoundaryHash:       record.SettlementBoundaryHash,
		DeploymentCount:              record.DeploymentCount,
		MembershipHash:               record.MembershipHash,
		FrozenAt:                     record.FrozenAt,
		RecordHash:                   record.RecordHash,
		RegistryScope:                record.RegistryScope,
		RegistryKeyID:                record.RegistryKeyID,
		Deployments:                  deployments,
		Settlements:                  settlements,
	}
}
