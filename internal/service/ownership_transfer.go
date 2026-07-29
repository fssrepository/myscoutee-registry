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
	defaultOwnershipTransferLimit = 50
	maxOwnershipTransferLimit     = 200
)

var (
	ownershipTransferIDPattern      = regexp.MustCompile(`^otf_[0-9a-f]{32}$`)
	ownershipTransferEventIDPattern = regexp.MustCompile(
		`^ote_[0-9a-f]{32}$`,
	)
	ownershipTransferActorPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$`,
	)
	ownershipTransferReasonPattern = regexp.MustCompile(
		`^[a-z][a-z0-9-]{2,63}$`,
	)
)

type OwnershipTransferPrepare struct {
	ExitReviewID              string
	TargetDeploymentID        string
	ClaimActionID             string
	SourceGroupID             string
	TargetGroupID             string
	ExitVerificationEventHash string
	RequesterID               string
	Reference                 string
	EvidenceHash              string
	IdempotencyKey            string
}

type OwnershipTransferDecision struct {
	TransferID     string
	Decision       string
	EffectiveDate  string
	ManagerID      string
	Reference      string
	EvidenceHash   string
	ReasonCode     string
	IdempotencyKey string
}

type OwnershipTransferStateChange struct {
	TransferID     string
	EffectiveDate  string
	ManagerID      string
	Reference      string
	EvidenceHash   string
	ReasonCode     string
	IdempotencyKey string
}

func (registry *Service) PrepareOwnershipTransfer(
	ctx context.Context,
	input OwnershipTransferPrepare,
) (protocol.OwnershipTransferMutationResult, error) {
	if !exitReviewIDPattern.MatchString(input.ExitReviewID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("exit_review_id is malformed")
	}
	if !deploymentIDPattern.MatchString(input.TargetDeploymentID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("target_deployment_id is malformed")
	}
	if !operatorActionIDPattern.MatchString(input.ClaimActionID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("claim_action_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(input.SourceGroupID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("source_group_id is malformed")
	}
	if !operatorGroupIDPattern.MatchString(input.TargetGroupID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("target_group_id is malformed")
	}
	if input.SourceGroupID == input.TargetGroupID {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("target_group_id must differ from source_group_id")
	}
	if !protocol.IsDigest(input.ExitVerificationEventHash) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("exit_verification_event_hash must be a canonical lowercase SHA-256 digest")
	}
	evidenceHash, err := validateOwnershipTransferActorFields(
		input.RequesterID,
		input.Reference,
		input.EvidenceHash,
		input.IdempotencyKey,
	)
	if err != nil {
		return protocol.OwnershipTransferMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OwnershipTransferMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before ownership transfer prepare: %w",
			err,
		)
	}
	transferID, err := registry.newID("otf_")
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("generate ownership transfer ID: %w", err)
	}
	eventID, err := registry.newID("ote_")
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("generate ownership transfer event ID: %w", err)
	}
	if !ownershipTransferIDPattern.MatchString(transferID) ||
		!ownershipTransferEventIDPattern.MatchString(eventID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("generated ownership transfer identifier is malformed")
	}
	event, transfer, duplicate, err := registry.store.PrepareOwnershipTransfer(
		ctx,
		store.OwnershipTransferPrepareInput{
			ExitReviewID:              input.ExitReviewID,
			TargetDeploymentID:        input.TargetDeploymentID,
			ClaimActionID:             input.ClaimActionID,
			SourceGroupID:             input.SourceGroupID,
			TargetGroupID:             input.TargetGroupID,
			ExitVerificationEventHash: input.ExitVerificationEventHash,
			ActorID:                   input.RequesterID,
			Reference:                 input.Reference,
			EvidenceHash:              evidenceHash,
			IdempotencyKey:            input.IdempotencyKey,
			CandidateTransferID:       transferID,
			CandidateEventID:          eventID,
			AcceptedAt: registry.canonicalNow().Format(
				time.RFC3339,
			),
			RegistryScope: registry.registryScope,
			RegistryKeyID: registry.signingKey.KeyID(),
		},
		registry.signOwnershipTransferEvent,
	)
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			mapOwnershipTransferStoreError(err)
	}
	return protocol.OwnershipTransferMutationResult{
		Duplicate: duplicate,
		Transfer:  ownershipTransferProtocolTransfer(transfer),
		Event:     ownershipTransferServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) DecideOwnershipTransfer(
	ctx context.Context,
	input OwnershipTransferDecision,
) (protocol.OwnershipTransferMutationResult, error) {
	decision := strings.TrimSpace(input.Decision)
	action := ""
	status := ""
	switch decision {
	case protocol.OwnershipTransferActionApprove:
		action = protocol.OwnershipTransferActionApprove
		status = protocol.OwnershipTransferStatusApproved
		if input.ReasonCode != "" {
			return protocol.OwnershipTransferMutationResult{},
				fmt.Errorf("reason_code must be empty for approve")
		}
	case protocol.OwnershipTransferActionReject:
		action = protocol.OwnershipTransferActionReject
		status = protocol.OwnershipTransferStatusRejected
		if !ownershipTransferReasonPattern.MatchString(input.ReasonCode) {
			return protocol.OwnershipTransferMutationResult{},
				fmt.Errorf("reason_code must be a 3-64 character lowercase token for reject")
		}
	default:
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("decision must be approve or reject")
	}
	return registry.appendOwnershipTransferMutation(
		ctx,
		action,
		status,
		OwnershipTransferStateChange{
			TransferID:     input.TransferID,
			EffectiveDate:  input.EffectiveDate,
			ManagerID:      input.ManagerID,
			Reference:      input.Reference,
			EvidenceHash:   input.EvidenceHash,
			ReasonCode:     input.ReasonCode,
			IdempotencyKey: input.IdempotencyKey,
		},
	)
}

func (registry *Service) CancelOwnershipTransfer(
	ctx context.Context,
	input OwnershipTransferStateChange,
) (protocol.OwnershipTransferMutationResult, error) {
	if !ownershipTransferReasonPattern.MatchString(input.ReasonCode) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("reason_code must be a 3-64 character lowercase token")
	}
	return registry.appendOwnershipTransferMutation(
		ctx,
		protocol.OwnershipTransferActionCancel,
		protocol.OwnershipTransferStatusCancelled,
		input,
	)
}

func (registry *Service) CompleteOwnershipTransfer(
	ctx context.Context,
	input OwnershipTransferStateChange,
) (protocol.OwnershipTransferMutationResult, error) {
	if input.ReasonCode != "" {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("reason_code must be empty for complete")
	}
	return registry.appendOwnershipTransferMutation(
		ctx,
		protocol.OwnershipTransferActionComplete,
		protocol.OwnershipTransferStatusCompleted,
		input,
	)
}

func (registry *Service) OwnershipTransfer(
	ctx context.Context,
	transferID string,
) (protocol.OwnershipTransfer, error) {
	if !ownershipTransferIDPattern.MatchString(transferID) {
		return protocol.OwnershipTransfer{}, fmt.Errorf("transfer_id is malformed")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OwnershipTransfer{}, fmt.Errorf(
			"registry integrity verification failed before ownership transfer read: %w",
			err,
		)
	}
	transfer, err := registry.store.OwnershipTransfer(ctx, transferID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.OwnershipTransfer{}, fmt.Errorf(
				"ownership transfer was not found: %w",
				err,
			)
		}
		return protocol.OwnershipTransfer{}, err
	}
	return ownershipTransferProtocolTransfer(transfer), nil
}

func (registry *Service) OwnershipTransfers(
	ctx context.Context,
	status string,
	limit int,
	beforeEventIndex int64,
) (protocol.OwnershipTransferPage, error) {
	status = strings.TrimSpace(status)
	if status != "" && !validOwnershipTransferStatus(status) {
		return protocol.OwnershipTransferPage{}, fmt.Errorf("status is invalid")
	}
	if limit == 0 {
		limit = defaultOwnershipTransferLimit
	}
	if limit < 1 || limit > maxOwnershipTransferLimit {
		return protocol.OwnershipTransferPage{},
			fmt.Errorf(
				"limit must be between 1 and %d",
				maxOwnershipTransferLimit,
			)
	}
	if beforeEventIndex < 0 {
		return protocol.OwnershipTransferPage{},
			fmt.Errorf("before_event_index cannot be negative")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OwnershipTransferPage{}, fmt.Errorf(
			"registry integrity verification failed before ownership transfer list: %w",
			err,
		)
	}
	page, err := registry.store.OwnershipTransfers(
		ctx,
		store.OwnershipTransferQuery{
			Status:           status,
			Limit:            limit,
			BeforeEventIndex: beforeEventIndex,
		},
	)
	if err != nil {
		return protocol.OwnershipTransferPage{}, err
	}
	items := make([]protocol.OwnershipTransfer, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, ownershipTransferProtocolTransfer(item))
	}
	return protocol.OwnershipTransferPage{
		Items:          items,
		NextEventIndex: page.NextEventIndex,
	}, nil
}

func (registry *Service) appendOwnershipTransferMutation(
	ctx context.Context,
	action string,
	status string,
	input OwnershipTransferStateChange,
) (protocol.OwnershipTransferMutationResult, error) {
	if !ownershipTransferIDPattern.MatchString(input.TransferID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("transfer_id is malformed")
	}
	now := registry.canonicalNow()
	if err := validateExitReviewDate(
		"effective_date",
		input.EffectiveDate,
		now,
		false,
	); err != nil {
		return protocol.OwnershipTransferMutationResult{}, err
	}
	evidenceHash, err := validateOwnershipTransferActorFields(
		input.ManagerID,
		input.Reference,
		input.EvidenceHash,
		input.IdempotencyKey,
	)
	if err != nil {
		return protocol.OwnershipTransferMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.OwnershipTransferMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before ownership transfer mutation: %w",
			err,
		)
	}
	current, err := registry.store.OwnershipTransfer(ctx, input.TransferID)
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			mapOwnershipTransferStoreError(err)
	}
	eventID, err := registry.newID("ote_")
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("generate ownership transfer event ID: %w", err)
	}
	if !ownershipTransferEventIDPattern.MatchString(eventID) {
		return protocol.OwnershipTransferMutationResult{},
			fmt.Errorf("generated ownership transfer event ID is malformed")
	}
	unsigned := protocol.OwnershipTransferEvent{
		TransferID:      input.TransferID,
		Action:          action,
		ResultingStatus: status,
		EffectiveDate:   input.EffectiveDate,
		ActorRole:       protocol.OwnershipTransferActorManager,
		ActorID:         input.ManagerID,
		Reference:       input.Reference,
		EvidenceHash:    evidenceHash,
		ReasonCode:      input.ReasonCode,
		RecordHash:      current.Record.RecordHash,
	}
	payloadHash := protocol.Digest(
		protocol.OwnershipTransferEventPayloadMessage(unsigned),
	)
	event, transfer, duplicate, err :=
		registry.store.AppendOwnershipTransferEvent(
			ctx,
			store.OwnershipTransferMutationInput{
				TransferID:       input.TransferID,
				Action:           action,
				ResultingStatus:  status,
				EffectiveDate:    input.EffectiveDate,
				ActorID:          input.ManagerID,
				Reference:        input.Reference,
				EvidenceHash:     evidenceHash,
				ReasonCode:       input.ReasonCode,
				IdempotencyKey:   input.IdempotencyKey,
				PayloadHash:      payloadHash,
				CandidateEventID: eventID,
				AcceptedAt:       now.Format(time.RFC3339),
				RegistryScope:    registry.registryScope,
				RegistryKeyID:    registry.signingKey.KeyID(),
			},
			registry.signOwnershipTransferEvent,
		)
	if err != nil {
		return protocol.OwnershipTransferMutationResult{},
			mapOwnershipTransferStoreError(err)
	}
	return protocol.OwnershipTransferMutationResult{
		Duplicate: duplicate,
		Transfer:  ownershipTransferProtocolTransfer(transfer),
		Event:     ownershipTransferServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) signOwnershipTransferEvent(
	event store.OwnershipTransferEvent,
) ([]byte, error) {
	return registry.signingKey.Sign(
		protocol.OwnershipTransferEventReceiptMessage(
			ownershipTransferServiceProtocolEvent(event),
		),
	), nil
}

func validateOwnershipTransferActorFields(
	actorID string,
	reference string,
	evidenceHash string,
	idempotencyKey string,
) (string, error) {
	if !ownershipTransferActorPattern.MatchString(actorID) {
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
		evidenceHash = protocol.OwnershipTransferZeroHash
	}
	if !protocol.IsDigest(evidenceHash) {
		return "", fmt.Errorf(
			"evidence_hash must be a canonical lowercase SHA-256 digest",
		)
	}
	return evidenceHash, nil
}

func validOwnershipTransferStatus(value string) bool {
	switch value {
	case protocol.OwnershipTransferStatusPrepared,
		protocol.OwnershipTransferStatusApproved,
		protocol.OwnershipTransferStatusRejected,
		protocol.OwnershipTransferStatusCancelled,
		protocol.OwnershipTransferStatusCompleted:
		return true
	default:
		return false
	}
}

func mapOwnershipTransferStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrIdempotencyConflict):
		return fmt.Errorf(
			"idempotency_key conflicts with another ownership transfer mutation: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferClaimBoundary):
		return fmt.Errorf(
			"claim generation is no longer current, approved, active, and eligible in the source group: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferExitBoundary):
		return fmt.Errorf(
			"exit review is not at the exact verified event boundary: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferTargetGroup):
		return fmt.Errorf(
			"target group has no current active approved eligible claim: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferConflict):
		return fmt.Errorf(
			"another prepared or approved transfer targets this claim generation: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferTransition):
		return fmt.Errorf(
			"ownership transfer state transition is not allowed: %w",
			err,
		)
	case errors.Is(err, store.ErrOwnershipTransferClockBeforeHead):
		return fmt.Errorf(
			"registry clock does not safely extend the ownership/ledger boundary: %w",
			err,
		)
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("ownership transfer was not found: %w", err)
	default:
		return err
	}
}

func ownershipTransferServiceProtocolEvent(
	event store.OwnershipTransferEvent,
) protocol.OwnershipTransferEvent {
	result := protocol.OwnershipTransferEvent{
		EventIndex:                event.EventIndex,
		EventID:                   event.EventID,
		TransferID:                event.TransferID,
		Action:                    event.Action,
		ResultingStatus:           event.ResultingStatus,
		EffectiveDate:             event.EffectiveDate,
		ActorRole:                 event.ActorRole,
		ActorID:                   event.ActorID,
		Reference:                 event.Reference,
		EvidenceHash:              event.EvidenceHash,
		ReasonCode:                event.ReasonCode,
		IdempotencyKey:            event.IdempotencyKey,
		PayloadHash:               event.PayloadHash,
		RecordHash:                event.RecordHash,
		AcceptedAt:                event.AcceptedAt,
		PreviousEventHash:         event.PreviousEventHash,
		PreviousTransferEventHash: event.PreviousTransferEventHash,
		EventHash:                 event.EventHash,
		RegistryScope:             event.RegistryScope,
		RegistryKeyID:             event.RegistryKeyID,
	}
	if len(event.Signature) > 0 {
		result.Signature = base64.StdEncoding.EncodeToString(event.Signature)
	}
	return result
}

func ownershipTransferProtocolTransfer(
	item store.OwnershipTransfer,
) protocol.OwnershipTransfer {
	events := make([]protocol.OwnershipTransferEvent, 0, len(item.Events))
	for _, event := range item.Events {
		events = append(events, ownershipTransferServiceProtocolEvent(event))
	}
	var membership *protocol.OwnershipTransferMembership
	if item.Membership != nil {
		converted := protocol.OwnershipTransferMembership{
			TransferID:           item.Membership.TransferID,
			CompletionEventIndex: item.Membership.CompletionEventIndex,
			CompletionEventHash:  item.Membership.CompletionEventHash,
			TargetDeploymentID:   item.Membership.TargetDeploymentID,
			ClaimActionID:        item.Membership.ClaimActionID,
			SourceGroupID:        item.Membership.SourceGroupID,
			TargetGroupID:        item.Membership.TargetGroupID,
			EffectiveDate:        item.Membership.EffectiveDate,
			ThroughAuditIndex:    item.Membership.ThroughAuditIndex,
			AuditHeadHash:        item.Membership.AuditHeadHash,
			CompletedAt:          item.Membership.CompletedAt,
			MembershipHash:       item.Membership.MembershipHash,
		}
		membership = &converted
	}
	return protocol.OwnershipTransfer{
		Record: protocol.OwnershipTransferRecord{
			TransferID:                 item.Record.TransferID,
			RulesetVersion:             item.Record.RulesetVersion,
			ExitReviewID:               item.Record.ExitReviewID,
			TargetDeploymentID:         item.Record.TargetDeploymentID,
			ClaimActionID:              item.Record.ClaimActionID,
			SourceGroupID:              item.Record.SourceGroupID,
			TargetGroupID:              item.Record.TargetGroupID,
			LegalName:                  item.Record.LegalName,
			ExitRecordHash:             item.Record.ExitRecordHash,
			ExitVerificationEventIndex: item.Record.ExitVerificationEventIndex,
			ExitVerificationEventHash:  item.Record.ExitVerificationEventHash,
			ExitEvidenceHash:           item.Record.ExitEvidenceHash,
			PreparedAt:                 item.Record.PreparedAt,
			RecordHash:                 item.Record.RecordHash,
			RegistryScope:              item.Record.RegistryScope,
			RegistryKeyID:              item.Record.RegistryKeyID,
		},
		Status:              item.Status,
		LatestEventIndex:    item.LatestEventIndex,
		LatestEventHash:     item.LatestEventHash,
		LatestAction:        item.LatestAction,
		LatestEffectiveDate: item.LatestEffectiveDate,
		LatestActorRole:     item.LatestActorRole,
		LatestActorID:       item.LatestActorID,
		LatestReference:     item.LatestReference,
		LatestEvidenceHash:  item.LatestEvidenceHash,
		LatestReasonCode:    item.LatestReasonCode,
		LatestAcceptedAt:    item.LatestAcceptedAt,
		Membership:          membership,
		Events:              events,
	}
}
