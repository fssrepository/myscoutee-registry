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
	defaultExitAllocationLimit = 50
	maxExitAllocationLimit     = 200
)

var (
	exitAllocationIDPattern = regexp.MustCompile(`^xal_[0-9a-f]{32}$`)
	exitAllocationEventIDPattern = regexp.MustCompile(
		`^xae_[0-9a-f]{32}$`,
	)
	exitAllocationPartyIDPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}$`,
	)
)

type ExitAllocationCreate struct {
	ExitReviewID                         string
	ExitVerificationEventHash            string
	DecisionMode                         string
	OwnershipTransferID                  string
	OwnershipTransferCompletionEventHash string
	BeneficiaryID                        string
	ContractReference                    string
	ContractTermsHash                    string
	EvidenceHash                         string
	AllocatorID                          string
	IdempotencyKey                       string
}

type ExitAllocationVerification struct {
	AllocationID  string
	VerifierID    string
	Reference     string
	EvidenceHash  string
	IdempotencyKey string
}

func (registry *Service) CreateExitAllocation(
	ctx context.Context,
	input ExitAllocationCreate,
) (protocol.ExitAllocationMutationResult, error) {
	if !exitReviewIDPattern.MatchString(input.ExitReviewID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("exit_review_id is malformed")
	}
	if !protocol.IsDigest(input.ExitVerificationEventHash) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"exit_verification_event_hash must be a canonical lowercase SHA-256 digest",
			)
	}
	input.DecisionMode = strings.TrimSpace(input.DecisionMode)
	switch input.DecisionMode {
	case protocol.ExitAllocationDecisionCompletedTransfer:
		if !ownershipTransferIDPattern.MatchString(
			input.OwnershipTransferID,
		) {
			return protocol.ExitAllocationMutationResult{},
				fmt.Errorf("ownership_transfer_id is malformed")
		}
		if !protocol.IsDigest(
			input.OwnershipTransferCompletionEventHash,
		) {
			return protocol.ExitAllocationMutationResult{},
				fmt.Errorf(
					"ownership_transfer_completion_event_hash must be a canonical lowercase SHA-256 digest",
				)
		}
		if input.BeneficiaryID != "" {
			return protocol.ExitAllocationMutationResult{},
				fmt.Errorf(
					"beneficiary_id must be empty for completed-transfer; the target group is derived",
				)
		}
	case protocol.ExitAllocationDecisionNoTransfer:
		if input.OwnershipTransferID != "" ||
			input.OwnershipTransferCompletionEventHash != "" {
			return protocol.ExitAllocationMutationResult{},
				fmt.Errorf(
					"ownership transfer fields must be empty for no-transfer",
				)
		}
		if !exitAllocationPartyIDPattern.MatchString(input.BeneficiaryID) {
			return protocol.ExitAllocationMutationResult{},
				fmt.Errorf("beneficiary_id is malformed")
		}
		input.OwnershipTransferCompletionEventHash =
			protocol.ExitAllocationZeroHash
	default:
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"decision_mode must be completed-transfer or no-transfer",
			)
	}
	if err := validateClaimText(
		"contract_reference",
		input.ContractReference,
		240,
	); err != nil {
		return protocol.ExitAllocationMutationResult{}, err
	}
	if !protocol.IsDigest(input.ContractTermsHash) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"contract_terms_hash must be a canonical lowercase SHA-256 digest",
			)
	}
	if !protocol.IsDigest(input.EvidenceHash) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"evidence_hash must be a canonical lowercase SHA-256 digest",
			)
	}
	if !exitAllocationPartyIDPattern.MatchString(input.AllocatorID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("allocator_id is malformed")
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return protocol.ExitAllocationMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitAllocationMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before final exit allocation create: %w",
			err,
		)
	}
	allocationID, err := registry.newID("xal_")
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("generate final exit allocation ID: %w", err)
	}
	eventID, err := registry.newID("xae_")
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("generate final exit allocation event ID: %w", err)
	}
	if !exitAllocationIDPattern.MatchString(allocationID) ||
		!exitAllocationEventIDPattern.MatchString(eventID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("generated final exit allocation identifier is malformed")
	}
	event, allocation, duplicate, err :=
		registry.store.CreateExitAllocation(
			ctx,
			store.ExitAllocationCreateInput{
				ExitReviewID: input.ExitReviewID,
				ExitVerificationEventHash: input.ExitVerificationEventHash,
				DecisionMode: input.DecisionMode,
				OwnershipTransferID: input.OwnershipTransferID,
				OwnershipTransferCompletionEventHash: input.OwnershipTransferCompletionEventHash,
				BeneficiaryID: input.BeneficiaryID,
				ContractReference: input.ContractReference,
				ContractTermsHash: input.ContractTermsHash,
				EvidenceHash: input.EvidenceHash,
				ActorID: input.AllocatorID,
				IdempotencyKey: input.IdempotencyKey,
				CandidateAllocationID: allocationID,
				CandidateEventID: eventID,
				AcceptedAt: registry.canonicalNow().Format(time.RFC3339),
				RegistryScope: registry.registryScope,
				RegistryKeyID: registry.signingKey.KeyID(),
			},
			registry.signExitAllocationEvent,
		)
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			mapExitAllocationStoreError(err)
	}
	return protocol.ExitAllocationMutationResult{
		Duplicate: duplicate,
		Allocation: exitAllocationProtocolAllocation(allocation),
		Event: exitAllocationServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) VerifyExitAllocation(
	ctx context.Context,
	input ExitAllocationVerification,
) (protocol.ExitAllocationMutationResult, error) {
	if !exitAllocationIDPattern.MatchString(input.AllocationID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("allocation_id is malformed")
	}
	if !exitAllocationPartyIDPattern.MatchString(input.VerifierID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("verifier_id is malformed")
	}
	if err := validateClaimText("reference", input.Reference, 240); err != nil {
		return protocol.ExitAllocationMutationResult{}, err
	}
	if !protocol.IsDigest(input.EvidenceHash) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"evidence_hash must be a canonical lowercase SHA-256 digest",
			)
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return protocol.ExitAllocationMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitAllocationMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before final exit allocation verify: %w",
			err,
		)
	}
	current, err := registry.store.ExitAllocation(ctx, input.AllocationID)
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			mapExitAllocationStoreError(err)
	}
	eventID, err := registry.newID("xae_")
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf("generate final exit allocation event ID: %w", err)
	}
	if !exitAllocationEventIDPattern.MatchString(eventID) {
		return protocol.ExitAllocationMutationResult{},
			fmt.Errorf(
				"generated final exit allocation event ID is malformed",
			)
	}
	unsigned := protocol.ExitAllocationEvent{
		AllocationID: current.Record.AllocationID,
		Action: protocol.ExitAllocationActionVerify,
		ResultingStatus: protocol.ExitAllocationStatusVerifiedFinal,
		ActorRole: protocol.ExitAllocationActorVerifier,
		ActorID: input.VerifierID,
		Reference: input.Reference,
		EvidenceHash: input.EvidenceHash,
		RecordHash: current.Record.RecordHash,
	}
	payloadHash := protocol.Digest(
		protocol.ExitAllocationEventPayloadMessage(unsigned),
	)
	event, allocation, duplicate, err :=
		registry.store.VerifyExitAllocation(
			ctx,
			store.ExitAllocationVerifyInput{
				AllocationID: input.AllocationID,
				ActorID: input.VerifierID,
				Reference: input.Reference,
				EvidenceHash: input.EvidenceHash,
				IdempotencyKey: input.IdempotencyKey,
				PayloadHash: payloadHash,
				CandidateEventID: eventID,
				AcceptedAt: registry.canonicalNow().Format(time.RFC3339),
				RegistryScope: registry.registryScope,
				RegistryKeyID: registry.signingKey.KeyID(),
			},
			registry.signExitAllocationEvent,
		)
	if err != nil {
		return protocol.ExitAllocationMutationResult{},
			mapExitAllocationStoreError(err)
	}
	return protocol.ExitAllocationMutationResult{
		Duplicate: duplicate,
		Allocation: exitAllocationProtocolAllocation(allocation),
		Event: exitAllocationServiceProtocolEvent(event),
	}, nil
}

func (registry *Service) ExitAllocation(
	ctx context.Context,
	allocationID string,
) (protocol.ExitAllocation, error) {
	if !exitAllocationIDPattern.MatchString(allocationID) {
		return protocol.ExitAllocation{}, fmt.Errorf("allocation_id is malformed")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitAllocation{}, fmt.Errorf(
			"registry integrity verification failed before final exit allocation read: %w",
			err,
		)
	}
	allocation, err := registry.store.ExitAllocation(ctx, allocationID)
	if err != nil {
		return protocol.ExitAllocation{}, mapExitAllocationStoreError(err)
	}
	return exitAllocationProtocolAllocation(allocation), nil
}

func (registry *Service) ExitAllocations(
	ctx context.Context,
	status string,
	decisionMode string,
	limit int,
	beforeEventIndex int64,
) (protocol.ExitAllocationPage, error) {
	status = strings.TrimSpace(status)
	if status != "" &&
		status != protocol.ExitAllocationStatusRecorded &&
		status != protocol.ExitAllocationStatusVerifiedFinal {
		return protocol.ExitAllocationPage{}, fmt.Errorf("status is invalid")
	}
	decisionMode = strings.TrimSpace(decisionMode)
	if decisionMode != "" &&
		decisionMode != protocol.ExitAllocationDecisionCompletedTransfer &&
		decisionMode != protocol.ExitAllocationDecisionNoTransfer {
		return protocol.ExitAllocationPage{},
			fmt.Errorf("decision_mode is invalid")
	}
	if limit == 0 {
		limit = defaultExitAllocationLimit
	}
	if limit < 1 || limit > maxExitAllocationLimit {
		return protocol.ExitAllocationPage{},
			fmt.Errorf(
				"limit must be between 1 and %d",
				maxExitAllocationLimit,
			)
	}
	if beforeEventIndex < 0 {
		return protocol.ExitAllocationPage{},
			fmt.Errorf("before_event_index cannot be negative")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.ExitAllocationPage{}, fmt.Errorf(
			"registry integrity verification failed before final exit allocation list: %w",
			err,
		)
	}
	page, err := registry.store.ExitAllocations(
		ctx,
		store.ExitAllocationQuery{
			Status: status,
			DecisionMode: decisionMode,
			Limit: limit,
			BeforeEventIndex: beforeEventIndex,
		},
	)
	if err != nil {
		return protocol.ExitAllocationPage{}, err
	}
	items := make([]protocol.ExitAllocation, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, exitAllocationProtocolAllocation(item))
	}
	return protocol.ExitAllocationPage{
		Items: items,
		NextEventIndex: page.NextEventIndex,
	}, nil
}

func (registry *Service) signExitAllocationEvent(
	event store.ExitAllocationEvent,
) ([]byte, error) {
	return registry.signingKey.Sign(
		protocol.ExitAllocationEventReceiptMessage(
			exitAllocationServiceProtocolEvent(event),
		),
	), nil
}

func mapExitAllocationStoreError(err error) error {
	switch {
	case errors.Is(err, store.ErrIdempotencyConflict):
		return fmt.Errorf(
			"idempotency_key conflicts with another final exit allocation mutation: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationAlreadyExists):
		return fmt.Errorf(
			"exit review already has a final allocation: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationExitBoundary):
		return fmt.Errorf(
			"exit review is not at the exact current verified-eligible event: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationTransferBoundary):
		return fmt.Errorf(
			"ownership-transfer or no-transfer beneficiary decision is not valid at the current boundary: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationConservation):
		return fmt.Errorf(
			"per-currency distributable minor units cannot be exactly conserved: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationTransition):
		return fmt.Errorf(
			"final exit allocation is not recorded or is already verified-final: %w",
			err,
		)
	case errors.Is(err, store.ErrExitAllocationClockBeforeHead):
		return fmt.Errorf(
			"registry clock does not safely extend the final allocation sources: %w",
			err,
		)
	case errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("final exit allocation was not found: %w", err)
	default:
		return err
	}
}

func exitAllocationServiceProtocolEvent(
	event store.ExitAllocationEvent,
) protocol.ExitAllocationEvent {
	result := protocol.ExitAllocationEvent{
		EventIndex: event.EventIndex,
		EventID: event.EventID,
		AllocationID: event.AllocationID,
		Action: event.Action,
		ResultingStatus: event.ResultingStatus,
		ActorRole: event.ActorRole,
		ActorID: event.ActorID,
		Reference: event.Reference,
		EvidenceHash: event.EvidenceHash,
		IdempotencyKey: event.IdempotencyKey,
		PayloadHash: event.PayloadHash,
		RecordHash: event.RecordHash,
		AcceptedAt: event.AcceptedAt,
		PreviousEventHash: event.PreviousEventHash,
		PreviousAllocationEventHash: event.PreviousAllocationEventHash,
		EventHash: event.EventHash,
		RegistryScope: event.RegistryScope,
		RegistryKeyID: event.RegistryKeyID,
	}
	if len(event.Signature) > 0 {
		result.Signature = base64.StdEncoding.EncodeToString(event.Signature)
	}
	return result
}

func exitAllocationProtocolAllocation(
	item store.ExitAllocation,
) protocol.ExitAllocation {
	events := make([]protocol.ExitAllocationEvent, 0, len(item.Events))
	for _, event := range item.Events {
		events = append(events, exitAllocationServiceProtocolEvent(event))
	}
	return protocol.ExitAllocation{
		Record: exitAllocationServiceProtocolRecord(item.Record),
		Status: item.Status,
		LatestEventIndex: item.LatestEventIndex,
		LatestEventHash: item.LatestEventHash,
		LatestAction: item.LatestAction,
		LatestActorRole: item.LatestActorRole,
		LatestActorID: item.LatestActorID,
		LatestReference: item.LatestReference,
		LatestEvidenceHash: item.LatestEvidenceHash,
		LatestAcceptedAt: item.LatestAcceptedAt,
		Events: events,
	}
}

func exitAllocationServiceProtocolRecord(
	record store.ExitAllocationRecord,
) protocol.ExitAllocationRecord {
	sources := make(
		[]protocol.ExitAllocationSettlementSource,
		0,
		len(record.SettlementSources),
	)
	for _, source := range record.SettlementSources {
		sources = append(sources, protocol.ExitAllocationSettlementSource{
			BoundaryOrder: source.BoundaryOrder,
			SettlementID: source.SettlementID,
			Period: source.Period,
			CurrencyCode: source.CurrencyCode,
			FractionDigits: source.FractionDigits,
			Revision: source.Revision,
			LedgerIndex: source.LedgerIndex,
			SettlementHash: source.SettlementHash,
			SourceFingerprint: source.SourceFingerprint,
			SettlementAllocationHash: source.SettlementAllocationHash,
			DistributableMinor: source.DistributableMinor,
		})
	}
	currencies := make(
		[]protocol.ExitAllocationCurrency,
		0,
		len(record.CurrencyAllocations),
	)
	for _, allocation := range record.CurrencyAllocations {
		currencies = append(currencies, protocol.ExitAllocationCurrency{
			AllocationOrder: allocation.AllocationOrder,
			CurrencyCode: allocation.CurrencyCode,
			FractionDigits: allocation.FractionDigits,
			DistributableMinor: allocation.DistributableMinor,
			AllocatedMinor: allocation.AllocatedMinor,
			BeneficiaryType: allocation.BeneficiaryType,
			BeneficiaryID: allocation.BeneficiaryID,
		})
	}
	return protocol.ExitAllocationRecord{
		AllocationID: record.AllocationID,
		RulesetVersion: record.RulesetVersion,
		ExitReviewID: record.ExitReviewID,
		TargetDeploymentID: record.TargetDeploymentID,
		ClaimActionID: record.ClaimActionID,
		SourceGroupID: record.SourceGroupID,
		ExitRecordHash: record.ExitRecordHash,
		ExitVerificationEventIndex: record.ExitVerificationEventIndex,
		ExitVerificationEventHash: record.ExitVerificationEventHash,
		ExitEvidenceHash: record.ExitEvidenceHash,
		DecisionMode: record.DecisionMode,
		OwnershipTransferID: record.OwnershipTransferID,
		OwnershipTransferCompletionEventIndex: record.OwnershipTransferCompletionEventIndex,
		OwnershipTransferCompletionEventHash: record.OwnershipTransferCompletionEventHash,
		ThroughOwnershipTransferEventIndex: record.ThroughOwnershipTransferEventIndex,
		OwnershipTransferHeadHash: record.OwnershipTransferHeadHash,
		BeneficiaryType: record.BeneficiaryType,
		BeneficiaryID: record.BeneficiaryID,
		ContractReference: record.ContractReference,
		ContractTermsHash: record.ContractTermsHash,
		EvidenceHash: record.EvidenceHash,
		SettlementSourceCount: record.SettlementSourceCount,
		SettlementSourceHash: record.SettlementSourceHash,
		CurrencyAllocationCount: record.CurrencyAllocationCount,
		CurrencyAllocationHash: record.CurrencyAllocationHash,
		CreatedAt: record.CreatedAt,
		RecordHash: record.RecordHash,
		RegistryScope: record.RegistryScope,
		RegistryKeyID: record.RegistryKeyID,
		SettlementSources: sources,
		CurrencyAllocations: currencies,
	}
}
