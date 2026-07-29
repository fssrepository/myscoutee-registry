package service

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/fssrepository/myscoutee-registry/internal/protocol"
	"github.com/fssrepository/myscoutee-registry/internal/store"
)

const (
	defaultRegistryCaseLimit = 50
	maxRegistryCaseLimit     = 200
)

var (
	registryCaseIDPattern       = regexp.MustCompile(`^case_[0-9a-f]{32}$`)
	registryCaseEventIDPattern  = regexp.MustCompile(`^cse_[0-9a-f]{32}$`)
	registryCaseCategoryPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{2,63}$`)
)

type RegistryCaseFlag struct {
	SubjectType    string
	SubjectID      string
	Category       string
	Severity       string
	EvidenceHash   string
	Reference      string
	ActorID        string
	IdempotencyKey string
}

type RegistryCaseClear struct {
	CaseID         string
	EvidenceHash   string
	Reference      string
	ActorID        string
	IdempotencyKey string
}

func (registry *Service) FlagRegistryCase(
	ctx context.Context,
	input RegistryCaseFlag,
) (protocol.RegistryCaseMutationResult, error) {
	normalized, err := validateRegistryCaseFlag(input)
	if err != nil {
		return protocol.RegistryCaseMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before case flag: %w",
			err,
		)
	}
	caseID, err := registry.newID("case_")
	if err != nil {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"generate registry case ID: %w",
			err,
		)
	}
	if !registryCaseIDPattern.MatchString(caseID) {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"generated registry case ID is malformed",
		)
	}
	return registry.appendRegistryCaseEvent(
		ctx,
		protocol.RegistryCaseActionFlag,
		caseID,
		normalized.SubjectType,
		normalized.SubjectID,
		normalized.Category,
		normalized.Severity,
		normalized.EvidenceHash,
		normalized.Reference,
		normalized.ActorID,
		normalized.IdempotencyKey,
	)
}

func (registry *Service) ClearRegistryCase(
	ctx context.Context,
	input RegistryCaseClear,
) (protocol.RegistryCaseMutationResult, error) {
	if !registryCaseIDPattern.MatchString(input.CaseID) {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"case_id is malformed",
		)
	}
	if err := validateClaimText("reference", input.Reference, 240); err != nil {
		return protocol.RegistryCaseMutationResult{}, err
	}
	if err := validateClaimText("actor_id", input.ActorID, 120); err != nil {
		return protocol.RegistryCaseMutationResult{}, err
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return protocol.RegistryCaseMutationResult{}, err
	}
	evidenceHash, err := normalizeRegistryCaseEvidenceHash(input.EvidenceHash)
	if err != nil {
		return protocol.RegistryCaseMutationResult{}, err
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"registry integrity verification failed before case clear: %w",
			err,
		)
	}
	current, err := registry.store.RegistryCase(ctx, input.CaseID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
				"registry case was not found: %w",
				err,
			)
		}
		return protocol.RegistryCaseMutationResult{}, err
	}
	return registry.appendRegistryCaseEvent(
		ctx,
		protocol.RegistryCaseActionClear,
		current.CaseID,
		current.SubjectType,
		current.SubjectID,
		current.Category,
		current.Severity,
		evidenceHash,
		input.Reference,
		input.ActorID,
		input.IdempotencyKey,
	)
}

func (registry *Service) RegistryCase(
	ctx context.Context,
	caseID string,
) (protocol.RegistryCase, error) {
	if !registryCaseIDPattern.MatchString(caseID) {
		return protocol.RegistryCase{}, fmt.Errorf("case_id is malformed")
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.RegistryCase{}, fmt.Errorf(
			"registry integrity verification failed before case read: %w",
			err,
		)
	}
	item, err := registry.store.RegistryCase(ctx, caseID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return protocol.RegistryCase{}, fmt.Errorf(
				"registry case was not found: %w",
				err,
			)
		}
		return protocol.RegistryCase{}, err
	}
	return registryCaseProtocolRecord(item), nil
}

func (registry *Service) RegistryCases(
	ctx context.Context,
	status string,
	limit int,
	beforeEventIndex int64,
) (protocol.RegistryCasePage, error) {
	normalizedStatus := strings.ToUpper(strings.TrimSpace(status))
	if normalizedStatus != "" &&
		normalizedStatus != protocol.RegistryCaseStatusOpen &&
		normalizedStatus != protocol.RegistryCaseStatusCleared {
		return protocol.RegistryCasePage{}, fmt.Errorf(
			"status must be OPEN, CLEARED, or empty",
		)
	}
	if limit == 0 {
		limit = defaultRegistryCaseLimit
	}
	if limit < 1 || limit > maxRegistryCaseLimit {
		return protocol.RegistryCasePage{}, fmt.Errorf(
			"limit must be between 1 and %d",
			maxRegistryCaseLimit,
		)
	}
	if beforeEventIndex < 0 {
		return protocol.RegistryCasePage{}, fmt.Errorf(
			"before_event_index cannot be negative",
		)
	}
	if err := registry.verifyOperationalState(ctx); err != nil {
		return protocol.RegistryCasePage{}, fmt.Errorf(
			"registry integrity verification failed before case list: %w",
			err,
		)
	}
	page, err := registry.store.RegistryCases(ctx, store.RegistryCaseQuery{
		Status:           normalizedStatus,
		Limit:            limit,
		BeforeEventIndex: beforeEventIndex,
	})
	if err != nil {
		return protocol.RegistryCasePage{}, err
	}
	items := make([]protocol.RegistryCase, 0, len(page.Items))
	for _, item := range page.Items {
		items = append(items, registryCaseProtocolRecord(item))
	}
	return protocol.RegistryCasePage{
		Items:          items,
		NextEventIndex: page.NextEventIndex,
	}, nil
}

func (registry *Service) appendRegistryCaseEvent(
	ctx context.Context,
	action string,
	caseID string,
	subjectType string,
	subjectID string,
	category string,
	severity string,
	evidenceHash string,
	reference string,
	actorID string,
	idempotencyKey string,
) (protocol.RegistryCaseMutationResult, error) {
	eventID, err := registry.newID("cse_")
	if err != nil {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"generate registry case event ID: %w",
			err,
		)
	}
	if !registryCaseEventIDPattern.MatchString(eventID) {
		return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
			"generated registry case event ID is malformed",
		)
	}
	payloadHash := protocol.Digest(protocol.RegistryCasePayloadMessage(
		action,
		caseID,
		subjectType,
		subjectID,
		category,
		severity,
		evidenceHash,
		reference,
		actorID,
	))
	event, item, duplicate, err := registry.store.AppendRegistryCaseEvent(
		ctx,
		store.RegistryCaseEventInput{
			Action:           action,
			CaseID:           caseID,
			SubjectType:      subjectType,
			SubjectID:        subjectID,
			Category:         category,
			Severity:         severity,
			EvidenceHash:     evidenceHash,
			Reference:        reference,
			ActorID:          actorID,
			IdempotencyKey:   idempotencyKey,
			PayloadHash:      payloadHash,
			CandidateEventID: eventID,
			AcceptedAt: registry.canonicalNow().
				Format(time.RFC3339),
			RegistryScope: registry.registryScope,
			RegistryKeyID: registry.signingKey.KeyID(),
		},
		func(event store.RegistryCaseEvent) ([]byte, error) {
			return registry.signingKey.Sign(
				protocol.RegistryCaseEventReceiptMessage(
					registryCaseProtocolEvent(event),
				),
			), nil
		},
	)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrIdempotencyConflict):
			return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
				"idempotency_key was already used for another registry case mutation: %w",
				err,
			)
		case errors.Is(err, store.ErrRegistryCaseAlreadyCleared):
			return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
				"registry case is already cleared: %w",
				err,
			)
		case errors.Is(err, store.ErrRegistryCaseClockBeforeHead):
			return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
				"registry clock is before the immutable case-event head: %w",
				err,
			)
		case errors.Is(err, store.ErrNotFound):
			return protocol.RegistryCaseMutationResult{}, fmt.Errorf(
				"registry case subject was not found: %w",
				err,
			)
		default:
			return protocol.RegistryCaseMutationResult{}, err
		}
	}
	return protocol.RegistryCaseMutationResult{
		Duplicate: duplicate,
		Case:      registryCaseProtocolRecord(item),
		Event:     registryCaseProtocolEvent(event),
	}, nil
}

func validateRegistryCaseFlag(
	input RegistryCaseFlag,
) (RegistryCaseFlag, error) {
	input.SubjectType = strings.TrimSpace(input.SubjectType)
	input.SubjectID = strings.TrimSpace(input.SubjectID)
	input.Category = strings.TrimSpace(input.Category)
	input.Severity = strings.TrimSpace(input.Severity)
	if !validRegistryCaseSubjectID(input.SubjectType, input.SubjectID) {
		return RegistryCaseFlag{}, fmt.Errorf(
			"subject_id is malformed for subject_type %q",
			input.SubjectType,
		)
	}
	if !registryCaseCategoryPattern.MatchString(input.Category) {
		return RegistryCaseFlag{}, fmt.Errorf(
			"category must be a 3-64 character lowercase token",
		)
	}
	if !validRegistryCaseSeverity(input.Severity) {
		return RegistryCaseFlag{}, fmt.Errorf(
			"severity must be info, warning, or critical",
		)
	}
	evidenceHash, err := normalizeRegistryCaseEvidenceHash(input.EvidenceHash)
	if err != nil {
		return RegistryCaseFlag{}, err
	}
	input.EvidenceHash = evidenceHash
	if err := validateClaimText("reference", input.Reference, 240); err != nil {
		return RegistryCaseFlag{}, err
	}
	if err := validateClaimText("actor_id", input.ActorID, 120); err != nil {
		return RegistryCaseFlag{}, err
	}
	if err := validateToken("idempotency_key", input.IdempotencyKey); err != nil {
		return RegistryCaseFlag{}, err
	}
	return input, nil
}

func normalizeRegistryCaseEvidenceHash(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return protocol.RegistryCaseZeroHash, nil
	}
	if !protocol.IsDigest(value) {
		return "", fmt.Errorf(
			"evidence_hash must be a canonical lowercase SHA-256 digest",
		)
	}
	return value, nil
}

func validRegistryCaseSubjectID(subjectType, subjectID string) bool {
	switch subjectType {
	case protocol.RegistryCaseSubjectDeployment:
		return deploymentIDPattern.MatchString(subjectID)
	case protocol.RegistryCaseSubjectClaim:
		return operatorActionIDPattern.MatchString(subjectID)
	case protocol.RegistryCaseSubjectGroup:
		return operatorGroupIDPattern.MatchString(subjectID)
	case protocol.RegistryCaseSubjectQMAU:
		return batchIDPattern.MatchString(subjectID)
	case protocol.RegistryCaseSubjectRevenue:
		return revenueBatchIDPattern.MatchString(subjectID)
	case protocol.RegistryCaseSubjectLedger:
		index, err := strconv.ParseInt(subjectID, 10, 64)
		return err == nil &&
			index > 0 &&
			strconv.FormatInt(index, 10) == subjectID
	default:
		return false
	}
}

func validRegistryCaseSeverity(severity string) bool {
	switch severity {
	case protocol.RegistryCaseSeverityInfo,
		protocol.RegistryCaseSeverityWarning,
		protocol.RegistryCaseSeverityCritical:
		return true
	default:
		return false
	}
}

func registryCaseProtocolEvent(
	event store.RegistryCaseEvent,
) protocol.RegistryCaseEvent {
	return protocol.RegistryCaseEvent{
		EventIndex:        event.EventIndex,
		EventID:           event.EventID,
		CaseID:            event.CaseID,
		Action:            event.Action,
		SubjectType:       event.SubjectType,
		SubjectID:         event.SubjectID,
		Category:          event.Category,
		Severity:          event.Severity,
		EvidenceHash:      event.EvidenceHash,
		Reference:         event.Reference,
		ActorID:           event.ActorID,
		IdempotencyKey:    event.IdempotencyKey,
		PayloadHash:       event.PayloadHash,
		AcceptedAt:        event.AcceptedAt,
		PreviousEventHash: event.PreviousEventHash,
		EventHash:         event.EventHash,
		RegistryScope:     event.RegistryScope,
		RegistryKeyID:     event.RegistryKeyID,
		Signature: base64.StdEncoding.EncodeToString(
			event.Signature,
		),
	}
}

func registryCaseProtocolRecord(item store.RegistryCase) protocol.RegistryCase {
	return protocol.RegistryCase{
		CaseID:            item.CaseID,
		Status:            item.Status,
		SubjectType:       item.SubjectType,
		SubjectID:         item.SubjectID,
		Category:          item.Category,
		Severity:          item.Severity,
		FlagEvidenceHash:  item.FlagEvidenceHash,
		FlagReference:     item.FlagReference,
		FlagActorID:       item.FlagActorID,
		FlaggedAt:         item.FlaggedAt,
		FlagEventIndex:    item.FlagEventIndex,
		FlagEventHash:     item.FlagEventHash,
		ClearEvidenceHash: item.ClearEvidenceHash,
		ClearReference:    item.ClearReference,
		ClearActorID:      item.ClearActorID,
		ClearedAt:         item.ClearedAt,
		ClearEventIndex:   item.ClearEventIndex,
		ClearEventHash:    item.ClearEventHash,
		LatestEventIndex:  item.LatestEventIndex,
		LatestEventHash:   item.LatestEventHash,
	}
}
